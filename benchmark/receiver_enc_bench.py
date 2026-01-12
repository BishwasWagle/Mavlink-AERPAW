#!/usr/bin/env python3
"""
ENC (v2) UDP command receiver benchmark with:
- allowlist attest_hex
- HMAC over attest:nonce:cipher
- AES-256-GCM decrypt
- anti-replay: nonce cache + ts window + seq monotonicity per sender IP

Packet:
  ENC|v2|attest_hex|nonce_hex|ciphertext_b64|hmac_hex

Inner plaintext:
  v2|seq|ts_ms|GOTO|lat,lon,alt|pad=<optional>

Logs to CSV:
  mode,verdict,reason,seq,sender_ts_ms,recv_ts_ms,e2e_ms,proc_ms,payload_bytes,sender_ip

Optional:
  --no_io disables /tmp writes (recommended for pure compute benchmarking)
"""

import argparse
import base64
import csv
import datetime
import hmac
import hashlib
import os
import socket
import time
from collections import deque
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CMD_FILE = "/tmp/flight_cmd.txt"
SECURE_FLAG = "/tmp/secure_ok.flag"

def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def now_ms() -> int:
    return int(time.time() * 1000)

class NonceCache:
    def __init__(self, max_size: int = 10000):
        self.max_size = int(max_size)
        self.q = deque()
        self.s = set()

    def seen(self, nonce_hex: str) -> bool:
        return nonce_hex in self.s

    def add(self, nonce_hex: str):
        if nonce_hex in self.s:
            return
        self.q.append(nonce_hex)
        self.s.add(nonce_hex)
        while len(self.q) > self.max_size:
            old = self.q.popleft()
            self.s.discard(old)

def load_allowlist(path: str):
    allowed = set()
    if not path or not os.path.exists(path):
        return allowed
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            allowed.add(line)
    return allowed

def set_secure_ok():
    with open(SECURE_FLAG, "w") as f:
        f.write("1")

def publish_cmd(cmd: str, lat: float, lon: float, alt: float):
    os.makedirs(os.path.dirname(CMD_FILE), exist_ok=True)
    with open(CMD_FILE, "w") as f:
        f.write(f"enc|{cmd}|{lat},{lon},{alt}\n")

def verify_and_decrypt(aes_key_file: str, hmac_key_file: str,
                       attest_hex: str, nonce_hex: str, enc_b64: str, mac_hex: str) -> bytes:
    aes_key = open(aes_key_file, "rb").read()
    hmac_key = open(hmac_key_file, "rb").read()
    if len(aes_key) != 32:
        raise ValueError("bad_aes_key_len")

    mac_data = f"{attest_hex}:{nonce_hex}:{enc_b64}".encode("utf-8")
    expected = hmac.new(hmac_key, mac_data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac_hex):
        raise ValueError("hmac_failed")

    nonce = bytes.fromhex(nonce_hex)
    ciphertext = base64.b64decode(enc_b64)
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def parse_inner(pt: bytes):
    # v2|seq|ts_ms|GOTO|lat,lon,alt|pad=...
    s = pt.decode("utf-8", errors="strict").strip()
    parts = s.split("|")
    if len(parts) < 5:
        return None, "bad_inner"
    ver, seq_s, ts_s, cmd, coords, *_rest = parts
    if ver != "v2":
        return None, "bad_inner_ver"
    if cmd != "GOTO":
        return None, "bad_cmd"
    try:
        seq = int(seq_s)
        sender_ts_ms = int(ts_s)
        lat_s, lon_s, alt_s = coords.split(",")
        lat, lon, alt = float(lat_s), float(lon_s), float(alt_s)
    except Exception:
        return None, "inner_parse_error"
    return (seq, sender_ts_ms, cmd, lat, lon, alt), "ok"

def csv_writer_open(path: str):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    f = open(path, "a", newline="", buffering=1)
    w = csv.writer(f)
    if f.tell() == 0:
        w.writerow([
            "mode","verdict","reason","seq","sender_ts_ms","recv_ts_ms",
            "e2e_ms","proc_ms","payload_bytes","sender_ip"
        ])
    return f, w

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--listen", default="0.0.0.0")
    p.add_argument("--port", type=int, default=14551)
    p.add_argument("--buf", type=int, default=65535)

    p.add_argument("--aes-key", default="./mavlink_aes256.key")
    p.add_argument("--hmac-key", default="./mavlink_hmac.key")

    p.add_argument("--allowlist", default="./allowed_attest_hashes.txt")
    p.add_argument("--mode", choices=["no_defense", "defended"], default="defended")
    p.add_argument("--replay_window_ms", type=int, default=5000)
    p.add_argument("--nonce_cache_size", type=int, default=10000)

    p.add_argument("--csv", default="./bench_enc.csv")
    p.add_argument("--no_io", action="store_true",
                   help="Benchmark mode: disable /tmp file writes")
    args = p.parse_args()

    defended = (args.mode == "defended")
    nonce_cache = NonceCache(args.nonce_cache_size)
    last_seq_by_sender = {}

    allowed = load_allowlist(args.allowlist)

    _fcsv, wcsv = csv_writer_open(args.csv)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen, args.port))

    print(f"[{ts()}] [INFO] ENC receiver listening on {args.listen}:{args.port} mode={args.mode}")
    print(f"[{ts()}] [INFO] allowlist entries={len(allowed)} file={args.allowlist}")
    print(f"[{ts()}] [INFO] Logging to {args.csv}  no_io={args.no_io}")

    while True:
        data, addr = sock.recvfrom(args.buf)
        t0 = time.perf_counter_ns()  # START AFTER recvfrom => compute time only
        recv_ts_ms = now_ms()

        sender_ip = addr[0]
        payload_bytes = len(data)
        packet = data.decode("utf-8", errors="ignore").strip()

        verdict = "DROP"
        reason = ""
        seq = ""
        sender_ts_ms = ""
        e2e_ms = ""

        # Parse outer: ENC|v2|attest|nonce|cipher|hmac
        parts = packet.split("|", 5)
        if len(parts) != 6 or parts[0] != "ENC":
            reason = "not_enc"
        else:
            _, ver, attest_hex, nonce_hex, enc_b64, mac_hex = parts
            if ver != "v2":
                reason = "bad_version"
            elif allowed and attest_hex not in allowed:
                reason = "attest_not_allowed"
            elif defended and nonce_cache.seen(nonce_hex):
                reason = "replay_nonce"
            else:
                try:
                    pt = verify_and_decrypt(args.aes_key, args.hmac_key, attest_hex, nonce_hex, enc_b64, mac_hex)
                    parsed, inner_reason = parse_inner(pt)

                    if not parsed:
                        reason = inner_reason
                    else:
                        seq, sender_ts_ms, cmd, lat, lon, alt = parsed

                        if defended:
                            if abs(recv_ts_ms - sender_ts_ms) > int(args.replay_window_ms):
                                reason = "stale_or_future"
                            else:
                                last = last_seq_by_sender.get(sender_ip, -1)
                                if seq <= last:
                                    reason = "non_monotonic_seq"
                                else:
                                    last_seq_by_sender[sender_ip] = seq
                                    nonce_cache.add(nonce_hex)
                                    verdict = "ACCEPT"
                                    reason = "ok"
                        else:
                            verdict = "ACCEPT"
                            reason = "ok"

                        if verdict == "ACCEPT":
                            e2e_ms = recv_ts_ms - sender_ts_ms
                            if not args.no_io:
                                set_secure_ok()
                                publish_cmd(cmd, lat, lon, alt)

                except Exception as e:
                    reason = f"crypto_fail:{str(e)}"

        proc_ms = (time.perf_counter_ns() - t0) / 1e6

        wcsv.writerow([
            "ENC", verdict, reason, seq, sender_ts_ms, recv_ts_ms,
            e2e_ms, f"{proc_ms:.6f}", payload_bytes, sender_ip
        ])

if __name__ == "__main__":
    main()
