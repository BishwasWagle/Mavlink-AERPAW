#!/usr/bin/env python3
"""
AERPAW UDP ENC Receiver with:
- Software-emulated "attestation" allowlist check (attest_hex)
- AES-GCM decryption + HMAC integrity
- Anti-replay defenses (nonce cache + ts window + seq monotonicity)

Packet format (matches slide):
  ENC|v2|attest_hex|nonce_hex|ciphertext_b64|hmac_hex

HMAC covers: attest_hex:nonce_hex:ciphertext_b64

Inner plaintext:
  v2|seq|ts_ms|GOTO|lat,lon,alt
"""

import argparse
import base64
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
    """
    File contains one attest_hex per line (comments allowed with #).
    """
    allowed = set()
    if not path:
        return allowed
    if not os.path.exists(path):
        return allowed
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            allowed.add(line)
    return allowed


def verify_and_decrypt_v2(aes_key_file: str, hmac_key_file: str,
                          attest_hex: str, nonce_hex: str, enc_b64: str, mac_hex: str) -> bytes:
    aes_key = open(aes_key_file, "rb").read()
    hmac_key = open(hmac_key_file, "rb").read()
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes for AES-256")
    print(attest_hex)
    mac_data = f"{attest_hex}:{nonce_hex}:{enc_b64}".encode("utf-8")
    expected_mac = hmac.new(hmac_key, mac_data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, mac_hex):
        raise ValueError("HMAC verification failed")

    nonce = bytes.fromhex(nonce_hex)
    ciphertext = base64.b64decode(enc_b64)

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext


def parse_inner(pt_bytes: bytes):
    # v2|seq|ts_ms|GOTO|lat,lon,alt
    s = pt_bytes.decode("utf-8", errors="strict").strip()
    parts = s.split("|")
    if len(parts) != 5:
        return None
    ver, seq_s, ts_s, cmd, coords = parts
    if ver != "v2" or cmd not in ("GOTO",):
        return None
    seq = int(seq_s)
    ts_ms = int(ts_s)
    lat_s, lon_s, alt_s = coords.split(",")
    return (cmd, float(lat_s), float(lon_s), float(alt_s), seq, ts_ms)


def publish_cmd(cmd: str, lat: float, lon: float, alt: float):
    os.makedirs(os.path.dirname(CMD_FILE), exist_ok=True)
    with open(CMD_FILE, "w") as f:
        f.write(f"enc|{cmd}|{lat},{lon},{alt}\n")


def set_secure_ok():
    with open(SECURE_FLAG, "w") as f:
        f.write("1")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--listen", default="0.0.0.0")
    p.add_argument("--port", type=int, default=14551)
    p.add_argument("--aes-key", default="./mavlink_aes256.key")
    p.add_argument("--hmac-key", default="./mavlink_hmac.key")
    p.add_argument("--buf", type=int, default=8192)

    p.add_argument("--mode", choices=["no_defense", "defended"], default="defended")

    # freshness & replay
    p.add_argument("--replay_window_ms", type=int, default=5000)
    p.add_argument("--nonce_cache_size", type=int, default=10000)

    # receiver validation: allowlisted software fingerprints
    p.add_argument("--allowlist", default="./allowed_attest_hashes.txt",
                   help="File containing allowed attest_hex values (one per line)")

    args = p.parse_args()

    defended = (args.mode == "defended")
    nonce_cache = NonceCache(args.nonce_cache_size)
    last_seq_by_sender = {}  # IP -> last_seq

    allowed = load_allowlist(args.allowlist)
    print(f"[{ts()}] [INFO] Loaded allowlist entries={len(allowed)} from {args.allowlist}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen, args.port))
    print(f"[{ts()}] [INFO] Listening on UDP {args.listen}:{args.port} mode={args.mode}")

    while True:
        data, addr = sock.recvfrom(args.buf)
        sender_key = addr[0]
        packet = data.decode("utf-8", errors="ignore").strip()
        print(f"[{ts()}] [INFO] Packet from {addr[0]}:{addr[1]}")

        if not packet.startswith("ENC|"):
            print(f"[{ts()}] [DROP] Non-ENC packet ignored")
            print("-" * 48)
            continue

        # ENC|v2|attest|nonce|cipher|hmac
        parts = packet.split("|", 5)
        if len(parts) != 6:
            print(f"[{ts()}] [DROP] Bad ENC header format")
            print("-" * 48)
            continue

        _, ver, attest_hex, nonce_hex, enc_b64, mac_hex = parts
        if ver != "v2":
            print(f"[{ts()}] [DROP] Unsupported version {ver}")
            print("-" * 48)
            continue

        # Receiver Validation: software fingerprint check
        if allowed and attest_hex not in allowed:
            print(f"[{ts()}] [DROP] Unknown/modified software (attest not allowlisted): {attest_hex[:16]}...")
            print("-" * 48)
            continue

        # Defended: fast nonce replay reject (before decrypt)
        if defended and nonce_cache.seen(nonce_hex):
            print(f"[{ts()}] [DROP] Replay detected (nonce reused): {nonce_hex[:16]}...")
            print("-" * 48)
            continue

        try:
            pt = verify_and_decrypt_v2(args.aes_key, args.hmac_key, attest_hex, nonce_hex, enc_b64, mac_hex)
            inner = parse_inner(pt)
            if not inner:
                print(f"[{ts()}] [DROP] Bad inner plaintext format")
                print("-" * 48)
                continue
            cmd, lat, lon, alt, seq, ts_ms = inner
        except Exception as e:
            print(f"[{ts()}] [DROP] Verify/decrypt failed: {e}")
            print("-" * 48)
            continue

        if defended:
            now = now_ms()
            if abs(now - ts_ms) > int(args.replay_window_ms):
                print(f"[{ts()}] [DROP] Stale/Future packet: ts_ms={ts_ms} now_ms={now} window={args.replay_window_ms}")
                print("-" * 48)
                continue

            last = last_seq_by_sender.get(sender_key, -1)
            if seq <= last:
                print(f"[{ts()}] [DROP] Non-monotonic seq from {sender_key}: seq={seq} last={last}")
                print("-" * 48)
                continue
            last_seq_by_sender[sender_key] = seq

            nonce_cache.add(nonce_hex)

        set_secure_ok()
        publish_cmd(cmd, lat, lon, alt)
        print(f"[{ts()}] [OK] Accepted ENC v2 cmd={cmd} {lat:.6f},{lon:.6f},{alt:.1f} seq={seq} ts={ts_ms}")
        print("-" * 48)


if __name__ == "__main__":
    main()
