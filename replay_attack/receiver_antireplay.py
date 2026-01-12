#!/usr/bin/env python3
# receiver_cmd.py
"""
AERPAW UDP ENC-only Command Receiver + optional replay defenses

Listens on UDP and writes:
  /tmp/flight_cmd.txt  (enc|CMD|lat,lon,alt)

Sets:
  /tmp/secure_ok.flag  when a valid encrypted command is decrypted/verified

ENC outer format:
  ENC|v1|nonce_hex|ciphertext_b64|hmac_hex

Encrypted inner plaintext (after decrypt):
  v1|<seq>|<ts_ms>|GOTO|lat,lon,alt

Two modes:
  --mode no_defense     => accept any valid ENC (replays allowed)
  --mode defended       => nonce cache + ts/seq checks enabled
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
    """Bounded nonce cache to reject ENC replays without unbounded memory."""
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


def decrypt_fips(aes_key_file: str, hmac_key_file: str, payload: str) -> bytes:
    """
    payload is: v1|nonce_hex|ciphertext_b64|hmac_hex
    Verifies HMAC over nonce_hex:ciphertext_b64 and decrypts using AES-256-GCM.
    """
    parts = payload.split("|")
    if len(parts) != 4:
        raise ValueError("Bad encrypted payload format")

    ver, nonce_hex, enc_b64, mac_hex = parts
    if ver != "v1":
        raise ValueError("Unsupported version")

    aes_key = open(aes_key_file, "rb").read()
    hmac_key = open(hmac_key_file, "rb").read()
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes for AES-256")

    mac_data = f"{nonce_hex}:{enc_b64}".encode("utf-8")
    expected_mac = hmac.new(hmac_key, mac_data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, mac_hex):
        raise ValueError("HMAC verification failed")

    nonce = bytes.fromhex(nonce_hex)
    ciphertext = base64.b64decode(enc_b64)

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext


def parse_enc_inner(pt_bytes: bytes):
    """
    expected inner plaintext: v1|seq|ts_ms|GOTO|lat,lon,alt
    returns (cmd, lat, lon, alt, seq, ts_ms)
    """
    s = pt_bytes.decode("utf-8", errors="strict").strip()
    parts = s.split("|")
    if len(parts) != 5:
        return None
    ver, seq_s, ts_s, cmd, coords = parts
    if ver != "v1" or cmd not in ("GOTO",):
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

    # ONLY two modes
    p.add_argument("--mode", choices=["no_defense", "defended"], default="defended",
                   help="no_defense = accept replays; defended = nonce cache + ts/seq checks")

    # used only in defended mode
    p.add_argument("--replay_window_ms", type=int, default=5000,
                   help="Defended mode: accept if abs(now-ts_ms) <= replay_window_ms")
    p.add_argument("--nonce_cache_size", type=int, default=10000,
                   help="Defended mode: how many ENC nonces to remember")

    args = p.parse_args()

    defended = (args.mode == "defended")
    nonce_cache = NonceCache(args.nonce_cache_size)
    last_seq_by_sender = {}  # sender_key -> last_seq (simple: per IP)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen, args.port))
    print(f"[{ts()}] [INFO] Listening on UDP {args.listen}:{args.port} mode={args.mode}")

    while True:
        data, addr = sock.recvfrom(args.buf)
        sender_key = addr[0]  # minimal identity for seq monotonicity
        packet = data.decode("utf-8", errors="ignore").strip()
        print(packet)
        print(f"[{ts()}] [INFO] Packet from {addr[0]}:{addr[1]}")

        if not packet.startswith("ENC|"):
            print(f"[{ts()}] [DROP] Non-ENC packet ignored: {packet[:60]}")
            print("-" * 48)
            continue

        # parse outer header
        parts = packet.split("|", 4)  # ENC|v1|nonce|ciphertext|hmac
        if len(parts) != 5:
            print(f"[{ts()}] [DROP] Bad ENC header format")
            print("-" * 48)
            continue

        _, ver, nonce_hex, enc_b64, mac_hex = parts
        print(f"[{ts()}] [INFO] ENC header: ver={ver}, nonce={nonce_hex[:8]}..., mac={mac_hex[:8]}...")
        print("-" * 48)

        # defended: nonce cache check BEFORE decrypt (fast reject)
        if defended and nonce_cache.seen(nonce_hex):
            print(f"[{ts()}] [DROP] Replay detected (nonce reused): {nonce_hex[:16]}...")
            print("-" * 48)
            continue

        try:
            payload = packet[len("ENC|"):]
            pt = decrypt_fips(args.aes_key, args.hmac_key, payload)
            inner = parse_enc_inner(pt)
            if not inner:
                print(f"[{ts()}] [DROP] Bad inner plaintext format")
                print("-" * 48)
                continue

            cmd, lat, lon, alt, seq, ts_ms = inner

        except Exception as e:
            print(f"[{ts()}] [DROP] Parse/decrypt failed: {e}")
            print("-" * 48)
            continue

        # defended: ts/seq checks
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

            # accept => add nonce to cache
            nonce_cache.add(nonce_hex)

        # accept
        set_secure_ok()
        publish_cmd(cmd, lat, lon, alt)
        print(f"[{ts()}] [OK] Accepted ENC command: {cmd} {lat:.6f},{lon:.6f},{alt:.1f} seq={seq} ts={ts_ms}")
        print("-" * 48)


if __name__ == "__main__":
    main()
