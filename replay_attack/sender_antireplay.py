#!/usr/bin/env python3
# sender_cmd.py
"""
AERPAW UDP ENC-only Command Sender

Sends:
  ENC|v1|nonce_hex|ciphertext_b64|hmac_hex

Inner plaintext (AESGCM) is:
  v1|<seq>|<ts_ms>|GOTO|lat,lon,alt

Replay helpers:
  --seq N          (force a seq)
  --freeze_ts      (keep same ts_ms across the process run)
  --freeze_seq N   (always send this seq; useful to trigger seq-replay drops)
"""

import argparse
import base64
import hmac
import hashlib
import os
import socket
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def now_ms() -> int:
    return int(time.time() * 1000)


def encrypt_fips(aes_key_file: str, hmac_key_file: str, plaintext: bytes) -> str:
    """Return: v1|nonce_hex|ciphertext_b64|hmac_hex (HMAC over nonce_hex:ciphertext_b64)"""
    aes_key = open(aes_key_file, "rb").read()
    hmac_key = open(hmac_key_file, "rb").read()

    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes for AES-256")

    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # includes tag at end
    enc_b64 = base64.b64encode(ciphertext).decode("ascii")
    nonce_hex = nonce.hex()

    mac_data = f"{nonce_hex}:{enc_b64}".encode("utf-8")
    mac_hex = hmac.new(hmac_key, mac_data, hashlib.sha256).hexdigest()

    return f"v1|{nonce_hex}|{enc_b64}|{mac_hex}"


def send_udp(ip: str, port: int, packet: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet.encode("utf-8"), (ip, port))
    sock.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cmd", choices=["goto"], required=True)
    p.add_argument("--lat", type=float, required=True)
    p.add_argument("--lon", type=float, required=True)
    p.add_argument("--alt", type=float, default=25.0)

    p.add_argument("--ip", default="192.168.144.5")
    p.add_argument("--port", type=int, default=14551)

    p.add_argument("--aes-key", default="./mavlink_aes256.key")
    p.add_argument("--hmac-key", default="./mavlink_hmac.key")

    # seq/ts controls
    p.add_argument("--seq", type=int, default=None)
    p.add_argument("--freeze_ts", action="store_true")
    p.add_argument("--freeze_seq", type=int, default=None)

    args = p.parse_args()

    if not os.path.exists(args.aes_key) or not os.path.exists(args.hmac_key):
        raise FileNotFoundError("AES or HMAC key file missing")

    cmd_token = "GOTO"
    coords = f"{args.lat},{args.lon},{args.alt}"

    if not hasattr(main, "_seq_counter"):
        main._seq_counter = 0
    if not hasattr(main, "_fixed_ts"):
        main._fixed_ts = now_ms()

    # seq
    if args.freeze_seq is not None:
        seq = int(args.freeze_seq)
    elif args.seq is not None:
        seq = int(args.seq)
    else:
        main._seq_counter += 1
        seq = main._seq_counter

    # ts
    ts_ms = main._fixed_ts if args.freeze_ts else now_ms()

    inner = f"v1|{seq}|{ts_ms}|{cmd_token}|{coords}".encode("utf-8")
    enc_payload = encrypt_fips(args.aes_key, args.hmac_key, inner)
    packet = "ENC|" + enc_payload

    print(f"[INFO] Sending to {args.ip}:{args.port} -> {packet[:110]}{'...' if len(packet) > 110 else ''}")
    send_udp(args.ip, args.port, packet)
    print(f"[OK] Sent ENC seq={seq} ts_ms={ts_ms}")


if __name__ == "__main__":
    main()
