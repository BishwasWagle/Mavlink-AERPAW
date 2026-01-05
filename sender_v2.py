#!/usr/bin/env python3
# sender_cmd.py
"""
AERPAW UDP Command Sender (PLAINTEXT or ENCRYPTED)

Sends either:
  PLAIN|v1|GOTO|lat,lon,alt
or
  ENC|v1|nonce_hex|ciphertext_b64|hmac_hex

Encrypted payload (inside AESGCM) is:
  v1|GOTO|lat,lon,alt

Usage examples:
  # Plaintext command (will trigger spoof in flight script)
  python3 sender_cmd.py --mode plain --cmd goto --lat 35.7302614 --lon -78.6986117 --alt 25 --ip 192.168.144.5 --port 14551

  # Encrypted command (will force discard spoof + go home and land)
  python3 sender_cmd.py --mode enc --cmd goto --lat 35.7302614 --lon -78.6986117 --alt 25 --ip 192.168.144.5 --port 14551 \
    --aes-key ./mavlink_aes256.key --hmac-key ./mavlink_hmac.key
"""

import argparse
import base64
import hmac
import hashlib
import os
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_fips(aes_key_file: str, hmac_key_file: str, plaintext: bytes) -> str:
    """Return: v1|nonce_hex|ciphertext_b64|hmac_hex (HMAC over nonce_hex:ciphertext_b64)"""
    aes_key = open(aes_key_file, "rb").read()
    hmac_key = open(hmac_key_file, "rb").read()

    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes for AES-256")

    nonce = os.urandom(12)  # 96-bit nonce for GCM
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
    p.add_argument("--mode", choices=["plain", "enc"], required=True, help="Send mode: plain or enc")
    p.add_argument("--cmd", choices=["goto"], required=True, help="Command type")
    p.add_argument("--lat", type=float, required=True)
    p.add_argument("--lon", type=float, required=True)
    p.add_argument("--alt", type=float, default=25.0)

    p.add_argument("--ip", default="192.168.144.5")
    p.add_argument("--port", type=int, default=14551)

    p.add_argument("--aes-key", default="./mavlink_aes256.key")
    p.add_argument("--hmac-key", default="./mavlink_hmac.key")

    args = p.parse_args()

    # Normalize command token
    cmd_token = "GOTO" if args.cmd == "goto" else args.cmd.upper()
    coords = f"{args.lat},{args.lon},{args.alt}"

    if args.mode == "plain":
        packet = f"PLAIN|v1|{cmd_token}|{coords}"
    else:
        if not os.path.exists(args.aes_key) or not os.path.exists(args.hmac_key):
            raise FileNotFoundError("AES or HMAC key file missing for --mode enc")
        inner = f"v1|{cmd_token}|{coords}".encode("utf-8")
        enc_payload = encrypt_fips(args.aes_key, args.hmac_key, inner)
        packet = "ENC|" + enc_payload

    print(f"[INFO] Sending to {args.ip}:{args.port} -> {packet[:80]}{'...' if len(packet) > 80 else ''}")
    send_udp(args.ip, args.port, packet)
    print("[OK] Sent")


if __name__ == "__main__":
    main()
