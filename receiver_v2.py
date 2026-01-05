#!/usr/bin/env python3
# receiver_cmd.py
"""
AERPAW UDP Command Receiver (PLAINTEXT or ENCRYPTED)

Listens on UDP and writes the parsed command to:
  /tmp/flight_cmd.txt  (mode|CMD|lat,lon,alt)

Also sets:
  /tmp/secure_ok.flag  when a valid encrypted command is decrypted/verified

PLAINTEXT format:
  PLAIN|v1|GOTO|lat,lon,alt

ENCRYPTED format:
  ENC|v1|nonce_hex|ciphertext_b64|hmac_hex

Encrypted payload after decrypt:
  v1|GOTO|lat,lon,alt

Usage:
  python3 receiver_cmd.py --listen 0.0.0.0 --port 14551 --aes-key ./mavlink_aes256.key --hmac-key ./mavlink_hmac.key
"""

import argparse
import base64
import datetime
import hmac
import hashlib
import os
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CMD_FILE = "/tmp/flight_cmd.txt"
SECURE_FLAG = "/tmp/secure_ok.flag"


def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def decrypt_fips(aes_key_file: str, hmac_key_file: str, payload: str) -> bytes:
    """
    payload is: v1|nonce_hex|ciphertext_b64|hmac_hex
    Verifies HMAC over nonce_hex:ciphertext_b64 and decrypts using AES-256-GCM.
    Returns plaintext bytes.
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


def parse_plain(packet: str):
    # PLAIN|v1|GOTO|lat,lon,alt
    parts = packet.strip().split("|")
    if len(parts) != 4:
        return None
    _, ver, cmd, coords = parts
    if ver != "v1":
        return None
    if cmd not in ("GOTO",):
        return None
    try:
        lat_s, lon_s, alt_s = coords.split(",")
        return ("plain", cmd, float(lat_s), float(lon_s), float(alt_s))
    except Exception:
        return None


def parse_enc(aes_key_file: str, hmac_key_file: str, packet: str):
    # ENC|v1|nonce|b64|hmac
    if not packet.startswith("ENC|"):
        return None
    payload = packet[len("ENC|"):]
    pt = decrypt_fips(aes_key_file, hmac_key_file, payload)  # bytes

    # expected: v1|GOTO|lat,lon,alt
    s = pt.decode("utf-8", errors="strict").strip()
    parts = s.split("|")
    if len(parts) != 3:
        return None
    ver, cmd, coords = parts
    if ver != "v1" or cmd not in ("GOTO",):
        return None
    lat_s, lon_s, alt_s = coords.split(",")
    return ("enc", cmd, float(lat_s), float(lon_s), float(alt_s))


def publish_cmd(mode: str, cmd: str, lat: float, lon: float, alt: float):
    os.makedirs(os.path.dirname(CMD_FILE), exist_ok=True)
    with open(CMD_FILE, "w") as f:
        f.write(f"{mode}|{cmd}|{lat},{lon},{alt}\n")


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
    args = p.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen, args.port))
    print(f"[{ts()}] [INFO] Listening on UDP {args.listen}:{args.port}")

    while True:
        data, addr = sock.recvfrom(args.buf)
        packet = data.decode("utf-8", errors="ignore").strip()
        print(f"[{ts()}] [INFO] Packet from {addr[0]}:{addr[1]}")

        cmd_tuple = None
        try:
            if packet.startswith("PLAIN|"):
                cmd_tuple = parse_plain(packet)
            elif packet.startswith("ENC|"):
                parts = packet.split("|", 4)  # ENC|v1|nonce|ciphertext|hmac
                if len(parts) == 5:
                    _, ver, nonce_hex, enc_b64, mac_hex = parts
                    print(f"[{ts()}] [INFO] Unencrypted ENC header: ver={ver}, nonce={nonce_hex[:8]}..., mac={mac_hex[:8]}...")
                else:
                    print(f"[{ts()}] [WARN] Bad ENC header format")
                print("-" * 48)
                cmd_tuple = parse_enc(args.aes_key, args.hmac_key, packet)
                if cmd_tuple:
                    set_secure_ok()
            else:
                cmd_tuple = None
        except Exception as e:
            print(f"[{ts()}] [WARN] Parse/decrypt failed: {e}")
            cmd_tuple = None

        if not cmd_tuple:
            print(f"[{ts()}] [WARN] Unrecognized/invalid packet: {packet[:120]}")
            continue

        mode, cmd, lat, lon, alt = cmd_tuple
        publish_cmd(mode, cmd, lat, lon, alt)
        print(f"[{ts()}] [OK] Parsed {mode} command: {cmd} {lat:.6f},{lon:.6f},{alt:.1f}")
        print("-" * 48)


if __name__ == "__main__":
    main()
