#!/usr/bin/env python3
"""
ENC benchmark sender (v2, no Docker).
Packet:
  ENC|v2|attest_hex|nonce_hex|ciphertext_b64|hmac_hex

Inner plaintext:
  v2|seq|ts_ms|GOTO|lat,lon,alt|pad=<N bytes>

Controls:
  --rate --count --pad-bytes
  --env-extra-file (optional stable build id)
"""

import argparse
import base64
import hmac
import hashlib
import os
import socket
import subprocess
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def now_ms() -> int:
    return int(time.time() * 1000)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True).strip()
    except Exception:
        return ""

def read_text(path: str) -> str:
    try:
        return open(path, "r", encoding="utf-8", errors="ignore").read().strip()
    except Exception:
        return ""

def vm_env_fingerprint(extra_file: str | None = None) -> str:
    os_release = read_text("/etc/os-release")
    uname = run_cmd(["uname", "-a"])
    pyver = run_cmd(["python3", "--version"])
    pip_freeze = ""
    if os.environ.get("VIRTUAL_ENV"):
        pip_freeze = run_cmd(["python3", "-m", "pip", "freeze"])
    extra = read_text(extra_file) if extra_file else ""

    material = "\n".join([
        "OS_RELEASE=" + os_release,
        "UNAME=" + uname,
        "PYVER=" + pyver,
        "PIP_FREEZE=" + pip_freeze,
        "EXTRA=" + extra
    ]).encode("utf-8")
    return hashlib.sha256(material).hexdigest()

def compute_attest_hash(sender_path: str, env_fp_hex: str) -> str:
    sender_h = sha256_file(sender_path)
    return hashlib.sha256((sender_h + "\n" + env_fp_hex).encode("utf-8")).hexdigest()

def encrypt_and_mac(aes_key_file: str, hmac_key_file: str, inner: bytes, attest_hex: str):
    aes_key = open(aes_key_file, "rb").read()
    hmac_key = open(hmac_key_file, "rb").read()
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes")

    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, inner, None)  # includes tag
    enc_b64 = base64.b64encode(ciphertext).decode("ascii")
    nonce_hex = nonce.hex()

    mac_data = f"{attest_hex}:{nonce_hex}:{enc_b64}".encode("utf-8")
    mac_hex = hmac.new(hmac_key, mac_data, hashlib.sha256).hexdigest()
    return nonce_hex, enc_b64, mac_hex

def send_udp(ip: str, port: int, payload: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload.encode("utf-8"), (ip, port))
    sock.close()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ip", required=True)
    p.add_argument("--port", type=int, default=14551)
    p.add_argument("--lat", type=float, required=True)
    p.add_argument("--lon", type=float, required=True)
    p.add_argument("--alt", type=float, default=25.0)

    p.add_argument("--aes-key", default="./mavlink_aes256.key")
    p.add_argument("--hmac-key", default="./mavlink_hmac.key")

    p.add_argument("--env-extra-file", default=None)

    p.add_argument("--rate", type=float, default=100.0, help="msgs/sec")
    p.add_argument("--count", type=int, default=5000)
    p.add_argument("--pad-bytes", type=int, default=0)
    args = p.parse_args()

    sender_path = os.path.abspath(__file__)
    env_fp = vm_env_fingerprint(args.env_extra_file)
    attest_hex = compute_attest_hash(sender_path, env_fp)

    pad = "X" * max(0, args.pad_bytes)
    period = 1.0 / args.rate if args.rate > 0 else 0.0

    seq = 0
    t_start = time.perf_counter()
    next_t = t_start

    # Print once so you can add to allowlist if needed
    print(f"[INFO] env_fp={env_fp}")
    print(f"[INFO] attest_hex={attest_hex}")

    for _ in range(args.count):
        seq += 1
        ts_ms = now_ms()
        inner = f"v2|{seq}|{ts_ms}|GOTO|{args.lat},{args.lon},{args.alt}|pad={pad}".encode("utf-8")
        nonce_hex, enc_b64, mac_hex = encrypt_and_mac(args.aes_key, args.hmac_key, inner, attest_hex)
        packet = f"ENC|v2|{attest_hex}|{nonce_hex}|{enc_b64}|{mac_hex}"
        send_udp(args.ip, args.port, packet)

        if period > 0:
            next_t += period
            sleep_s = next_t - time.perf_counter()
            if sleep_s > 0:
                time.sleep(sleep_s)

    elapsed = time.perf_counter() - t_start
    print(f"[OK] Sent {args.count} ENC msgs in {elapsed:.3f}s => {args.count/elapsed:.1f} msgs/sec")

if __name__ == "__main__":
    main()
