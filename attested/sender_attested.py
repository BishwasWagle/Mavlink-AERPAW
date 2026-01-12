#!/usr/bin/env python3
import argparse, base64, hmac, hashlib, os, socket, subprocess, time
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
    """
    Docker-free "runtime image" fingerprint.
    Keep it stable by using deterministic sources.
    """
    os_release = read_text("/etc/os-release")
    uname = run_cmd(["uname", "-a"])
    pyver = run_cmd(["python3", "--version"])

    # Optional: include venv packages if you want stricter binding
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
    material = (sender_h + "\n" + env_fp_hex).encode("utf-8")
    return hashlib.sha256(material).hexdigest()

def encrypt_and_mac(aes_key_file: str, hmac_key_file: str, inner_plaintext: bytes, attest_hex: str):
    aes_key = open(aes_key_file, "rb").read()
    hmac_key = open(hmac_key_file, "rb").read()
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes for AES-256")

    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, inner_plaintext, None)
    enc_b64 = base64.b64encode(ciphertext).decode("ascii")
    nonce_hex = nonce.hex()

    mac_data = f"{attest_hex}:{nonce_hex}:{enc_b64}".encode("utf-8")
    mac_hex = hmac.new(hmac_key, mac_data, hashlib.sha256).hexdigest()
    return nonce_hex, enc_b64, mac_hex

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

    # “container image” substitute: environment fingerprint
    p.add_argument("--env-extra-file", default=None,
                   help="Optional file whose content is included in environment fingerprint (e.g., build_id.txt)")

    # seq/ts controls
    p.add_argument("--seq", type=int, default=None)
    p.add_argument("--freeze_ts", action="store_true")
    p.add_argument("--freeze_seq", type=int, default=None)

    args = p.parse_args()

    sender_path = os.path.abspath(__file__)
    env_fp = vm_env_fingerprint(args.env_extra_file)
    attest_hex = compute_attest_hash(sender_path, env_fp)

    if not hasattr(main, "_seq_counter"):
        main._seq_counter = 0
    if not hasattr(main, "_fixed_ts"):
        main._fixed_ts = now_ms()

    if args.freeze_seq is not None:
        seq = int(args.freeze_seq)
    elif args.seq is not None:
        seq = int(args.seq)
    else:
        main._seq_counter += 1
        seq = main._seq_counter

    ts_ms = main._fixed_ts if args.freeze_ts else now_ms()

    inner = f"v2|{seq}|{ts_ms}|GOTO|{args.lat},{args.lon},{args.alt}".encode("utf-8")
    nonce_hex, enc_b64, mac_hex = encrypt_and_mac(args.aes_key, args.hmac_key, inner, attest_hex)

    packet = f"ENC|v2|{attest_hex}|{nonce_hex}|{enc_b64}|{mac_hex}"

    print(f"[INFO] env_fp={env_fp[:12]}... attest={attest_hex[:12]}...")
    send_udp(args.ip, args.port, packet)
    print(f"[OK] Sent ENC v2 seq={seq} ts_ms={ts_ms}")

if __name__ == "__main__":
    main()
