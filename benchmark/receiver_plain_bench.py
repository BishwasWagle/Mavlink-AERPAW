#!/usr/bin/env python3
"""
PLAIN UDP command receiver benchmark.

Accepts:
  PLAIN|v1|seq|ts_ms|GOTO|lat,lon,alt|pad=<optional>

Logs per-packet metrics to CSV:
  mode,verdict,reason,seq,sender_ts_ms,recv_ts_ms,e2e_ms,proc_ms,payload_bytes,sender_ip

Optional:
  --no_io   disables /tmp/flight_cmd.txt and /tmp/secure_ok.flag writes (recommended for pure compute benchmarking)
"""

import argparse
import csv
import datetime
import os
import socket
import time

CMD_FILE = "/tmp/flight_cmd.txt"
SECURE_FLAG = "/tmp/secure_ok.flag"

def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def now_ms() -> int:
    return int(time.time() * 1000)

def set_secure_ok():
    with open(SECURE_FLAG, "w") as f:
        f.write("1")

def publish_cmd(cmd: str, lat: float, lon: float, alt: float):
    os.makedirs(os.path.dirname(CMD_FILE), exist_ok=True)
    with open(CMD_FILE, "w") as f:
        f.write(f"plain|{cmd}|{lat},{lon},{alt}\n")

def parse_plain(packet: str):
    # PLAIN|v1|seq|ts_ms|GOTO|lat,lon,alt|pad=...
    if not packet.startswith("PLAIN|"):
        return None, "not_plain"
    parts = packet.split("|")
    if len(parts) < 6:
        return None, "bad_format"

    # Allow flexible tail fields
    # PLAIN | v1 | seq | ts_ms | GOTO | coords | ...
    try:
        _, ver, seq_s, ts_s, cmd, coords, *_rest = parts
    except ValueError:
        return None, "bad_format"

    if ver != "v1":
        return None, "bad_version"
    if cmd != "GOTO":
        return None, "bad_cmd"

    try:
        seq = int(seq_s)
        sender_ts_ms = int(ts_s)
        lat_s, lon_s, alt_s = coords.split(",")
        lat, lon, alt = float(lat_s), float(lon_s), float(alt_s)
    except Exception:
        return None, "parse_error"

    return (seq, sender_ts_ms, cmd, lat, lon, alt), "ok"

def csv_writer_open(path: str):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    f = open(path, "a", newline="", buffering=1)  # line-buffered
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
    p.add_argument("--csv", default="./bench_plain.csv")
    p.add_argument("--no_io", action="store_true",
                   help="Benchmark mode: disable /tmp file writes")
    args = p.parse_args()

    _fcsv, wcsv = csv_writer_open(args.csv)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen, args.port))
    print(f"[{ts()}] [INFO] PLAIN receiver listening on {args.listen}:{args.port}")
    print(f"[{ts()}] [INFO] Logging to {args.csv}  no_io={args.no_io}")

    while True:
        data, addr = sock.recvfrom(args.buf)
        t0 = time.perf_counter_ns()  # START AFTER recvfrom => compute time only
        recv_ts_ms = now_ms()

        sender_ip = addr[0]
        payload_bytes = len(data)
        packet = data.decode("utf-8", errors="ignore").strip()

        parsed, reason = parse_plain(packet)

        verdict = "DROP"
        e2e_ms = ""
        seq = ""
        sender_ts_ms = ""

        if parsed:
            seq, sender_ts_ms, cmd, lat, lon, alt = parsed
            e2e_ms = recv_ts_ms - sender_ts_ms
            verdict = "ACCEPT"
            reason = "ok"
            if not args.no_io:
                set_secure_ok()
                publish_cmd(cmd, lat, lon, alt)

        proc_ms = (time.perf_counter_ns() - t0) / 1e6

        wcsv.writerow([
            "PLAIN", verdict, reason, seq, sender_ts_ms, recv_ts_ms,
            e2e_ms, f"{proc_ms:.6f}", payload_bytes, sender_ip
        ])

if __name__ == "__main__":
    main()
