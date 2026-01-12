#!/usr/bin/env python3
"""
PLAIN benchmark sender.
Sends:
  PLAIN|v1|seq|ts_ms|GOTO|lat,lon,alt|pad=<N bytes>

Controls:
  --rate <msgs/sec>
  --count <num msgs>
  --pad-bytes <N>
"""

import argparse
import socket
import time

def now_ms() -> int:
    return int(time.time() * 1000)

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

    p.add_argument("--rate", type=float, default=100.0, help="msgs/sec")
    p.add_argument("--count", type=int, default=5000)
    p.add_argument("--pad-bytes", type=int, default=0, help="add payload to amplify work")
    args = p.parse_args()

    pad = "X" * max(0, args.pad_bytes)
    period = 1.0 / args.rate if args.rate > 0 else 0.0

    seq = 0
    t_start = time.perf_counter()
    next_t = t_start

    for _ in range(args.count):
        seq += 1
        ts_ms = now_ms()
        payload = f"PLAIN|v1|{seq}|{ts_ms}|GOTO|{args.lat},{args.lon},{args.alt}|pad={pad}"
        send_udp(args.ip, args.port, payload)

        if period > 0:
            next_t += period
            sleep_s = next_t - time.perf_counter()
            if sleep_s > 0:
                time.sleep(sleep_s)

    elapsed = time.perf_counter() - t_start
    print(f"[OK] Sent {args.count} PLAIN msgs in {elapsed:.3f}s => {args.count/elapsed:.1f} msgs/sec")

if __name__ == "__main__":
    main()
