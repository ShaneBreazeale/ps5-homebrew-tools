#!/usr/bin/env python3
"""Send one ELF to the loader, then log its stdout until the connection
dies. Unlike send_payload.py there is no idle timeout: a wedged or
panicking console keeps the log open on the host, so a continuous
payload (follower-live, thread-probe-v3) streams its whole trace and a
panic power-off only costs the final in-flight write."""
import argparse
import socket
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("elf", type=Path)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=9021)
    ap.add_argument("--log", type=Path, required=True)
    args = ap.parse_args()

    data = args.elf.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        ap.error("expected an ELF64 little-endian payload")
    if args.log.exists():
        ap.error(f"refusing to overwrite {args.log}")

    with socket.create_connection((args.host, args.port), timeout=8) as s:
        s.settimeout(None)
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        print(f"sent {len(data)} bytes; streaming until connection death",
              flush=True)
        start = time.time()
        with args.log.open("xb") as out:
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    out.write(chunk)
                    out.flush()
            except OSError as e:
                print(f"connection ended: {e}", flush=True)
    print(f"streamed {time.time() - start:.1f}s; log: {args.log}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
