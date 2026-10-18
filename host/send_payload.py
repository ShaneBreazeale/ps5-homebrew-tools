#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Send one ELF to elfldr and capture its output, without probes or retries."""

import argparse
from pathlib import Path
import socket
import sys


def positive_timeout(value):
    result = float(value)
    if not 0 < result < float('inf'):
        raise argparse.ArgumentTypeError('timeout must be positive and finite')
    return result


def port_number(value):
    result = int(value)
    if not 1 <= result <= 65535:
        raise argparse.ArgumentTypeError('port must be between 1 and 65535')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--host', required=True, help='console address or hostname')
    parser.add_argument('--port', type=port_number, default=9021)
    parser.add_argument('--log', type=Path, required=True, help='new capture file; never overwritten')
    parser.add_argument('--idle-timeout', type=positive_timeout, default=60)
    args = parser.parse_args(argv)

    try:
        data = args.elf.read_bytes()
        if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
            parser.error('expected an ELF64 little-endian payload with a complete header')
        # Reserve the log before opening the loader connection. An existing log
        # must never consume a loader connection or trigger a second payload run.
        with args.log.open('xb') as capture:
            with socket.create_connection((args.host, args.port), timeout=8) as connection:
                connection.settimeout(args.idle_timeout)
                connection.sendall(data)
                connection.shutdown(socket.SHUT_WR)
                print(f'Sent {len(data)} bytes from {args.elf.name}', flush=True)
                while True:
                    try:
                        chunk = connection.recv(65536)
                    except TimeoutError:
                        print('Log connection idle; payload may still be running. '
                              'Do not resend automatically.', file=sys.stderr)
                        return 2
                    if not chunk:
                        return 0
                    capture.write(chunk)
                    capture.flush()
                    print(chunk.decode('utf-8', errors='replace'), end='', flush=True)
    except OSError as error:
        print(f'{error}. Payload execution state may be unknown; no retry was made.',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
