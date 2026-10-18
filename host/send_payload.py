#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Send one ELF to elfldr and capture its output, without probes or retries."""

import argparse
import hashlib
from pathlib import Path
import socket
import sys

if __package__:
    from .capture_manifest import file_identity, new_manifest, utc_now, write_manifest
else:
    from capture_manifest import file_identity, new_manifest, utc_now, write_manifest


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
    parser.add_argument('--firmware', help='operator-supplied firmware label')
    parser.add_argument('--model', help='operator-supplied console model')
    parser.add_argument('--resident-profile', help='operator-supplied resident profile')
    args = parser.parse_args(argv)

    try:
        data = args.elf.read_bytes()
        if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
            parser.error('expected an ELF64 little-endian payload with a complete header')
        # Reserve the log before opening the loader connection. An existing log
        # must never consume a loader connection or trigger a second payload run.
        manifest = new_manifest(args.elf, args.log, args.firmware, args.model,
                                args.resident_profile)
        manifest['payload'] = {'name': args.elf.name, 'bytes': len(data),
                               'sha256': hashlib.sha256(data).hexdigest()}
        manifest['transport'] = {'host': args.host, 'port': args.port,
                                 'started_at': None, 'ended_at': None,
                                 'outcome': 'prepared'}
        manifest_path = Path(str(args.log) + '.json')
        capture = args.log.open('xb')
        try:
            metadata = manifest_path.open('x', encoding='utf-8')
        except OSError:
            # Release the empty log so a stale sidecar does not leave an orphan.
            capture.close()
            args.log.unlink()
            raise
        with capture, metadata:
            write_manifest(metadata, manifest)
            try:
                manifest['transport']['started_at'] = utc_now()
                manifest['transport']['outcome'] = 'connecting'
                write_manifest(metadata, manifest)
                with socket.create_connection((args.host, args.port), timeout=8) as connection:
                    connection.settimeout(args.idle_timeout)
                    manifest['transport']['outcome'] = 'sending'
                    write_manifest(metadata, manifest)
                    connection.sendall(data)
                    connection.shutdown(socket.SHUT_WR)
                    manifest['transport']['outcome'] = 'receiving'
                    print(f'Sent {len(data)} bytes from {args.elf.name}', flush=True)
                    while True:
                        try:
                            chunk = connection.recv(65536)
                        except socket.timeout:
                            manifest['transport']['outcome'] = 'idle_timeout'
                            print('Log connection idle; payload may still be running. '
                                  'Do not resend automatically.', file=sys.stderr)
                            return 2
                        if not chunk:
                            manifest['transport']['outcome'] = 'eof'
                            return 0
                        capture.write(chunk)
                        capture.flush()
                        print(chunk.decode('utf-8', errors='replace'), end='', flush=True)
            except OSError as error:
                manifest['transport']['error'] = str(error)
                manifest['transport']['outcome'] += '_error'
                raise
            finally:
                capture.flush()
                manifest['capture'] = file_identity(args.log)
                manifest['transport']['ended_at'] = utc_now()
                write_manifest(metadata, manifest)
    except OSError as error:
        print(f'{error}. Payload execution state may be unknown; no retry was made.',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
