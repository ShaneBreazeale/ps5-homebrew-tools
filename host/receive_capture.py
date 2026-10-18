#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Receive one bounded, checksummed capture into a new directory (no retries)."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import socket
import struct
import tempfile
import zlib

MAX_BYTES = 1 << 30
MAX_MANIFEST = 1 << 20
HEADER = struct.Struct('<4sIQ')


def recv_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError(f'truncated transfer: received {len(result)}/{size} bytes')
        result.extend(chunk)
    return bytes(result)


def receive(sock, output, max_bytes=MAX_BYTES):
    """Publish only after manifest, payload, explicit END1, and clean EOF verify."""
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError(f'output already exists: {output}')
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.capture-', dir=output.parent))
    files = {}
    total = 0
    try:
        while True:
            magic, name_len, size = HEADER.unpack(recv_exact(sock, HEADER.size))
            if magic == b'END1':
                if name_len or size:
                    raise ValueError('invalid completion frame')
                if sock.recv(1):
                    raise ValueError('trailing bytes after completion')
                break
            if magic != b'FPK1' or not 1 <= name_len <= 128:
                raise ValueError('invalid file frame')
            name = recv_exact(sock, name_len).decode('ascii')
            if name not in ('manifest.json', 'kernel_text.bin') or name in files:
                raise ValueError(f'unexpected or duplicate file name: {name!r}')
            if size > max_bytes or total + size > max_bytes + MAX_MANIFEST:
                raise ValueError('capture exceeds byte limit')
            if name == 'manifest.json' and size > MAX_MANIFEST:
                raise ValueError('manifest exceeds byte limit')
            crc, sha, remaining = 0, hashlib.sha256(), size
            with (stage / name).open('xb') as stream:
                while remaining:
                    data = recv_exact(sock, min(65536, remaining))
                    stream.write(data)
                    crc = zlib.crc32(data, crc)
                    sha.update(data)
                    remaining -= len(data)
                stream.flush()
                os.fsync(stream.fileno())
            files[name] = {'size': size, 'crc32': f'{crc:08x}', 'sha256': sha.hexdigest()}
            total += size
        if set(files) != {'manifest.json', 'kernel_text.bin'}:
            raise ValueError('missing manifest or kernel capture')
        manifest = json.loads((stage / 'manifest.json').read_text())
        if not isinstance(manifest, dict):
            raise ValueError('manifest must be a JSON object')
        payload = files['kernel_text.bin']
        if manifest.get('complete') is not True or manifest.get('status') != 'complete':
            raise ValueError('manifest does not declare a complete capture')
        sizes = [manifest.get('written_bytes'), manifest.get('expected_bytes')]
        if any(type(n) is not int or n != payload['size'] or n <= 0 for n in sizes):
            raise ValueError('manifest size mismatch')
        expected_crc = manifest.get('crc32_of_written_bytes')
        if not isinstance(expected_crc, str) or int(expected_crc, 16) != int(payload['crc32'], 16):
            raise ValueError('capture CRC32 mismatch')
        # Reserve the destination atomically to avoid replacing another capture.
        output.mkdir()
        try:
            for name in files:
                os.replace(stage / name, output / name)
            (output / 'transfer.json').write_text(json.dumps({'protocol': 'FPK1-END1', 'files': files}, indent=2) + '\n')
        except BaseException:
            shutil.rmtree(output)
            raise
        return files
    finally:
        shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host', help='console address')
    parser.add_argument('output', type=Path, help='new output directory')
    parser.add_argument('--port', type=int, default=9030)
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--max-bytes', type=int, default=MAX_BYTES)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not math.isfinite(args.timeout) or args.timeout <= 0 or args.max_bytes <= 0:
        parser.error('port, timeout, and max-bytes must be positive and in range')
    if args.output.exists() or args.output.is_symlink():
        parser.error(f'output already exists: {args.output}')
    try:
        with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
            files = receive(sock, args.output, args.max_bytes)
    except (OSError, ValueError, EOFError) as error:
        parser.exit(1, f'capture failed: {error}\n')
    print(json.dumps({'output': str(args.output), 'files': files}, indent=2))


if __name__ == '__main__':
    main()
