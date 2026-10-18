#!/usr/bin/env python3
"""Wrap a raw captured region as an ELF64 analysis image."""
import argparse
import struct
from pathlib import Path
from analysis_common import U64, integer


def wrap(data, base, anchor=None, alignment=4096):
    if not data:
        raise ValueError('dump is empty')
    if base < 0 or base + len(data) > U64:
        raise ValueError('dump address range is outside uint64')
    if alignment < 1 or alignment > (1 << 20) or alignment & (alignment - 1):
        raise ValueError('alignment must be a power of two from 1 to 1048576')
    if anchor is not None and (not 0 <= anchor < U64 or base <= anchor < base + len(data)):
        raise ValueError('anchor must be a uint64 address outside the captured range')
    count = 1 + (anchor is not None)
    minimum = 64 + 56 * count
    offset = minimum + (base - minimum) % alignment
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    header = ident + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0, 64, 0, 0, 64, 56, count, 0, 0, 0)
    headers = struct.pack('<IIQQQQQQ', 1, 5, offset, base, base, len(data), len(data), alignment)
    if anchor is not None:
        headers += struct.pack('<IIQQQQQQ', 1, 6, 0, anchor, anchor, 0, 0, 1)
    return header + headers + bytes(offset - minimum) + data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dump', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--base', type=integer, required=True, help='virtual address of first dump byte')
    parser.add_argument('--anchor', type=integer, help='optional empty RW segment address; carries no captured data')
    parser.add_argument('--alignment', type=integer, default=4096)
    args = parser.parse_args()
    try:
        result = wrap(args.dump.read_bytes(), args.base, args.anchor, args.alignment)
        with args.output.open('xb') as target:
            target.write(result)
    except (OSError, ValueError) as error:
        parser.exit(2, f'error: {error}\n')
    print(f'wrote {args.output}: {len(result)} bytes; analysis image, not executable payload')


if __name__ == '__main__':
    main()
