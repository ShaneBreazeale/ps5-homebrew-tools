#!/usr/bin/env python3
"""Audit x86-64 patch instruction shapes without applying patches."""
import argparse
import json
import re
from pathlib import Path
from analysis_common import elf_loads, integer


def load_patches(path, array=None):
    text = path.read_text()
    if array:
        text = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
        match = re.search(r'\b' + re.escape(array) + r'\s*\[\s*\]\s*=\s*\{(.*?)\};', text, re.S)
        if not match:
            raise ValueError('named patch array not found')
        body = match.group(1)
        pattern = r'\{\s*(0x[0-9a-fA-F]+|[0-9]+)\s*,\s*"((?:\\x[0-9a-fA-F]{2})+)"\s*,\s*([0-9]+)\s*\}'
        entries = []
        for match in re.finditer(pattern, body):
            offset, escaped, length = match.groups()
            raw = bytes(int(x, 16) for x in re.findall(r'\\x(..)', escaped))
            if len(raw) != int(length):
                raise ValueError('declared patch length differs from bytes')
            entries.append({'offset': offset, 'bytes': raw.hex()})
        if re.sub(pattern, '', body).replace(',', '').strip():
            raise ValueError('unsupported patch array entry')
    else:
        entries = json.loads(text)
    if not isinstance(entries, list) or not entries:
        raise ValueError('patches must be a nonempty JSON list or named C array')
    result = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('each patch must be an object')
        offset, patch = integer(entry['offset']), bytes.fromhex(entry['bytes'])
        if offset < 0 or not patch:
            raise ValueError('patch requires nonnegative offset and nonempty bytes')
        if any(offset < oldoff + len(oldpatch) and oldoff < offset + len(patch) for oldoff, oldpatch in result):
            raise ValueError('overlapping patches')
        result.append((offset, patch))
    return result


def classify(original, patch):
    short = len(original) >= 2 and 0x70 <= original[0] <= 0x7f
    near = len(original) >= 6 and original[0] == 0x0f and 0x80 <= original[1] <= 0x8f
    if patch in (b'\xeb', b'\x66\x90'):
        return ('shape_match' if short else 'mismatch', 'requires complete two-byte conditional branch')
    if patch in (b'\x90\xe9', b'\xeb\x04'):
        return ('shape_match' if near else 'mismatch', 'requires complete six-byte conditional branch')
    if patch == b'\xeb\x03':
        return ('shape_match' if len(original) >= 5 and original[0] == 0xe8 else 'mismatch', 'requires complete five-byte call')
    return 'manual_review', 'return stubs, padding, constants and other edits require semantic review'


def audit(data, patches, base=None):
    loads = elf_loads(data)
    base = min(va for va, _, _ in loads) if base is None else base
    if not 0 <= base < 1 << 64:
        raise ValueError('base must fit uint64')
    rows = []
    for offset, patch in patches:
        va = base + offset
        original = None
        for start, fileoff, size in loads:
            relative = va - start
            if 0 <= relative and relative + len(patch) <= size:
                original = data[fileoff+relative:fileoff+min(size, relative+max(16, len(patch)))]
                break
        status, note = ('outside_capture', 'patch is not fully file-backed') if original is None else classify(original, patch)
        rows.append({'offset': hex(offset), 'address': hex(va), 'patch': patch.hex(),
                     'original': original.hex() if original is not None else None, 'status': status, 'note': note})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('patches', type=Path)
    parser.add_argument('--array', help='exact C array name; omitted for JSON input')
    parser.add_argument('--base', type=integer, help='module offset origin; defaults to lowest file-backed PT_LOAD')
    args = parser.parse_args()
    try:
        rows = audit(args.elf.read_bytes(), load_patches(args.patches, args.array), args.base)
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(2, f'error: {error}\n')
    print(json.dumps({'limitation': 'Instruction-shape heuristics only; branch targets and runtime semantics are unverified.', 'patches': rows}, indent=2))
    return int(any(row['status'] != 'shape_match' for row in rows))


if __name__ == '__main__':
    raise SystemExit(main())
