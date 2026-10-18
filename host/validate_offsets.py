#!/usr/bin/env python3
"""Inspect offsets and optional exact byte signatures in a raw captured region."""
import argparse
import hashlib
import json
from pathlib import Path
from analysis_common import U64, integer, load_table


def validate(data, table, base, origin, checks):
    if not data or not 0 <= base < U64 or base + len(data) > U64 or not 0 <= origin < U64:
        raise ValueError('empty dump or invalid uint64 mapping')
    if not isinstance(checks, dict):
        raise ValueError('checks must be an object mapping symbols to hex byte strings')
    patterns = {}
    for name, value in checks.items():
        pattern = bytes.fromhex(value)
        if not pattern:
            raise ValueError(f'empty signature for {name}')
        patterns[name] = pattern
    rows = []
    for name in sorted(set(table) | set(patterns)):
        if name not in table:
            rows.append({'name': name, 'status': 'missing', 'checked': True})
            continue
        va = origin + table[name]
        offset = va - base
        pattern = patterns.get(name)
        size = len(pattern) if pattern else 1
        inside = 0 <= va < U64 and 0 <= offset and offset + size <= len(data)
        status = 'outside_capture' if not inside else ('match' if data[offset:offset+size] == pattern else 'mismatch') if pattern else 'unverified'
        rows.append({'name': name, 'address': hex(va), 'file_offset': offset,
                     'checked': pattern is not None, 'status': status,
                     'bytes': data[offset:offset+max(size, 24)].hex() if inside else None})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('table', type=Path, help='DEF(name, expression) header or JSON symbol-to-integer map')
    parser.add_argument('--dump', type=Path)
    parser.add_argument('--base', type=integer, help='virtual address of first captured byte')
    parser.add_argument('--origin', type=integer, help='address added to table values')
    parser.add_argument('--profile', type=Path, help='JSON checks and optional mapping defaults')
    parser.add_argument('--compare', type=Path, help='compare against a second DEF/JSON table by symbol')
    args = parser.parse_args()
    try:
        table = load_table(args.table)
        report = {'limitation': 'Byte signatures and table equality do not validate semantics or console compatibility.'}
        failed = False
        if args.compare:
            other = load_table(args.compare)
            report['comparison'] = [{'name': name, 'left': table.get(name), 'right': other.get(name),
                                     'equal': name in table and name in other and table[name] == other[name]}
                                    for name in sorted(set(table) | set(other))]
            failed = any(not row['equal'] for row in report['comparison'])
        if args.dump:
            profile = json.loads(args.profile.read_text()) if args.profile else {}
            if not isinstance(profile, dict):
                raise ValueError('profile must be a JSON object')
            base = args.base if args.base is not None else integer(profile['base'])
            origin = args.origin if args.origin is not None else integer(profile['origin'])
            data = args.dump.read_bytes()
            if 'size' in profile and len(data) != integer(profile['size']):
                raise ValueError('dump size differs from profile')
            report['sha256'] = hashlib.sha256(data).hexdigest()
            report['profile'] = profile.get('name')
            report['offsets'] = validate(data, table, base, origin, profile.get('checks', {}))
            failed |= any(row['checked'] and row['status'] != 'match' for row in report['offsets'])
        elif not args.compare:
            raise ValueError('provide --dump or --compare')
        elif args.profile or args.base is not None or args.origin is not None:
            raise ValueError('mapping/profile options require --dump')
    except (OSError, ValueError, TypeError, KeyError, SyntaxError, RecursionError) as error:
        parser.exit(2, f'error: {error}\n')
    print(json.dumps(report, indent=2))
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
