#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Create a checksum manifest for an existing diagnostic capture."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def file_identity(path):
    path = Path(path)
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(chunk)
            digest.update(chunk)
    return {'name': path.name, 'bytes': size, 'sha256': digest.hexdigest()}


def source_identity():
    root = Path(__file__).resolve().parents[1]
    try:
        commit = subprocess.check_output(
            ['git', '-C', str(root), 'rev-parse', 'HEAD'], stderr=subprocess.DEVNULL,
            text=True).strip()
        dirty = bool(subprocess.check_output(
            ['git', '-C', str(root), 'status', '--porcelain'], stderr=subprocess.DEVNULL,
            text=True).strip())
        return {'commit': commit, 'dirty': dirty}
    except (OSError, subprocess.CalledProcessError):
        return {'commit': None, 'dirty': None}


def new_manifest(payload, capture, firmware=None, model=None, resident_profile=None):
    return {'schema_version': 1, 'created_at': utc_now(),
            'source': source_identity(), 'payload': file_identity(payload),
            'capture': {'name': Path(capture).name},
            'environment': {'firmware': firmware, 'model': model,
                            'resident_profile': resident_profile},
            'environment_source': 'operator-supplied; not detected',
            'payload_execution': 'unknown'}


def write_manifest(stream, manifest):
    stream.seek(0)
    json.dump(manifest, stream, indent=2, sort_keys=True)
    stream.write('\n')
    stream.truncate()
    stream.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--payload', type=Path, required=True)
    parser.add_argument('--output', type=Path, help='default: <capture>.json')
    parser.add_argument('--firmware')
    parser.add_argument('--model')
    parser.add_argument('--resident-profile')
    parser.add_argument('--notes')
    args = parser.parse_args(argv)
    destination = args.output or Path(str(args.capture) + '.json')
    try:
        manifest = new_manifest(args.payload, args.capture, args.firmware,
                                args.model, args.resident_profile)
        manifest['capture'] = file_identity(args.capture)
        manifest['transport'] = {'outcome': 'not_recorded', 'started_at': None,
                                 'ended_at': None}
        manifest['notes'] = args.notes
        with destination.open('x', encoding='utf-8') as stream:
            write_manifest(stream, manifest)
    except (OSError, ValueError) as error:
        parser.exit(1, f'{error}\n')
    print(destination)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
