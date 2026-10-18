#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Create a source-and-artifact bundle with SHA-256 inventory."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT).decode().strip()


def package(output, artifacts):
    output = output.resolve()
    if output.exists():
        raise FileExistsError(f'output exists: {output}')
    output.parent.mkdir(parents=True, exist_ok=True)
    # Tracked files only: untracked notes or captures must never ship in a bundle.
    paths = git('ls-files', '--cached', '-z').split('\0')
    sources = [ROOT / name for name in paths if name and (ROOT / name).is_file()]
    selected = []
    for arg in artifacts:
        path = arg.resolve()
        if not path.is_file() or not path.is_relative_to(ROOT):
            raise ValueError(f'artifact must be a regular file inside the repository: {arg}')
        selected.append(path)
    entries = {str(path.relative_to(ROOT)): path.read_bytes() for path in sources + selected}
    if len(entries) != len(sources) + len(selected):
        raise ValueError('duplicate archive path')
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(entries.items())}
    manifest = {
        'schema': 1,
        'source_commit': git('rev-parse', 'HEAD'),
        'source_dirty': bool(git('status', '--porcelain', '--untracked-files=normal')),
        'artifacts': sorted(str(path.relative_to(ROOT)) for path in selected),
        'sha256': hashes,
    }
    entries['manifest.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    entries['SHA256SUMS'] = (''.join(f'{digest}  {name}\n' for name, digest in hashes.items())).encode()
    try:
        with output.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as archive:
                for name, data in sorted(entries.items()):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    archive.addfile(info, io.BytesIO(data))
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    print(f'Wrote {output} ({len(selected)} artifacts, {len(sources)} source files)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--artifact', type=Path, action='append', default=[])
    args = parser.parse_args()
    try:
        package(args.output, args.artifact)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'package failed: {error}\n')


if __name__ == '__main__':
    main()
