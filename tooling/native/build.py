#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build the native starter and source-generated runtime into a folder and ZIP."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[2]
NATIVE = Path(__file__).resolve().parent
RAW_SHA = '8ee6e124993e1af26420cb455890fd002f5d6c7e78883c860ce45734e7d002bb'
SIGNED_SHA = 'e6ff45d16adf687855cc3b33b0c8a4132b6504360b221e0a34c7e99fb3ba0036'

def run(*args):
    subprocess.run([str(a) for a in args], check=True)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def icon(path):
    """Original geometric icon, produced without image libraries or source artwork."""
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    rows = bytearray()
    for y in range(512):
        rows.append(0)
        for x in range(512):
            edge = 112 <= x < 400 and 112 <= y < 400
            cutout = 160 <= x < 352 and 160 <= y < 352
            rows.extend((35, 193, 172, 255) if edge and not cutout else (15, 25, 42, 255))
    path.write_bytes(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 512, 512, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(bytes(rows), 9)) + chunk(b'IEND', b''))

def build_runtime(work):
    """Compile the host tools and regenerate libc.prx, checking pinned checksums."""
    cxx = shlex.split(os.environ.get('CXX', 'c++'))
    tool = work / 'ps5-native-tool'
    libc = work / 'libc-builder'
    common = ['-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror']
    run(*cxx, *common, *[NATIVE / (n + '.cpp') for n in ['native_app_builder', 'self_container', 'elf_object', 'sce_module_writer']], '-lz', '-o', tool)
    run(*cxx, *common, NATIVE / 'libc_builder.cpp', '-o', libc)
    raw = work / 'libc.elf'
    runtime = work / 'libc.prx'
    run(libc, NATIVE / 'runtime/api-surface.txt', NATIVE / 'runtime/imports.txt', raw)
    if sha(raw) != RAW_SHA:
        raise ValueError('generated raw runtime does not match upstream checksum')
    run(tool, 'self', '--sign', '--in', raw, '--out', runtime)
    if sha(runtime) != SIGNED_SHA:
        raise ValueError('generated signed runtime does not match upstream checksum')
    return tool, libc, runtime

def check_runtime():
    with tempfile.TemporaryDirectory(prefix='native-check-') as temp:
        build_runtime(Path(temp))
    print('Native runtime checksums match pinned values; console validation: pending')

def build(args):
    sdk = args.sdk.resolve()
    source = args.template.resolve()
    metadata = json.loads((source / 'sce_sys/param.json').read_text())
    title = metadata.get('titleId', '')
    if not re.fullmatch(r'PPSA\d{5}', title):
        raise ValueError('titleId must be PPSA followed by five digits')
    if not re.fullmatch(r'[A-Z]{2}\d{4}-' + title + r'_00-[A-Z0-9]{16}', metadata.get('contentId', '')):
        raise ValueError('contentId must match titleId and contain a 16-character suffix')
    if not (sdk / 'target/lib').is_dir():
        raise ValueError('SDK must contain target/lib')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    destination = output / title
    archive = output / (title + '.zip')
    if destination.exists() or archive.exists():
        raise FileExistsError('application output exists; choose a new --output directory')
    with tempfile.TemporaryDirectory(prefix='.native-build-', dir=output) as temp:
        work = Path(temp)
        tool, libc, runtime = build_runtime(work)
        objects = []
        for unit in [NATIVE / 'app_crt.cpp', NATIVE / 'app_cpp_runtime.cpp', source / 'main.cpp']:
            obj = work / (unit.stem + '.o')
            run(sdk / 'bin/prospero-clang++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-fno-exceptions', '-fno-rtti', '-ffunction-sections', '-fdata-sections', '-c', unit, '-o', obj)
            objects.append(obj)
        stubs = sorted((sdk / 'target/lib').glob('*.so'))
        intermediate, elf = work / 'llvm-pie.elf', work / 'eboot.elf'
        run(sdk / 'bin/prospero-lld', '-T', NATIVE / 'ps5-pie.ld', '--version-script', NATIVE / 'app-symbols.map', '-e', '_start', '-o', intermediate, *objects, '--as-needed', *stubs)
        run(tool, 'link', '--in', intermediate, '--out', elf, '--stub-dir', sdk / 'target/lib', '--module-sdk', '0x02000009', '--companion-sdk', '0x08050001', '--file-name', 'eboot.elf')
        app = work / title
        (app / 'sce_sys').mkdir(parents=True)
        (app / 'sce_module').mkdir()
        run(tool, 'self', '--sign', '--in', elf, '--out', app / 'eboot.bin', '--magic', '0x1D3D154F')
        shutil.copy2(runtime, app / 'sce_module/libc.prx')
        shutil.copy2(source / 'sce_sys/param.json', app / 'sce_sys/param.json')
        icon(app / 'sce_sys/icon0.png')
        for file in [app / 'eboot.bin', app / 'sce_module/libc.prx']:
            run(tool, 'self', '--inspect', '--file', file)
        files = {str(p.relative_to(app)): sha(p) for p in sorted(app.rglob('*')) if p.is_file()}
        (app / 'build-manifest.json').write_text(json.dumps({'schema': 1, 'console_tested': False, 'files': files, 'source_sha256': {str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else p.name: sha(p) for p in [source / 'main.cpp', source / 'sce_sys/param.json', *NATIVE.glob('*.cpp'), *NATIVE.glob('*.hpp'), *NATIVE.glob('*.ld'), *NATIVE.glob('*.map'), *sorted((NATIVE / 'runtime').glob('*.txt'))]}}, indent=2) + '\n')
        temporary_zip = work / (title + '.zip')
        with zipfile.ZipFile(temporary_zip, 'w', zipfile.ZIP_DEFLATED) as bundle:
            for file in sorted(app.rglob('*')):
                if file.is_file():
                    bundle.write(file, str(file.relative_to(work)))
        # Caller-owned output must not be modified concurrently during publication.
        app.rename(destination)
        temporary_zip.rename(archive)
        shutil.copy2(tool, output / 'ps5-native-tool')
        shutil.copy2(libc, output / 'libc-builder')
        shutil.copy2(elf, output / 'eboot.elf')
    print(f'Built {destination}\nArchive: {archive}\nConsole validation: pending')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, default=os.environ.get('PS5_PAYLOAD_SDK'))
    parser.add_argument('--template', type=Path, default=ROOT / 'templates/minimal-app')
    parser.add_argument('--output', type=Path, default=ROOT / 'out/native-app')
    parser.add_argument('--runtime-only', action='store_true',
                        help='rebuild host tools and libc.prx in a temporary directory, verify checksums, keep nothing; no SDK needed')
    args = parser.parse_args()
    if args.sdk is None and not args.runtime_only:
        parser.error('set PS5_PAYLOAD_SDK or pass --sdk')
    try:
        check_runtime() if args.runtime_only else build(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'native build failed: {error}\n')

if __name__ == '__main__':
    main()
