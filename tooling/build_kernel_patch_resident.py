#!/usr/bin/env python3
"""Link a private pinned resident with LLVM 18; never install or contact a console.

The installer translation unit is compiled, not linked into a payload: its
research-runtime entry/bootstrap still needs a separately reviewed SDK adapter.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess

from verify_kernel_patch_stage2 import verify

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def audit_elf(data, allowed, executable_entry=True):
    """Check the subset actually consumed by the pinned load_kelf, not system ld.

    Deliberately independent of readelf's text format. No execution or relocation
    of the input occurs here. All reads and mapped ranges are bounded.
    """
    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            raise ValueError('truncated ELF structure')
        return struct.unpack_from(fmt, data, offset)

    header = unpack('<16sHHIQQQIHHHHHH', 0)
    ident, kind, machine, version, entry, phoff = header[:6]
    if ident[:7] != b'\x7fELF\x02\x01\x01' or (kind, machine, version) != (3, 62, 1):
        raise ValueError('expected a little-endian x86-64 shared ELF')
    if header[8:10] != (64, 56) or not 1 <= header[10] <= 32:
        raise ValueError('invalid ELF program header layout')
    segments, dynamic = [], None
    for index in range(header[10]):
        ph = unpack('<IIQQQQQQ', phoff + index * 56)
        ptype, flags, off, va, _, filesz, memsz, align = ph
        if off + filesz > len(data) or va + memsz >= 1 << 64:
            raise ValueError('ELF segment is outside the image')
        if ptype == 1:
            if filesz > memsz or va + memsz > 0x1f0000 or align not in (1, 4096):
                raise ValueError('ELF load segment exceeds resident mapping/layout')
            if align > 1 and (off - va) % align:
                raise ValueError('incongruent ELF segment alignment')
            if any(va < end and start < va + memsz for start, end, *_ in segments):
                raise ValueError('overlapping ELF load segments')
            segments.append((va, va + memsz, off, filesz, flags))
        elif ptype == 2:
            if dynamic is not None or filesz % 16:
                raise ValueError('invalid ELF dynamic segment')
            dynamic = (off, filesz)
        elif ptype in (3, 7):
            raise ValueError('resident ELF cannot use an interpreter or TLS')
    if not segments or dynamic is None or not any(start <= entry < end and
            (flags & 1 or not executable_entry) for start, end, _, _, flags in segments):
        raise ValueError('resident entry point is not in an appropriate load segment')

    def mapped(va, size, file_backed=True):
        for start, end, off, filesz, _ in segments:
            if start <= va and va + size <= (start + filesz if file_backed else end):
                return off + va - start
        raise ValueError('ELF table or relocation is outside a load segment')

    tags = {}
    for off in range(dynamic[0], sum(dynamic), 16):
        tag, value = unpack('<QQ', off)
        if tag == 0:
            break
        if tag in tags:
            raise ValueError('duplicate ELF dynamic tag')
        tags[tag] = value
    else:
        raise ValueError('unterminated ELF dynamic table')
    if any(tag in tags for tag in (1, 2, 17, 18, 20, 23, 35, 36, 37)):
        raise ValueError('resident loader cannot handle dependencies, PLT, REL or RELR')
    if not {5, 6, 7, 8, 9, 10, 11} <= tags.keys():
        raise ValueError('missing resident dynamic tables')
    if tags.get(11) != 24 or tags.get(9) != 24 or tags.get(8, 0) % 24:
        raise ValueError('unsupported resident symbol/RELA layout')
    strsize = tags.get(10, 0)
    strings = mapped(tags[5], strsize)
    symbase = tags[6]
    rela = mapped(tags[7], tags[8])
    imports, counts = set(), {}
    for off in range(rela, rela + tags[8], 24):
        target, info, addend = unpack('<QQq', off)
        mapped(target, 8, False)
        rtype, symindex = info & 0xffffffff, info >> 32
        if rtype not in (1, 6, 8) or (rtype == 6 and addend) or (rtype == 8 and symindex):
            raise ValueError('unsupported resident relocation')
        counts[str(rtype)] = counts.get(str(rtype), 0) + 1
        if rtype == 8:
            if not any(start <= addend <= end for start, end, *_ in segments):
                raise ValueError('relative relocation points outside resident mapping')
            continue
        nameoff, _, _, shndx, value, _ = unpack('<IBBHQQ', mapped(symbase + symindex * 24, 24))
        if nameoff >= strsize:
            raise ValueError('symbol name is outside ELF string table')
        end = data.find(b'\0', strings + nameoff, strings + strsize)
        if end < 0:
            raise ValueError('unterminated ELF symbol name')
        name = data[strings + nameoff:end].decode('ascii')
        # load_kelf treats value==0 as an external, even for a defined symbol.
        if value == 0:
            if shndx != 0 or name not in allowed:
                raise ValueError('unresolved/unexpected resident import: ' + name)
            imports.add(name)
        elif shndx != 0xfff1:
            # This loader does not add load bias to defined symbol values in
            # R_X86_64_64/GLOB_DAT: local addresses must use RELATIVE instead.
            raise ValueError('symbol relocation needs unsupported local load-bias handling')
    return {'entry': entry, 'mapped_size': max(end for _, end, *_ in segments),
            'imports': sorted(imports), 'relocations': counts, 'loader_subset_checked': True}


def loader_symbols(source):
    text = (source / 'prosper0gdb/offsets/offset_list.txt').read_text()
    symbols = set(re.findall(r'^(?:KDATA_OFFSET|ABSOLUTE_OFFSET|OPTIONAL_KDATA_OFFSET)\((\w+)\)', text, re.M))
    symbols.update(('comparison_table', 'dmem', 'int1_handler', 'int3_handler', 'int13_handler',
                    'ist_errc', 'ist_noerrc', 'ist4', 'pcpu', 'shared_area', 'tss',
                    'uelf_cr3', 'uelf_entry', 'fwver'))
    return symbols


def build(overlay, output, sdk, obs=0, yasm='yasm', nasm='nasm', jobs=4):
    overlay, output, sdk = Path(overlay).resolve(), Path(output).absolute(), Path(sdk).resolve()
    identity = verify(overlay)
    manifest = json.loads((overlay / 'manifest.json').read_text())
    if 'link_inputs' not in manifest['identity_inputs']:
        raise ValueError('prepare a fresh overlay with --link-inputs')
    if output.exists():
        raise ValueError('build output already exists; use a fresh directory')
    if obs not in (0, 1) or not 1 <= jobs <= 32:
        raise ValueError('invalid build configuration')
    if not (sdk / 'toolchain/prospero.mk').is_file():
        raise ValueError('SDK must contain toolchain/prospero.mk')
    tools = {name: sdk / 'bin' / ('prospero-' + name) for name in ('clang', 'llvm-config', 'ar', 'objcopy')}
    for name, value in (('yasm', yasm), ('nasm', nasm)):
        path = shutil.which(value)
        if not path:
            raise ValueError('missing assembler: ' + name)
        tools[name] = Path(path).resolve()
    version = subprocess.check_output([str(tools['llvm-config']), '--version'], text=True).strip()
    if not re.fullmatch(r'18\.\d+\.\d+', version):
        raise ValueError('resident build requires LLVM 18, found ' + version)
    bindir = Path(subprocess.check_output([str(tools['llvm-config']), '--bindir'], text=True).strip())
    llvm_tools = {name: {'path': str((bindir / name).resolve()), 'sha256': digest(bindir / name)}
                  for name in ('clang', 'ld.lld', 'llvm-objcopy')}
    output.mkdir(mode=0o700)
    os.chmod(output, 0o700)
    (output / 'INCOMPLETE').write_text('Build has not completed; do not use partial artifacts.\n')
    (output / 'objects').mkdir()
    (output / 'logs').mkdir()
    (output / 'uelf').mkdir()
    source = overlay / 'source'
    kstuff = source / 'ps5-kstuff'
    uelf, bear, isa = kstuff / 'uelf', kstuff / 'BearSSL', kstuff / 'isa-l_crypto'
    commands = []

    def run(label, args):
        args = [str(arg) for arg in args]
        record = {'label': label, 'argv': args, 'cwd': str(output)}
        commands.append(record)
        with (output / 'logs' / (label + '.log')).open('xb') as log:
            status = subprocess.run(args, cwd=output, stdout=log, stderr=subprocess.STDOUT).returncode
        record['exit_status'] = status
        if status:
            raise ValueError('build failed at ' + label + '; see private build log')

    common = ['-std=gnu11', '-O3', '-g', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
              '-fno-ident', '-fno-plt', '-fPIC', '-mno-red-zone', '-mgeneral-regs-only',
              '-ffunction-sections', '-fdata-sections', '-nostdinc',
              '-I', source / 'freebsd-headers', '-isystem', isa / 'include',
              '-I', uelf, '-DKSTUFF_OBS=' + str(obs),
              '-ffile-prefix-map=' + str(overlay) + '=/private-overlay',
              '-ffile-prefix-map=' + str(output) + '=/private-build',
              '-ffile-prefix-map=' + str(sdk) + '=/ps5-payload-sdk']
    units = [(path, []) for path in sorted(uelf.glob('*.c'))]
    units.append((uelf / 'kp_stage2/runtime.c', ['-fvisibility=hidden']))
    # Preserve the existing BearSSL integer implementation and ISA-L subset.
    units += [(path, ['-I', bear / 'inc', '-I', bear / 'src', '-include', kstuff / 'overrides.h'])
              for path in sorted((bear / 'src/int').glob('*.c'))]
    units += [(bear / path, ['-I', bear / 'inc', '-I', bear / 'src', '-include', kstuff / 'overrides.h'])
              for path in ('src/rsa/rsa_i62_pub.c', 'src/codec/ccopy.c')]
    units.append((kstuff / 'isa_l_crypto_ps5_minimal.c', ['-DNO_COMPAT_ISAL_CRYPTO_API_2_24', '-DSAFE_PARAM']))
    objects = []
    tasks = []
    for index, (path, flags) in enumerate(units):
        obj = output / 'objects' / (str(index) + '-' + path.stem + '.o')
        objects.append(obj)
        tasks.append(('compile-' + str(index), [tools['clang'], *common, *flags, '-c', path, '-o', obj]))
    try:
        # Independent compilation only. Link, verification and publication remain sequential.
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            list(pool.map(lambda task: run(*task), tasks))
        asm_sources = ('aes/keyexp_128.asm', 'aes/cbc_dec_128_x8_avx.asm',
                       'aes/XTS_AES_128_enc_expanded_key_avx.asm', 'aes/XTS_AES_128_dec_expanded_key_avx.asm',
                       'sha256_mb/sha256_ni_x1.asm')
        for index, path in enumerate([isa / name for name in asm_sources] + [kstuff / 'isa_l_crypto_ps5_sha256_zen2.asm']):
            obj = output / 'objects' / ('isa-' + str(index) + '.o')
            run('assemble-isa-' + str(index), [tools['nasm'], '-f', 'elf64', '-D', 'SAFE_DATA',
                *[arg for folder in ('', 'include', 'aes', 'sha256_mb', 'intel-ipsec-mb/lib')
                  for arg in ('-I', str(isa / folder) + '/')], path, '-o', obj])
            objects.append(obj)
        run('assemble-crt', [tools['yasm'], '-f', 'elf64', uelf / 'crt.asm', '-o', output / 'objects/crt.o'])
        link = [tools['clang'], '-shared', '-nodefaultlibs', '-Wl,-Bsymbolic',
                '-Wl,--gc-sections', '-Wl,-z,max-page-size=4096', '-Wl,-e,_start', '-Wl,--build-id=none']
        run('link-uelf', [*link, output / 'objects/crt.o', *objects, '-o', output / 'uelf/uelf'])
        # kelf is a ROP image. Its entry is deliberately in data, not executable text.
        (output / 'structs.inc').write_bytes((kstuff / 'structs-ps5.inc').read_bytes())
        run('assemble-kelf', [tools['yasm'], '-I', str(output) + '/', '-f', 'elf64',
                              kstuff / 'kelf.asm', '-o', output / 'objects/kelf.o'])
        # The unchanged upstream kelf is a ROP image containing relocated data
        # in .text. Its custom loader already applies these relocations before
        # use. This link flag grants no live kernel page write capability.
        run('link-kelf', [*link, '-Wl,-z,notext', output / 'objects/kelf.o', '-o', output / 'kelf'])
        allowed = loader_symbols(source)
        audits = {'uelf': audit_elf((output / 'uelf/uelf').read_bytes(), allowed),
                  'kelf': audit_elf((output / 'kelf').read_bytes(), allowed, False)}
        run('strip-uelf', [tools['objcopy'], '--strip-all', '--remove-section=.comment', output / 'uelf/uelf', output / 'uelf/uelf.bin'])
        audit_elf((output / 'uelf/uelf.bin').read_bytes(), allowed)
        # Compile the actual installer, including the embedded final linked images.
        # Do not substitute a dummy bootstrap fixture or the legacy runtime ELF.
        run('compile-installer', [tools['clang'], *common, '-O0', '-DPS5KEK', '-c',
                                  kstuff / 'main.c', '-o', output / 'installer.o'])
        if verify(overlay) != identity:
            raise ValueError('overlay identity changed during build')
        artifacts = {name: {'sha256': digest(output / name), 'size': (output / name).stat().st_size}
                     for name in ('uelf/uelf', 'uelf/uelf.bin', 'kelf', 'installer.o')}
        evidence = {'schema': 1, 'stage': manifest['stage'], 'build_id': identity, 'obs': obs,
                    'llvm_version': version, 'overlay_manifest_sha256': digest(overlay / 'manifest.json'),
                    'builder_sha256': digest(Path(__file__)), 'artifacts': artifacts, 'loader_audits': audits,
                    'resident_linked': True, 'installer_compiled': True, 'installer_linked': False,
                    'console_validated': False, 'tools': {name: {'path': str(path), 'sha256': digest(path)}
                                                        for name, path in tools.items()},
                    'llvm_tools': llvm_tools, 'sdk_makefile_sha256': digest(sdk / 'toolchain/prospero.mk')}
        with (output / 'build-evidence.json').open('x') as handle:
            json.dump(evidence, handle, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        for path in output.rglob('*'):
            if path.is_file():
                os.chmod(path, 0o600)
        (output / 'INCOMPLETE').unlink()
        return evidence
    finally:
        with (output / 'commands.json').open('x') as handle:
            json.dump(sorted(commands, key=lambda item: item['label']), handle, indent=2)
            handle.write('\n')
        # Credentials can appear in linked images, objects and compiler diagnostics.
        for path in output.rglob('*'):
            if path.is_file():
                os.chmod(path, 0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--overlay', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--sdk', type=Path, default=os.environ.get('PS5_PAYLOAD_SDK'))
    parser.add_argument('--obs', type=int, choices=(0, 1), default=0)
    parser.add_argument('--yasm', default=os.environ.get('YASM', 'yasm'))
    parser.add_argument('--nasm', default=os.environ.get('NASM', 'nasm'))
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if args.sdk is None:
        parser.error('set PS5_PAYLOAD_SDK or pass --sdk')
    try:
        result = build(args.overlay, args.output, args.sdk, args.obs, args.yasm, args.nasm, args.jobs)
    except (OSError, ValueError, KeyError, UnicodeError, struct.error, subprocess.SubprocessError) as error:
        parser.exit(2, f'error: {error}\n')
    print(json.dumps({key: result[key] for key in ('build_id', 'resident_linked', 'installer_compiled',
                                                'installer_linked', 'console_validated')}, indent=2))


if __name__ == '__main__':
    main()
