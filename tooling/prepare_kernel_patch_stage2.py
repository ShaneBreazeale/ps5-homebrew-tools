#!/usr/bin/env python3
"""Prepare a private, pinned source overlay for the read-only stage 2 bridge.

Exports selected committed sources to a NEW directory; never edits the source
checkout, installs a resident or contacts a console. Generated configs and ELFs
contain a bearer credential and belong outside Git and release artifacts.
"""
import argparse
import hashlib
import io
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import secrets
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / 'residents/patch/stage2-profile.json'
EXPORT = ('ps5-kstuff/main.c', 'ps5-kstuff/uelf', 'ps5-kstuff/structs-ps5.inc',
          'freebsd-headers', 'prosper0gdb/r0gdb.h', 'prosper0gdb/offsets.h',
          'prosper0gdb/offsets', 'gdb_stub/dbg.h', 'lib/shellcore-imports.h')
HELPERS = ('patch.h', 'probe.h', 'bridge.h', 'stage2.h', 'stage2_loader.h',
           'user_pages.h', 'stage2_client.h', 'stage2_client.c', 'runtime.c')
LINK_EXPORT = ('gdb_stub/trap_state.h', 'ps5-kstuff/Makefile', 'ps5-kstuff/kelf.asm', 'ps5-kstuff/shellcore_hook',
               'ps5-kstuff/shellcore_patches', 'ps5-kstuff/overrides.h',
               'ps5-kstuff/isa_l_crypto_ps5_minimal.c',
               'ps5-kstuff/isa_l_crypto_ps5_sha256_zen2.asm')
LINK_SUBMODULES = ('ps5-kstuff/BearSSL', 'ps5-kstuff/isa-l_crypto')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(data, before, after):
    if data.count(before) != 1:
        raise ValueError('pinned integration marker is absent or ambiguous')
    return data.replace(before, after)


def patch_sources(files):
    """Pure transformation; fixed markers, no regex rewrite or shell scripts."""
    result = dict(files)
    main = result['ps5-kstuff/main.c'].decode()
    # shared_area.h now imports the toolkit's string.h. Keep the installer's
    # private comparator separate from that header's external strcmp prototype.
    main = replace_once(main, 'static int strcmp(', 'static int kp_loader_strcmp(')
    main = replace_once(main, 'if(!strcmp(symbols[i], name))', 'if(!kp_loader_strcmp(symbols[i], name))')
    main = replace_once(main, '!strcmp(symbols[i]+1, name)', '!kp_loader_strcmp(symbols[i]+1, name)')
    marker = 'void notify(const char* s)'
    main = replace_once(main, marker, '#include "uelf/kp_stage2/stage2_loader.h"\n\n' + marker)
    marker = '    uint64_t percpu_ist4[NCPUS];'
    main = replace_once(main, marker,
        '    if (NCPUS != 16 || (r0gdb_get_fw_version() & 0xffff0000u) != 0x13600000u\n'
        '            || kp_s2_prepare()) { notify("stage 2 profile/entropy refusal"); return 1; }\n' + marker)
    marker = '#endif\n    }\n\n    //kmemzero((char*)(IDT+16*1), 16);'
    main = replace_once(main, marker,
        '#endif\n        if (kp_s2_cpu_complete((unsigned)cpu, entry, TSS(cpu))) die();\n'
        '    }\n\n    //kmemzero((char*)(IDT+16*1), 16);')
    marker = '#ifndef DEBUG\n\n    const char *console_type'
    main = replace_once(main, marker,
        '    if (kp_s2_publish(shared_area_kernel + offsetof(struct shared_area_layout, kp_stage2),\n'
        '            kdata_base, r0gdb_get_fw_version(), offsets.kernel_pmap_store)) {\n'
        '        notify("stage 2 publication refused; resident state requires inspection"); return 1;\n'
        '    }\n' + marker)
    result['ps5-kstuff/main.c'] = main.encode()
    shared = result['ps5-kstuff/uelf/shared_area.h'].decode()
    shared = replace_once(shared, '#include <stdint.h>', '#include <stdint.h>\n#include "kp_stage2/stage2.h"')
    shared = replace_once(shared, '    struct kstuff_msg_log msg_log;\n#endif\n};',
        '    struct kstuff_msg_log msg_log;\n#endif\n    struct kp_stage2_store kp_stage2;\n};')
    shared = replace_once(shared, '== 14064, "unexpected shared_area size"', '== 14240, "unexpected shared_area size"')
    shared = replace_once(shared, '== 7888, "unexpected non-OBS shared_area size"', '== 8064, "unexpected non-OBS shared_area size"')
    result['ps5-kstuff/uelf/shared_area.h'] = shared.encode()
    kekcall = result['ps5-kstuff/uelf/kekcall.c'].decode()
    marker = 'int handle_kekcall(uint64_t* regs, uint64_t* args, uint32_t nr)\n{'
    kekcall = replace_once(kekcall, marker,
        '#include "kp_stage2/bridge.h"\n'
        'int kp_stage2_handle(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);\n\n' + marker + '\n'
        '    if (nr == KP_BRIDGE_SELECTOR) {\n'
        '        int error = kp_stage2_handle(args[RDI], args[RSI], args[RDX], args[R8], args[R9]);\n'
        '        if (!error) args[RAX] = 0;\n'
        '        return error;\n'
        '    }')
    result['ps5-kstuff/uelf/kekcall.c'] = kekcall.encode()
    return result



STAGE3_HELPERS = ('stage3.h', 'stage3_bridge.h', 'stage3_loader.h', 'stage3_client.h', 'stage3_client.c')


def patch_stage3(files):
    result = dict(files)
    main = result['ps5-kstuff/main.c'].decode()
    main = replace_once(main, '"uelf/kp_stage2/stage2_loader.h"', '"uelf/kp_stage2/stage3_loader.h"')
    main = replace_once(main, 'if (kp_s2_publish(', 'if (kp_s3_publish(')
    result['ps5-kstuff/main.c'] = main.encode()
    shared = result['ps5-kstuff/uelf/shared_area.h'].decode()
    shared = replace_once(shared, '#include "kp_stage2/stage2.h"',
                          '#define KP_STAGE3_ENABLED 1\n#include "kp_stage2/stage3.h"')
    shared = replace_once(shared, '    struct kp_stage2_store kp_stage2;',
                          '    struct kp_stage2_store kp_stage2;\n    struct kp_stage3_store kp_stage3;')
    shared = replace_once(shared, 'SHARED_AREA_SIZE = 16384', 'SHARED_AREA_SIZE = 24576')
    shared = replace_once(shared, 'SHARED_AREA_SIZE = 8192', 'SHARED_AREA_SIZE = 16384')
    shared = replace_once(shared, '== 14240, "unexpected shared_area size"',
                          '== 14240 + sizeof(struct kp_stage3_store), "unexpected shared_area size"')
    shared = replace_once(shared, '== 8064, "unexpected non-OBS shared_area size"',
                          '== 8064 + sizeof(struct kp_stage3_store), "unexpected non-OBS shared_area size"')
    result['ps5-kstuff/uelf/shared_area.h'] = shared.encode()
    dispatch = result['ps5-kstuff/uelf/kekcall.c'].decode()
    marker = '    if (nr == KP_BRIDGE_SELECTOR) {'
    dispatch = replace_once(dispatch, marker,
        '    if (nr == KP_STAGE3_QUERY_SELECTOR || nr == KP_STAGE3_EXERCISE_SELECTOR) {\n'
        '        int error = kp_stage3_handle(nr,args[RDI],args[RSI],args[RDX],args[R8],args[R9]);\n'
        '        if (!error) args[RAX] = 0;\n        return error;\n    }\n' + marker)
    marker = 'int kp_stage2_handle(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);'
    dispatch = replace_once(dispatch, marker, marker + '\n'
        'int kp_stage3_handle(uint32_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);')
    result['ps5-kstuff/uelf/kekcall.c'] = dispatch.encode()
    return result


def prepare(source, output, profile, stage=2, link_inputs=False):
    if stage not in (2, 3):
        raise ValueError("unsupported integration stage")
    source, output = Path(source).resolve(), Path(output).absolute()
    if output.exists():
        raise ValueError('output already exists')
    if profile.get('schema') != 1 or not isinstance(profile.get('files'), dict):
        raise ValueError('invalid source profile')
    commit = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != profile['commit']:
        raise ValueError('source HEAD differs from the pinned profile')
    selected = {}
    for name, expected in profile['files'].items():
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('unsafe profile path')
        committed = subprocess.check_output(['git', '-C', str(source), 'show', commit + ':' + name])
        if sha(committed) != expected or sha((source / name).read_bytes()) != expected:
            raise ValueError(f'changed/unreviewed integration source: {name}')
        selected[name] = committed
    transformed = patch_sources(selected)
    if stage == 3:
        transformed = patch_stage3(transformed)
    # Export committed inputs only; unrelated dirty research files/captures stay put.
    archive = subprocess.check_output(['git', '-C', str(source), 'archive', commit,
                                       *EXPORT, *(LINK_EXPORT if link_inputs else ())])
    archives = [archive]
    submodules = {}
    if link_inputs:
        for name in LINK_SUBMODULES:
            entry = subprocess.check_output(['git', '-C', str(source), 'ls-tree', commit, name], text=True).split()
            if len(entry) != 4 or entry[:2] != ['160000', 'commit'] or entry[3] != name:
                raise ValueError('missing pinned link dependency')
            pin = entry[2]
            checkout = source / name
            head = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
            if head != pin:
                raise ValueError('link dependency HEAD differs from the committed gitlink')
            # Export committed inputs only; no prebuilt archives or dirty files.
            archives.append(subprocess.check_output(['git', '-C', str(checkout), 'archive',
                                                      '--prefix=' + name + '/', pin]))
            submodules[name] = pin
    output.mkdir(mode=0o700, parents=False)
    os.chmod(output, 0o700)
    destination = output / 'source'
    try:
        links, regular = [], set()
        for archive in archives:
            with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
              for member in tar:
                  path = PurePosixPath(member.name)
                  if path.is_absolute() or '..' in path.parts or (not member.isdir() and not member.isfile() and not member.issym()):
                      raise ValueError('source archive contains an unsupported path/type')
                  target = destination / str(path)
                  if member.issym():
                      normalized = posixpath.normpath(posixpath.join(str(path.parent), member.linkname))
                      if member.linkname.startswith('/') or normalized.startswith('../') or normalized == '..':
                          raise ValueError('unsafe source symlink')
                      links.append((target, member.linkname, normalized))
                  elif member.isdir():
                      target.mkdir(parents=True, exist_ok=True)
                  else:
                      target.parent.mkdir(parents=True, exist_ok=True)
                      target.write_bytes(tar.extractfile(member).read())
                      regular.add(str(path))
        for target, link, normalized in links:
            if normalized not in regular:
                raise ValueError('source symlink must point directly to an exported regular file')
            target.symlink_to(link)
        for name, data in transformed.items():
            if name in ('ps5-kstuff/main.c', 'ps5-kstuff/uelf/kekcall.c', 'ps5-kstuff/uelf/shared_area.h'):
                (destination / name).write_bytes(data)
        helpers = destination / 'ps5-kstuff/uelf/kp_stage2'
        helpers.mkdir()
        fingerprints = {name: sha(data) for name, data in sorted(transformed.items())}
        if link_inputs:
            # Pin every exported dependency, including headers, assembly and
            # submodules, rather than only the files containing patch markers.
            fingerprints.update({str(path.relative_to(destination)): sha(path.read_bytes())
                                 for path in sorted(destination.rglob('*')) if path.is_file()})
        for name in HELPERS + (STAGE3_HELPERS if stage == 3 else ()):
            data = (ROOT / 'residents/patch' / name).read_bytes()
            (helpers / name).write_bytes(data)
            fingerprints['integration/' + name] = sha(data)
        bridge = (ROOT / 'residents/patch/kstuff_stage2.c').read_bytes()
        (destination / 'ps5-kstuff/uelf/kp_stage2_bridge.c').write_bytes(bridge)
        fingerprints['integration/kstuff_stage2.c'] = sha(bridge)
        token = secrets.token_bytes(32)
        identity_inputs = {'stage': stage, 'profile': profile, 'sources': fingerprints, 'credential_sha256': sha(token),
                           'generator_sha256': sha(Path(__file__).read_bytes())}
        if link_inputs:
            identity_inputs['link_inputs'] = {'submodules': submodules,
                'builder_sha256': sha((ROOT / 'tooling/build_kernel_patch_resident.py').read_bytes())}
        build = hashlib.sha256(json.dumps(identity_inputs, sort_keys=True, separators=(',', ':')).encode()).digest()
        def array(data):
            return '{' + ','.join(f'0x{value:02x}' for value in data) + '}'
        config = ('/* PRIVATE generated credential: keep this overlay and linked ELFs out of Git. */\n'
                  '#ifndef KPS2_CONFIG_H\n#define KPS2_CONFIG_H\n'
                  '#define KPS2_BUILD_BYTES ' + array(build) + '\n'
                  '#define KPS2_TOKEN_BYTES ' + array(token) + '\n#endif\n')
        config_path = helpers / 'kp_stage2_config.h'
        config_path.write_text(config)
        os.chmod(config_path, 0o600)
        # The SDK client and resident compile from the same private config path.
        (output / 'client-config').mkdir(mode=0o700)
        client_config = output / 'client-config/kp_stage2_config.h'
        client_config.write_text(config)
        os.chmod(client_config, 0o600)
        inc = destination / 'ps5-kstuff/structs-ps5.inc'
        (inc.parent / 'structs.h').write_text(''.join('#' + line[1:] if line.startswith('%') else line
                                                   for line in inc.read_text().splitlines(keepends=True)))
        manifest = {'schema': 1, 'profile': profile['id'], 'source_commit': commit,
                    'build_id': build.hex(), 'identity_inputs': identity_inputs,
                    'stage': stage, 'inspection_only': stage == 2, 'console_validated': False,
                    'source_hashes': fingerprints, 'config_sha256': sha(config.encode())}
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        return manifest
    except Exception:
        # Keep partial evidence for inspection; never retry/overwrite it in place.
        (output / 'INCOMPLETE').write_text('Preparation did not complete. Use a fresh directory after resolving the error.\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=int, choices=(2, 3), default=2)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', type=Path, default=PROFILE)
    parser.add_argument('--link-inputs', action='store_true',
                        help='include pinned resident link dependencies from initialized submodules')
    args = parser.parse_args()
    try:
        manifest = prepare(args.source, args.output, json.loads(args.profile.read_text()), args.stage, args.link_inputs)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(2, f'error: {error}\n')
    print(json.dumps({'overlay': str(args.output.absolute()), 'build_id': manifest['build_id'],
                      'stage': args.stage, 'inspection_only': args.stage == 2, 'console_validated': False}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
