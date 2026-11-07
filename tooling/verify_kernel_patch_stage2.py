#!/usr/bin/env python3
"""Verify private overlay source/config pins before compilation; prints no secrets."""
import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(overlay, stage=None):
    overlay = Path(overlay).resolve()
    if (overlay / 'INCOMPLETE').exists():
        raise ValueError('overlay preparation is incomplete')
    manifest = json.loads((overlay / 'manifest.json').read_text())
    if manifest.get('schema') != 1 or manifest.get('stage') not in (2,3) or manifest.get('inspection_only') is not (manifest.get('stage') == 2):
        raise ValueError('invalid overlay manifest')
    if stage is not None and manifest['stage'] != stage:
        raise ValueError('overlay integration stage mismatch')
    inputs = manifest['identity_inputs']
    if 'link_inputs' in inputs:
        builder = ROOT / 'tooling/build_kernel_patch_resident.py'
        if inputs['link_inputs']['builder_sha256'] != hashlib.sha256(builder.read_bytes()).hexdigest():
            raise ValueError('resident builder changed; prepare a fresh overlay')
    if inputs.get('stage') != manifest['stage']:
        raise ValueError('manifest stage differs from pinned identity inputs')
    if inputs['generator_sha256'] != hashlib.sha256((ROOT / 'tooling/prepare_kernel_patch_stage2.py').read_bytes()).hexdigest():
        raise ValueError('overlay generator changed; prepare a fresh overlay')
    for name, digest in inputs['sources'].items():
        if name.startswith('integration/'):
            relative = name.removeprefix('integration/')
            local = ROOT / 'residents/patch' / relative
            exported = overlay / 'source/ps5-kstuff/uelf/kp_stage2' / relative
            if relative == 'kstuff_stage2.c':
                exported = overlay / 'source/ps5-kstuff/uelf/kp_stage2_bridge.c'
            if hashlib.sha256(local.read_bytes()).hexdigest() != digest:
                raise ValueError('integration source changed; prepare a fresh overlay')
        else:
            exported = overlay / 'source' / name
            # The Makefile is a pin, not an exported installer build input.
            if name == 'ps5-kstuff/Makefile' and not exported.exists():
                continue
        if hashlib.sha256(exported.read_bytes()).hexdigest() != digest:
            raise ValueError('overlay source differs from its manifest')
    config = overlay / 'client-config/kp_stage2_config.h'
    resident = overlay / 'source/ps5-kstuff/uelf/kp_stage2/kp_stage2_config.h'
    if config.read_bytes() != resident.read_bytes() or hashlib.sha256(config.read_bytes()).hexdigest() != manifest['config_sha256']:
        raise ValueError('client/resident config mismatch')
    identity = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if identity != manifest['build_id']:
        raise ValueError('overlay build identity mismatch')
    def macro(name):
        matches = re.findall(r'^#define ' + name + r' \{((?:0x[0-9a-f]{2},){31}0x[0-9a-f]{2})\}$', config.read_text(), re.M)
        if len(matches) != 1:
            raise ValueError('invalid generated credential config')
        return bytes(int(part, 16) for part in matches[0].split(','))
    if macro('KPS2_BUILD_BYTES').hex() != identity or hashlib.sha256(macro('KPS2_TOKEN_BYTES')).hexdigest() != inputs['credential_sha256']:
        raise ValueError('credential/build config does not match the pinned inputs')

    if 'link_inputs' in inputs:
        # New/unpinned translation units and headers must not enter a link via
        # globbing or include lookup. Generated config/structs are checked here.
        expected = {name for name in inputs['sources'] if not name.startswith('integration/')}
        for name in inputs['sources']:
            if name.startswith('integration/'):
                relative = name.removeprefix('integration/')
                expected.add('ps5-kstuff/uelf/' + ('kp_stage2_bridge.c' if relative == 'kstuff_stage2.c'
                             else 'kp_stage2/' + relative))
        expected.update(('ps5-kstuff/structs.h', 'ps5-kstuff/uelf/kp_stage2/kp_stage2_config.h'))
        actual = {str(path.relative_to(overlay / 'source')) for path in (overlay / 'source').rglob('*')
                  if path.is_file() or path.is_symlink()}
        if actual != expected:
            raise ValueError('unpinned or missing resident link input')
        inc = (overlay / 'source/ps5-kstuff/structs-ps5.inc').read_text()
        generated = ''.join('#' + line[1:] if line.startswith('%') else line
                            for line in inc.splitlines(keepends=True))
        if (overlay / 'source/ps5-kstuff/structs.h').read_text() != generated:
            raise ValueError('generated structs header differs from pinned source')

    return identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=int, choices=(2,3))
    parser.add_argument('--overlay', required=True, type=Path)
    args = parser.parse_args()
    try:
        identity = verify(args.overlay, args.stage)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f'error: {error}\n')
    print('Verified pinned overlay build ' + identity)


if __name__ == '__main__':
    main()
