#!/usr/bin/env python3
"""Resolve explicit kernel anchors against a hash-checked raw dump; never connects."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from analysis_common import integer

DEFAULT_PROFILE = Path(__file__).resolve().parents[1] / 'docs/debugger/profiles/retail-13.60-pro.json'
U64 = 1 << 64


def kernel_pointer(value):
    return 0xffff800000000000 <= value < U64


def load_profile(path):
    profile = json.loads(Path(path).read_text())
    if not isinstance(profile, dict) or type(profile.get('schema')) is not int or profile['schema'] != 1:
        raise ValueError('unsupported profile schema')
    if not re.fullmatch(r'[a-zA-Z0-9.-]{1,80}', profile['id']):
        raise ValueError('invalid profile ID')
    size = integer(profile['dump_size'])
    if not 0 < size <= 64 * 1024 * 1024 or not re.fullmatch(r'[0-9a-f]{64}', profile['dump_sha256']):
        raise ValueError('invalid dump size or SHA-256')
    anchors = profile['anchors']
    if not isinstance(anchors, dict) or integer(anchors['text']) != 0 or integer(anchors['data']) != size:
        raise ValueError('profile must map a raw text dump ending at the data anchor')
    for name, value in anchors.items():
        if not re.fullmatch(r'[a-zA-Z0-9-]+', name) or not 0 <= integer(value) <= size:
            raise ValueError('invalid anchor')
    for key in ('firmware_mask', 'firmware', 'soc_id'):
        if not 0 <= integer(profile[key]) < 1 << 32:
            raise ValueError('invalid firmware/model field')
    if not isinstance(profile['sites'], dict) or not profile['sites']:
        raise ValueError('profile requires instruction sites')
    for site in profile['sites'].values():
        signature = bytes.fromhex(site['signature'])
        offset = integer(site['text_offset'])
        if not 0 < len(signature) <= 64 or not 0 <= offset <= size - len(signature):
            raise ValueError('invalid site signature or range')
        if integer(site['instruction_length']) != len(signature):
            raise ValueError('instruction length differs from signature length')
    return profile


def load_probe(path):
    text = Path(path).read_text()
    records = [line[len('KOFFSET_JSON='):] for line in text.splitlines() if line.startswith('KOFFSET_JSON=')]
    if records:
        if len(records) != 1:
            raise ValueError('probe log must contain exactly one observation')
        text = records[0]
    probe = json.loads(text)
    if not isinstance(probe, dict):
        raise ValueError('probe must be an object')
    return probe


def validate_probe(probe, profile):
    if type(probe.get('schema')) is not int or probe['schema'] != 1 or probe.get('profile') != profile['id']:
        raise ValueError('probe schema/profile differs')
    if probe.get('status') != 'site_signature_match' or probe.get('trap_supported') is not False:
        raise ValueError('probe did not complete a read-only site signature match')
    fw, soc = integer(probe['firmware_raw']), integer(probe['soc_id'])
    if not 0 <= fw < 1 << 32 or fw & integer(profile['firmware_mask']) != integer(profile['firmware']) or soc != integer(profile['soc_id']):
        raise ValueError('probe firmware/model differs')
    text, data = integer(probe['kernel_text_va']), integer(probe['kernel_data_va'])
    if not kernel_pointer(text) or not kernel_pointer(data) or text & 4095 or data - text != integer(profile['anchors']['data']):
        raise ValueError('invalid probe base layout')
    offset, address = integer(probe['text_offset']), integer(probe['address'])
    signature = bytes.fromhex(probe['observed'])
    sites = [site for site in profile['sites'].values() if integer(site['text_offset']) == offset]
    if len(sites) != 1 or address != text + offset or not kernel_pointer(address):
        raise ValueError('probe address is inconsistent with profile and bases')
    if signature != bytes.fromhex(sites[0]['signature']) or integer(probe['bytes_read']) != len(signature):
        raise ValueError('probe bytes differ from the checked site')
    if integer(probe['pid']) <= 1 or integer(probe['observed_at_unix']) <= 0:
        raise ValueError('probe lacks an observation identity/time')
    return text


def plan(dump, profile, anchor, offset, probe=None):
    size = integer(profile['dump_size'])
    if len(dump) != size or hashlib.sha256(dump).hexdigest() != profile['dump_sha256']:
        raise ValueError('raw dump size/SHA-256 differs from profile')
    if anchor not in profile['anchors']:
        raise ValueError(f'unknown anchor {anchor!r}')
    offset = integer(offset)
    text_offset = integer(profile['anchors'][anchor]) + offset
    if not 0 <= text_offset < len(dump):
        raise ValueError('requested offset is outside captured text')
    known = None
    for name, site in profile['sites'].items():
        start, signature = integer(site['text_offset']), bytes.fromhex(site['signature'])
        if dump[start:start+len(signature)] != signature:
            raise ValueError(f'profile signature mismatch: {name}')
        if start == text_offset:
            known = {'name': name, **site}
    report = {
        'schema': 1, 'backend': 'kernel-offset-inspection', 'profile': profile['id'],
        'dump_sha256': profile['dump_sha256'], 'anchor': anchor, 'offset': hex(offset),
        'text_offset': hex(text_offset), 'data_offset': hex(text_offset - integer(profile['anchors']['data'])),
        'bytes': dump[text_offset:text_offset+32].hex(),
        'known_instruction': known, 'trap_supported': False,
        'runtime_observation': None,
        'limitations': ['No trap, step, resume or kernel writes are implemented.',
                        'A supplied probe is a dated observation; this tool does not check console readiness.',
                        'A site signature does not attest the whole running kernel or trap ownership.']
    }
    if probe is not None:
        text = validate_probe(probe, profile)
        address = text + text_offset
        if not kernel_pointer(address):
            raise ValueError('relocated address overflow')
        report['runtime_observation'] = {
            'address': hex(address), 'kernel_text_va': hex(text),
            'observed_at_unix': integer(probe['observed_at_unix']), 'probe_pid': integer(probe['pid']),
            'target_bytes_observed': text_offset == integer(probe['text_offset']),
            'whole_kernel_identity_verified': False
        }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, default=DEFAULT_PROFILE)
    parser.add_argument('--dump', type=Path, required=True, help='raw kernel text, not a wrapped ELF')
    parser.add_argument('--anchor', required=True, help='explicit profile anchor: text, data or exec')
    parser.add_argument('--offset', required=True, type=integer, help='signed offset; use --offset=-0x9303ee for a negative value')
    parser.add_argument('--probe', type=Path, help='one JSON observation or a sender log with one KOFFSET_JSON record')
    args = parser.parse_args()
    try:
        profile = load_profile(args.profile)
        if args.dump.stat().st_size != integer(profile['dump_size']):
            raise ValueError('raw dump size differs from profile')
        report = plan(args.dump.read_bytes(), profile, args.anchor, args.offset,
                      load_probe(args.probe) if args.probe else None)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        parser.exit(2, f'error: {error}\n')
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
