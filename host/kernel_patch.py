#!/usr/bin/env python3
"""Plan kernel patches, encode offline requests and simulate the portable C service.

No network connections or console access. Saved identities do not prove readiness.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES, MAX_PATCHES, MAX_IMAGE = 64, 16, 64 * 1024 * 1024
U64 = 1 << 64
KINDS = {'test_data': 1, 'data': 2, 'code': 3}
ANCHORS = {'text': 1, 'data': 2, 'resident': 3}
OPERATIONS = {'verify': 1, 'apply': 2, 'exercise': 3, 'revert': 4}
STATUS = ('ok', 'invalid', 'sequence', 'stale', 'unsupported', 'policy', 'busy',
          'poisoned', 'acquire', 'mapping', 'read', 'mismatch', 'journal', 'write',
          'verify_failed', 'restore', 'release', 'address')
STATES = ('unchanged', 'committed', 'restored', 'unknown')
FLAGS = ('preimage_valid', 'write_attempted', 'observed_valid', 'applied_verified',
         'restore_attempted', 'final_valid', 'restored_verified', 'lease_finished',
         'prepare_saved', 'outcome_saved', 'complete_saved', 'engine_poisoned')
FAULTS = ('none', 'original-mismatch', 'partial-write', 'write-error', 'readback-mismatch',
          'restore-failure', 'stale-before', 'stale-after', 'prepare-journal',
          'outcome-journal', 'complete-journal', 'mapping-refused', 'short-read',
          'read-error', 'acquire-error', 'release-error')
IDENTITY = struct.Struct('<6I4Q16s32s')
REQUEST = struct.Struct('<4I2Q16s32s32s2Iq64s64s64s')
RESULT = struct.Struct('<6I2Q4i64s64s64s')
PROBE_REQUEST = struct.Struct('<4I16s32s')
PROBE_REPLY_SIZE = 720
assert (IDENTITY.size, REQUEST.size, RESULT.size) == (104, 320, 248)


def keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(f'{label} requires exactly: {", ".join(expected)}')


def integer(value, minimum, maximum, label):
    if type(value) is int:
        result = value
    elif isinstance(value, str) and re.fullmatch(r'-?(?:0x[0-9a-fA-F]+|[0-9]+)', value):
        result = int(value, 16 if '0x' in value else 10)
    else:
        raise ValueError(f'{label} must be an integer or decimal/hex string')
    if not minimum <= result <= maximum:
        raise ValueError(f'{label} outside [{minimum}, {maximum}]')
    return result


def hexbytes(value, length, label, nonzero=False):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{' + str(length * 2) + r'}', value):
        raise ValueError(f'{label} requires {length} bytes of lowercase hex')
    result = bytes.fromhex(value)
    if nonzero and not any(result):
        raise ValueError(f'{label} cannot be all zero')
    return result


def identifier(value, label):
    if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}', value):
        raise ValueError(f'invalid {label}')
    return value


def strict_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f'duplicate JSON key: {key}')
            result[key] = value
        return result
    path = Path(path)
    with path.open('rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('JSON input exceeds 1 MiB')
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda v: (_ for _ in ()).throw(ValueError(f'invalid JSON constant: {v}')))


def validate_manifest(manifest, dump):
    keys(manifest, ('schema', 'id', 'firmware', 'soc', 'image', 'patches'), 'manifest')
    if type(manifest['schema']) is not int or manifest['schema'] != 1:
        raise ValueError('unsupported manifest schema')
    identifier(manifest['id'], 'manifest ID')
    integer(manifest['firmware'], 0, (1 << 32) - 1, 'firmware')
    integer(manifest['soc'], 0, (1 << 32) - 1, 'soc')
    image = manifest['image']
    keys(image, ('sha256', 'size', 'anchors'), 'image')
    size = integer(image['size'], 1, MAX_IMAGE, 'image size')
    hexbytes(image['sha256'], 32, 'image SHA-256', True)
    if len(dump) != size or hashlib.sha256(dump).hexdigest() != image['sha256']:
        raise ValueError('image size/SHA-256 mismatch')
    anchors = image['anchors']
    if not isinstance(anchors, dict) or not anchors or not set(anchors) <= set(ANCHORS):
        raise ValueError('anchors must explicitly map text, data or resident to capture-relative offsets')
    offsets = {name: integer(value, -MAX_IMAGE, MAX_IMAGE, 'anchor offset') for name, value in anchors.items()}
    patches = manifest['patches']
    if not isinstance(patches, list) or not 1 <= len(patches) <= MAX_PATCHES:
        raise ValueError('manifest requires 1–16 patches')
    seen, intervals, rows = set(), [], []
    for patch in patches:
        keys(patch, ('id', 'kind', 'anchor', 'offset', 'alignment', 'expected', 'replacement', 'undo', 'review'), 'patch')
        name = identifier(patch['id'], 'patch ID')
        if name in seen:
            raise ValueError('duplicate patch ID')
        seen.add(name)
        if patch['kind'] not in KINDS or patch['anchor'] not in offsets:
            raise ValueError('unknown kind or undeclared anchor')
        if patch['kind'] == 'test_data' and patch['anchor'] != 'resident':
            raise ValueError('test_data must use the resident anchor')
        offset = integer(patch['offset'], -(1 << 63), (1 << 63) - 1, 'patch offset')
        alignment = integer(patch['alignment'], 1, MAX_BYTES, 'alignment')
        if alignment & (alignment - 1):
            raise ValueError('alignment must be a power of two')
        if not isinstance(patch['expected'], str) or not 2 <= len(patch['expected']) <= MAX_BYTES * 2:
            raise ValueError('expected bytes must contain 1–64 bytes')
        length = len(patch['expected']) // 2
        expected = hexbytes(patch['expected'], length, 'expected bytes')
        replacement = hexbytes(patch['replacement'], length, 'replacement bytes')
        undo = hexbytes(patch['undo'], length, 'undo bytes')
        if undo != expected or replacement == expected:
            raise ValueError('undo must equal expected bytes; replacement must change bytes')
        review = patch['review']
        if not isinstance(review, str) or not 1 <= len(review.strip()) <= 2000:
            raise ValueError('each operation requires a review note (not automatic certification)')
        start = offsets[patch['anchor']] + offset
        if not 0 <= start <= size - length:
            raise ValueError('patch outside captured image')
        if any(start < end and old < start + length for old, end in intervals):
            raise ValueError('overlapping patches or aliased anchors')
        intervals.append((start, start + length))
        if dump[start:start + length] != expected:
            raise ValueError(f'original bytes differ for {name}')
        rows.append({'id': name, 'kind': patch['kind'], 'anchor': patch['anchor'],
                     'offset': hex(offset), 'capture_offset': hex(start), 'length': length,
                     'alignment': alignment, 'expected': expected.hex(),
                     'replacement': replacement.hex(), 'undo': undo.hex(), 'review': review})
    return rows


def plan(manifest, dump):
    rows = validate_manifest(manifest, dump)
    canonical = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return {'schema': 1, 'type': 'kernel-patch-plan', 'manifest_id': manifest['id'],
            'manifest_sha256': hashlib.sha256(canonical).hexdigest(),
            'image_sha256': manifest['image']['sha256'], 'patches': rows,
            'live_capability_verified': False, 'whole_kernel_identity_verified': False,
            'limitations': ['Offline planning only; no console connection or resident authorization.',
                            'Capture bytes and review text do not prove instruction or runtime semantics.',
                            'Code mutation requires a hardware adapter and is currently refused by the C service.']}



def policy_header(manifest, dump):
    """Compile an independently reviewed manifest into resident build input.

    This is not a loader: generated policy must be reviewed and compiled into
    the pinned resident. The runtime service never trusts a client policy.
    """
    report = plan(manifest, dump)
    def array(data):
        return '{' + ','.join('0x' + data[i:i+2] for i in range(0, len(data), 2)) + '}'
    lines = ['/* Generated offline policy. Review before compiling into a resident. */',
             '#ifndef KP_REVIEWED_POLICY_H', '#define KP_REVIEWED_POLICY_H',
             '#include "residents/patch/patch.h"',
             '#define KP_MANIFEST_SHA256 "' + report['manifest_sha256'] + '"',
             '#define KP_REVIEWED_FIRMWARE UINT32_C(' + str(integer(manifest['firmware'], 0, (1 << 32)-1, 'firmware')) + ')',
             '#define KP_REVIEWED_SOC UINT32_C(' + str(integer(manifest['soc'], 0, (1 << 32)-1, 'soc')) + ')',
             'static const struct kp_policy kp_reviewed_policies[] = {']
    for row in report['patches']:
        offset = int(row['offset'], 16)
        literal = ('(-INT64_C(' + str(-offset) + '))') if offset < 0 else ('INT64_C(' + str(offset) + ')')
        lines += ['    { .kind = ' + str(KINDS[row['kind']]) + ', .anchor = ' + str(ANCHORS[row['anchor']]) + ',',
                  '      .length = ' + str(row['length']) + ', .alignment = ' + str(row['alignment']) + ',',
                  '      .offset = ' + literal + ', .image = ' + array(manifest['image']['sha256']) + ',',
                  '      .expected = ' + array(row['expected']) + ', .replacement = ' + array(row['replacement']) + ' },']
    lines += ['};', '#define KP_REVIEWED_POLICY_COUNT (sizeof(kp_reviewed_policies) / sizeof(kp_reviewed_policies[0]))', '#endif', '']
    return '\n'.join(lines).encode()


def encode_identity(identity):
    keys(identity, ('schema', 'firmware', 'soc', 'capabilities', 'generation',
                    'text_base', 'data_base', 'resident_base', 'session', 'build'), 'identity')
    if type(identity['schema']) is not int or identity['schema'] != 1:
        raise ValueError('unsupported identity schema')
    firmware = integer(identity['firmware'], 0, (1 << 32) - 1, 'firmware')
    soc = integer(identity['soc'], 0, (1 << 32) - 1, 'soc')
    caps = integer(identity['capabilities'], 1, 7, 'capabilities')
    if not caps & 1:
        raise ValueError('identity requires inspection capability')
    generation = integer(identity['generation'], 1, U64 - 1, 'generation')
    bases = [integer(identity[key], 0xffff800000000000, U64 - 1, key)
             for key in ('text_base', 'data_base', 'resident_base')]
    if bases[0] & 4095 or bases[1] & 4095 or bases[0] >= bases[1]:
        raise ValueError('invalid kernel base layout/alignment')
    return IDENTITY.pack(1, IDENTITY.size, firmware, soc, caps, 0, generation, *bases,
                         hexbytes(identity['session'], 16, 'session', True),
                         hexbytes(identity['build'], 32, 'build', True))


def encode_request(manifest, dump, identity, patch_id, sequence, operation):
    rows = validate_manifest(manifest, dump)
    encode_identity(identity)
    if (integer(manifest['firmware'], 0, (1 << 32) - 1, 'firmware') !=
            integer(identity['firmware'], 0, (1 << 32) - 1, 'firmware') or
            integer(manifest['soc'], 0, (1 << 32) - 1, 'soc') !=
            integer(identity['soc'], 0, (1 << 32) - 1, 'soc')):
        raise ValueError('manifest firmware/model differs from identity')
    capture_bases = {
        integer(identity[name + '_base'], 0xffff800000000000, U64 - 1, name + ' base')
        - integer(value, -MAX_IMAGE, MAX_IMAGE, 'anchor offset')
        for name, value in manifest['image']['anchors'].items()
    }
    if len(capture_bases) != 1 or not 0xffff800000000000 <= next(iter(capture_bases)) <= U64 - len(dump):
        raise ValueError('runtime anchor layout differs from the captured image')
    found = [row for row in rows if row['id'] == patch_id]
    if not found:
        raise ValueError('unknown patch ID')
    row = found[0]
    if operation not in OPERATIONS:
        raise ValueError('unknown operation')
    if operation == 'exercise' and row['kind'] != 'test_data':
        raise ValueError('exercise is confined to resident-owned test data')
    base = integer(identity[row['anchor'] + '_base'], 0xffff800000000000, U64 - 1, 'base')
    address = base + int(row['offset'], 16)
    if not 0xffff800000000000 <= address <= U64 - row['length']:
        raise ValueError('runtime range overflow/nonkernel address')
    if address & (row['alignment'] - 1) or (address & 4095) + row['length'] > 4096:
        raise ValueError('runtime range crosses a page or violates policy alignment')
    return REQUEST.pack(1, REQUEST.size, OPERATIONS[operation], KINDS[row['kind']],
                        integer(sequence, 1, U64 - 1, 'sequence'),
                        integer(identity['generation'], 1, U64 - 1, 'generation'),
                        bytes.fromhex(identity['session']), bytes.fromhex(identity['build']),
                        bytes.fromhex(manifest['image']['sha256']), ANCHORS[row['anchor']],
                        row['length'], int(row['offset'], 16),
                        *(bytes.fromhex(row[key]).ljust(MAX_BYTES, b'\0')
                          for key in ('expected', 'replacement', 'undo')))



def decode_identity(binary):
    if len(binary) != IDENTITY.size:
        raise ValueError('invalid identity size')
    abi, size, firmware, soc, caps, reserved, generation, text, data, resident, session, build = IDENTITY.unpack(binary)
    if abi != 1 or size != IDENTITY.size or reserved:
        raise ValueError('invalid identity ABI/reserved fields')
    result = {'schema': 1, 'firmware': hex(firmware), 'soc': hex(soc), 'capabilities': caps,
              'generation': generation, 'text_base': hex(text), 'data_base': hex(data),
              'resident_base': hex(resident), 'session': session.hex(), 'build': build.hex()}
    encode_identity(result)
    return result


def decode_request(binary):
    """Validate the syntax of a cached command without granting its policy."""
    if len(binary) != REQUEST.size:
        raise ValueError('invalid cached request size')
    (abi, size, operation, kind, sequence, generation, session, build, image,
     anchor, length, offset, expected, replacement, undo) = REQUEST.unpack(binary)
    if (abi != 1 or size != REQUEST.size or operation not in OPERATIONS.values()
            or kind not in KINDS.values() or anchor not in ANCHORS.values()
            or not sequence or not generation or not any(session) or not any(build) or not any(image)
            or not 1 <= length <= MAX_BYTES or (kind == 1 and anchor != 3)):
        raise ValueError('invalid cached request fields')
    if any(expected[length:]) or any(replacement[length:]) or any(undo[length:]):
        raise ValueError('invalid cached request padding')
    if expected != undo or expected == replacement:
        raise ValueError('invalid cached request undo/replacement')
    return {'operation': next(k for k, v in OPERATIONS.items() if v == operation),
            'kind': next(k for k, v in KINDS.items() if v == kind),
            'sequence': sequence, 'generation': generation, 'session': session.hex(),
            'build': build.hex(), 'image_sha256': image.hex(),
            'anchor': next(k for k, v in ANCHORS.items() if v == anchor),
            'length': length, 'offset': hex(offset), 'expected': expected[:length].hex(),
            'replacement': replacement[:length].hex(), 'undo': undo[:length].hex()}


def encode_probe_request(build, challenge=None):
    if challenge is None:
        challenge = secrets.token_bytes(16).hex()
    return PROBE_REQUEST.pack(1, PROBE_REQUEST.size, 1, 0,
                              hexbytes(challenge, 16, 'probe challenge', True),
                              hexbytes(build, 32, 'pinned resident build', True))


def decode_probe_request(binary):
    if len(binary) != PROBE_REQUEST.size:
        raise ValueError('invalid probe request size')
    abi, size, operation, reserved, challenge, build = PROBE_REQUEST.unpack(binary)
    if abi != 1 or size != PROBE_REQUEST.size or operation != 1 or reserved or not any(challenge) or not any(build):
        raise ValueError('invalid probe request')
    return challenge, build


def decode_probe_reply(binary, request):
    challenge, pinned_build = decode_probe_request(request)
    if len(binary) != PROBE_REPLY_SIZE:
        raise ValueError('invalid probe reply size')
    abi, size, status, flags, echoed = struct.unpack_from('<4I16s', binary)
    if abi != 1 or size != PROBE_REPLY_SIZE or status not in (0, 1, 3, 7, 8, 16) or flags & ~3:
        raise ValueError('invalid probe reply header')
    if echoed != challenge:
        raise ValueError('probe challenge mismatch')
    identity_bytes = binary[32:136]
    sequence, applied, poisoned = struct.unpack_from('<Q2I', binary, 136)
    if applied > 0xffff or poisoned not in (0, 1):
        raise ValueError('invalid probe service state')
    identity = decode_identity(identity_bytes) if any(identity_bytes) else None
    if identity is None:
        if status not in (1, 3) or flags or sequence or applied or poisoned or any(binary[152:]):
            raise ValueError('invalid unbound probe refusal')
    elif bytes.fromhex(identity['build']) != pinned_build:
        raise ValueError('probe resident build mismatch')
    checked = bool(flags & 1)
    if checked != (status == 0) or (checked and poisoned):
        raise ValueError('inconsistent probe identity check')
    if status in (7, 16) and not poisoned or status == 3 and identity and not poisoned:
        raise ValueError('probe failure must retain revocation')
    if status in (0, 7, 8, 16) and identity is None:
        raise ValueError('missing pinned probe identity')
    last = None
    if flags & 2:
        if not sequence:
            raise ValueError('cached command requires a sequence')
        cached_request = binary[152:472]
        command = decode_request(cached_request)
        result = decode_result(binary[472:])
        if (command['sequence'] != sequence or result['sequence'] != sequence
                or result['length'] != command['length'] or result['status'] in ('invalid', 'sequence')):
            raise ValueError('cached command/result mismatch')
        if 'engine_poisoned' in result['flags'] and not poisoned:
            raise ValueError('probe cannot clear a cached poisoned state')
        if int(result['address'], 16):
            base = int(identity[command['anchor'] + '_base'], 16)
            address = base + int(command['offset'], 16)
            if int(result['address'], 16) != address or not 0xffff800000000000 <= address <= U64 - command['length']:
                raise ValueError('cached result address mismatch')
        elif any(flag in result['flags'] for flag in ('preimage_valid', 'write_attempted', 'observed_valid', 'final_valid')):
            raise ValueError('cached memory evidence requires a resolved address')
        before = command['replacement'] if command['operation'] == 'revert' else command['expected']
        desired = command['expected'] if command['operation'] == 'revert' else command['replacement']
        if 'write_attempted' in result['flags'] and result['preimage'] != before:
            raise ValueError('cached write preimage differs from the command')
        if 'applied_verified' in result['flags'] and result['observed'] != desired:
            raise ValueError('cached verified bytes differ from the command')
        if 'restored_verified' in result['flags'] and result['final'] != result['preimage']:
            raise ValueError('cached restoration differs from its preimage')
        last = {'request': command, 'request_sha256': hashlib.sha256(cached_request).hexdigest(), 'result': result}
    elif sequence or applied or any(binary[152:]):
        raise ValueError('missing or unexpected cached command')
    return {'schema': 1, 'type': 'kernel-patch-probe', 'status': STATUS[status],
            'adapter_identity_checked': checked, 'present_readiness_verified': False,
            'whole_kernel_identity_verified': False, 'challenge': challenge.hex(),
            'request_sha256': hashlib.sha256(request).hexdigest(),
            'reply_sha256': hashlib.sha256(binary).hexdigest(), 'identity': identity,
            'sequence': sequence, 'applied_mask': hex(applied), 'engine_poisoned': bool(poisoned),
            'last_command': last}


def decode_result(binary):
    if len(binary) != RESULT.size:
        raise ValueError('invalid result size')
    (abi, size, status, state, flags, length, sequence, address, adapter_error,
     restore_error, journal_error, release_error, preimage, observed, final) = RESULT.unpack(binary)
    if abi != 1 or size != RESULT.size or status >= len(STATUS) or state >= len(STATES):
        raise ValueError('invalid result ABI/status/state')
    if flags & ~((1 << len(FLAGS)) - 1) or not 0 <= length <= MAX_BYTES:
        raise ValueError('invalid result flags/length')
    for data, flag in ((preimage, 1), (observed, 4), (final, 32)):
        if any(data[length:]) or (not flags & flag and any(data)):
            raise ValueError('invalid result byte validity/padding')
    if flags & 8 and not flags & 4 or flags & 64 and not flags & 32:
        raise ValueError('inconsistent verification flags')
    if state == 1 and flags & 10 != 10 or state == 2 and flags & 80 != 80:
        raise ValueError('inconsistent result state')
    if flags & 2 and flags & 257 != 257:
        raise ValueError('write requires a saved preimage')
    if flags & 8 and flags & 3 != 3:
        raise ValueError('verified write requires preimage and a write attempt')
    if flags & 64 and flags & 17 != 17:
        raise ValueError('verified restoration requires preimage and a restore attempt')
    if status == 0 and (state == 3 or flags & 2048 or flags & 1152 != 1152):
        raise ValueError('success requires known state, lease completion and saved completion')
    if status == 0 and state in (1, 2) and not flags & 512:
        raise ValueError('successful mutation requires a saved outcome')
    return {'schema': 1, 'type': 'kernel-patch-result', 'status': STATUS[status],
            'state': STATES[state], 'sequence': sequence, 'address': hex(address),
            'length': length, 'flags': [name for bit, name in enumerate(FLAGS) if flags & (1 << bit)],
            'errors': {'adapter': adapter_error, 'restore': restore_error,
                       'journal': journal_error, 'release': release_error},
            'preimage': preimage[:length].hex() if flags & 1 else None,
            'observed': observed[:length].hex() if flags & 4 else None,
            'final': final[:length].hex() if flags & 32 else None}



def decode_stage2_record(record, expected_build):
    hexbytes(expected_build, 32, 'pinned resident build', True)
    keys(record, ('schema', 'pid', 'observed_at_unix', 'firmware', 'soc', 'text_base',
                  'data_base', 'status', 'write_enabled', 'queries'), 'stage 2 record')
    if type(record['schema']) is not int or record['schema'] != 1 or record['write_enabled'] is not False:
        raise ValueError('invalid stage 2 schema/write capability')
    integer(record['pid'], 2, (1 << 31) - 1, 'payload PID')
    integer(record['observed_at_unix'], 1, (1 << 63) - 1, 'observation time')
    firmware = integer(record['firmware'], 0, (1 << 32) - 1, 'firmware')
    soc = integer(record['soc'], 0, (1 << 32) - 1, 'soc')
    text = integer(record['text_base'], 0, U64 - 1, 'text base')
    data = integer(record['data_base'], 0, U64 - 1, 'data base')
    statuses = ('identity_match', 'provider_unavailable', 'invalid_challenge', 'transport_error',
                'invalid_reply', 'resident_refused', 'environment_mismatch', 'identity_changed')
    if record['status'] not in statuses or not isinstance(record['queries'], list) or len(record['queries']) > 2:
        raise ValueError('invalid stage 2 status/query count')
    reports = []
    for query in record['queries']:
        keys(query, ('transport_ok', 'request', 'reply'), 'stage 2 query')
        if type(query['transport_ok']) is not bool:
            raise ValueError('invalid transport result')
        request = hexbytes(query['request'], PROBE_REQUEST.size, 'probe request')
        reply = hexbytes(query['reply'], PROBE_REPLY_SIZE, 'probe reply')
        _, build = decode_probe_request(request)
        if build.hex() != expected_build:
            raise ValueError('query build differs from the independently pinned build')
        item = {'transport_ok': query['transport_ok'], 'request_sha256': hashlib.sha256(request).hexdigest(),
                'reply_sha256': hashlib.sha256(reply).hexdigest(), 'probe': None, 'validation_error': None}
        if query['transport_ok']:
            try:
                item['probe'] = decode_probe_reply(reply, request)
                probe = item['probe']
                if probe['last_command'] is not None or (probe['identity'] and probe['identity']['capabilities'] != 1):
                    raise ValueError('stage 2 must remain inspection-only without mutation history')
            except ValueError as error:
                item['validation_error'] = str(error)
                item['probe'] = None
        reports.append(item)
    matched = False
    if record['status'] == 'identity_match':
        if len(reports) != 2 or any(not q['transport_ok'] or q['validation_error'] or q['probe'] is None for q in reports):
            raise ValueError('claimed identity match lacks two validated exchanges')
        first, second = (q['probe'] for q in reports)
        if (first['status'] != 'ok' or second['status'] != 'ok' or first['challenge'] == second['challenge']
                or first['identity'] != second['identity'] or first['engine_poisoned'] or second['engine_poisoned']):
            raise ValueError('stage 2 identity/challenge changed or was refused')
        identity = first['identity']
        if (integer(identity['firmware'], 0, (1 << 32)-1, 'firmware') != firmware
                or integer(identity['soc'], 0, (1 << 32)-1, 'soc') != soc
                or int(identity['text_base'], 16) != text or int(identity['data_base'], 16) != data
                or firmware & 0xffff0000 != 0x13600000 or soc != 0x840fd0
                or text & 4095 or data - text != 0xcc0000):
            raise ValueError('stage 2 identity differs from the observed firmware/model/bases')
        matched = True
    return {'schema': 1, 'type': 'kernel-patch-stage2-observation', 'client_status': record['status'],
            'adapter_identity_checked': matched, 'present_readiness_verified': False,
            'whole_kernel_identity_verified': False, 'write_enabled': False,
            'expected_build': expected_build, 'pid': integer(record['pid'], 2, (1 << 31)-1, 'PID'),
            'observed_at_unix': integer(record['observed_at_unix'], 1, (1 << 63)-1, 'time'),
            'queries': reports, 'raw_record': record}


def decode_stage3_record(record, expected_build):
    build_pin = hexbytes(expected_build, 32, 'pinned resident build', True)
    keys(record, ('schema', 'pid', 'observed_at_unix', 'firmware', 'soc', 'text_base', 'data_base',
                  'status', 'queries', 'command_attempted', 'command_transport_ok', 'command', 'result'), 'stage 3 record')
    if type(record['schema']) is not int or record['schema'] != 1:
        raise ValueError('invalid stage 3 schema')
    for key in ('command_attempted', 'command_transport_ok'):
        if type(record[key]) is not bool:
            raise ValueError('invalid stage 3 transport flag')
    pid = integer(record['pid'], 2, (1 << 31)-1, 'PID')
    observed = integer(record['observed_at_unix'], 1, (1 << 63)-1, 'time')
    fw = integer(record['firmware'], 0, (1 << 32)-1, 'firmware')
    soc = integer(record['soc'], 0, (1 << 32)-1, 'soc')
    text = integer(record['text_base'], 0, U64-1, 'text base')
    data = integer(record['data_base'], 0, U64-1, 'data base')
    statuses = ('exercise_restored', 'exercise_restored_recovered', 'provider_unavailable', 'environment_mismatch',
                'invalid_challenge', 'transport_error', 'invalid_reply', 'resident_refused', 'history_present',
                'command_failed', 'recovery_unverified', 'query_checked', 'cached_result')
    if record['status'] not in statuses or not isinstance(record['queries'], list) or len(record['queries']) > 3:
        raise ValueError('invalid stage 3 status/query count')
    command = hexbytes(record['command'], REQUEST.size, 'stage 3 command')
    result = hexbytes(record['result'], RESULT.size, 'stage 3 result')
    if not record['command_attempted'] and (any(command) or any(result) or record['command_transport_ok']):
        raise ValueError('unattempted command cannot contain result evidence')
    reports = []
    binaries = []
    for entry in record['queries']:
        keys(entry, ('transport_ok', 'request', 'reply'), 'stage 3 query')
        if type(entry['transport_ok']) is not bool:
            raise ValueError('invalid query transport flag')
        q = hexbytes(entry['request'], PROBE_REQUEST.size, 'probe request')
        r = hexbytes(entry['reply'], PROBE_REPLY_SIZE, 'probe reply')
        challenge, build = decode_probe_request(q)
        if build != build_pin:
            raise ValueError('query differs from independently pinned build')
        probe, error = None, None
        if entry['transport_ok']:
            try:
                probe = decode_probe_reply(r, q)
            except ValueError as exc:
                error = str(exc)
        reports.append({'transport_ok': entry['transport_ok'], 'probe': probe, 'validation_error': error,
                        'challenge': challenge.hex(), 'reply_sha256': hashlib.sha256(r).hexdigest()})
        binaries.append(r)
    success = record['status'] in statuses[:2]
    verified = None
    if success:
        if len(reports) != 3 or not record['command_attempted'] or any(not r['transport_ok'] or r['probe'] is None for r in reports):
            raise ValueError('claimed restoration lacks three validated queries and an attempted command')
        probes = [r['probe'] for r in reports]
        identity = probes[0]['identity']
        if (len({r['challenge'] for r in reports}) != 3 or identity is None
                or any(p['status'] != 'ok' or p['identity'] != identity or p['engine_poisoned'] or p['applied_mask'] != '0x0' for p in probes)
                or identity['capabilities'] != 3 or any(p['last_command'] is not None for p in probes[:2])
                or probes[2]['sequence'] != 1 or probes[2]['last_command'] is None):
            raise ValueError('stage 3 identity/challenge/history mismatch')
        if (fw & 0xffff0000 != 0x13600000 or soc != 0x840fd0 or data-text != 0xcc0000
                or int(identity['firmware'],16) != fw or int(identity['soc'],16) != soc
                or int(identity['text_base'],16) != text or int(identity['data_base'],16) != data):
            raise ValueError('stage 3 environment mismatch')
        before = bytes.fromhex('4b50544553543100') + bytes(56)
        after = bytes.fromhex('4b50544553543200') + bytes(56)
        expected = REQUEST.pack(1, REQUEST.size, 3, 1, 1, identity['generation'], bytes.fromhex(identity['session']),
                                build_pin, build_pin, 3, 8, 0, before, after, before)
        if command != expected or binaries[2][152:472] != expected:
            raise ValueError('stage 3 command differs from the fixed owned-cell exercise')
        cached = binaries[2][472:]
        fields = RESULT.unpack(cached)
        if (fields[:7] != (1, RESULT.size, 0, 2, 2047, 8, 1) or fields[7] != int(identity['resident_base'],16)
                or any(fields[8:12]) or fields[12:] != (before, after, before)):
            raise ValueError('stage 3 restoration/readback/journal evidence is incomplete')
        if record['command_transport_ok']:
            if result != cached or record['status'] != 'exercise_restored':
                raise ValueError('stage 3 direct result differs from cached recovery evidence')
        elif record['status'] != 'exercise_restored_recovered':
            raise ValueError('lost reply requires recovered status')
        verified = decode_result(cached)
    query_checked = record['status'] in ('query_checked', 'cached_result')
    cached_restored = False
    if query_checked:
        if len(reports) != 1 or record['command_attempted'] or not reports[0]['transport_ok'] or reports[0]['probe'] is None:
            raise ValueError('read-only recovery requires one validated query and no command')
        probe = reports[0]['probe']
        identity = probe['identity']
        if (probe['status'] != 'ok' or identity is None or identity['capabilities'] != 3
                or probe['engine_poisoned'] or probe['applied_mask'] != '0x0'
                or fw & 0xffff0000 != 0x13600000 or soc != 0x840fd0 or data-text != 0xcc0000
                or int(identity['firmware'],16) != fw or int(identity['soc'],16) != soc
                or int(identity['text_base'],16) != text or int(identity['data_base'],16) != data):
            raise ValueError('read-only recovery identity/environment mismatch')
        if record['status'] == 'query_checked':
            if probe['sequence'] or probe['last_command'] is not None:
                raise ValueError('history-free query has unexpected history')
        else:
            before = bytes.fromhex('4b50544553543100') + bytes(56)
            after = bytes.fromhex('4b50544553543200') + bytes(56)
            expected = REQUEST.pack(1, REQUEST.size, 3, 1, 1, identity['generation'], bytes.fromhex(identity['session']),
                                    build_pin, build_pin, 3, 8, 0, before, after, before)
            if probe['sequence'] != 1 or binaries[0][152:472] != expected:
                raise ValueError('cached recovery differs from owned-cell policy')
            fields = RESULT.unpack(binaries[0][472:])
            verified = decode_result(binaries[0][472:])
            cached_restored = (fields[:7] == (1, RESULT.size, 0, 2, 2047, 8, 1)
                               and fields[7] == int(identity['resident_base'],16) and not any(fields[8:12])
                               and fields[12:] == (before, after, before))
    return {'schema': 1, 'type': 'kernel-patch-stage3-observation', 'client_status': record['status'],
            'owned_cell_restoration_verified': success or cached_restored, 'query_identity_checked': query_checked,
            'present_readiness_verified': False,
            'whole_kernel_identity_verified': False, 'expected_build': expected_build,
            'pid': pid, 'observed_at_unix': observed, 'queries': reports, 'result': verified, 'raw_record': record}


def load_stage3_log(path):
    return load_stage2_log(path, stage=3)


def load_stage2_log(path, stage=2):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f'duplicate stage {stage} JSON key')
            result[key] = value
        return result
    with Path(path).open('rb') as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError(f'stage {stage} log exceeds 1 MiB')
    prefix = f'KP_STAGE{stage}_JSON='
    records = [line[len(prefix):] for line in data.decode().splitlines() if line.startswith(prefix)]
    if len(records) != 1:
        raise ValueError(f'stage {stage} log requires exactly one {prefix[:-1]} record')
    return json.loads(records[0], object_pairs_hook=pairs)


def save_new(path, data):
    """Exclusive creation: an existing evidence record is never replaced."""
    with Path(path).open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('plan', 'policy', 'encode', 'simulate'):
        command = sub.add_parser(name)
        command.add_argument('--manifest', type=Path, required=True)
        command.add_argument('--dump', type=Path, required=True)
        command.add_argument('--output', type=Path, required=True)
        if name not in ('plan', 'policy'):
            command.add_argument('--identity', type=Path, required=True, help='saved identity; not proof of present readiness')
            command.add_argument('--patch', required=True)
            command.add_argument('--sequence', default='1')
            command.add_argument('--operation', choices=OPERATIONS, default='verify')
        if name == 'simulate':
            command.add_argument('--engine', type=Path, default=ROOT / 'out/host/kernel-patch-sim')
            command.add_argument('--fault', choices=FAULTS, default='none')
    command = sub.add_parser('decode')
    command.add_argument('--result', type=Path, required=True)
    command.add_argument('--output', type=Path, required=True)
    command = sub.add_parser('probe-request', help='create a fresh offline read-only query; submits nothing')
    command.add_argument('--build', required=True, help='independently pinned resident build SHA-256')
    command.add_argument('--output', type=Path, required=True)
    command = sub.add_parser('probe-decode', help='validate a saved reply against its saved query')
    command.add_argument('--request', type=Path, required=True)
    command.add_argument('--reply', type=Path, required=True)
    command.add_argument('--output', type=Path, required=True)
    command = sub.add_parser('stage2-decode', help='validate a saved read-only SDK observation')
    command.add_argument('--log', type=Path, required=True)
    command.add_argument('--build', required=True, help='independently pinned overlay build identity')
    command.add_argument('--output', type=Path, required=True)
    command = sub.add_parser('stage3-decode', help='validate saved owned-cell exercise and restoration evidence')
    command.add_argument('--log', type=Path, required=True)
    command.add_argument('--build', required=True)
    command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError('output already exists')
        if args.command == 'stage3-decode':
            report = decode_stage3_record(load_stage3_log(args.log), args.build)
        elif args.command == 'stage2-decode':
            report = decode_stage2_record(load_stage2_log(args.log), args.build)
        elif args.command == 'probe-request':
            save_new(args.output, encode_probe_request(args.build))
            return 0
        elif args.command == 'probe-decode':
            with args.request.open('rb') as stream:
                request = stream.read(PROBE_REQUEST.size + 1)
            with args.reply.open('rb') as stream:
                report = decode_probe_reply(stream.read(PROBE_REPLY_SIZE + 1), request)
        elif args.command == 'decode':
            with args.result.open('rb') as stream:
                report = decode_result(stream.read(RESULT.size + 1))
        else:
            manifest = strict_json(args.manifest)
            if args.dump.stat().st_size > MAX_IMAGE:
                raise ValueError('image exceeds 64 MiB')
            with args.dump.open('rb') as stream:
                dump = stream.read(MAX_IMAGE + 1)
            if len(dump) > MAX_IMAGE:
                raise ValueError('image exceeds 64 MiB')
            report = plan(manifest, dump)
            if args.command == 'policy':
                save_new(args.output, policy_header(manifest, dump))
                return 0
            if args.command in ('encode', 'simulate'):
                identity = strict_json(args.identity)
                request = encode_request(manifest, dump, identity, args.patch, args.sequence, args.operation)
                if args.command == 'encode':
                    save_new(args.output, request)
                    return 0
                # This executable accesses only a private host byte array.
                # Policy mirrors the manifest for simulation; a live resident
                # must register policies independently of all client requests.
                initial = next(row['expected'] for row in report['patches'] if row['id'] == args.patch)
                engine_hash = hashlib.sha256(args.engine.read_bytes()).hexdigest()
                completed = subprocess.run([str(args.engine.resolve()), args.fault],
                                           input=request + encode_identity(identity) + bytes.fromhex(initial).ljust(64, b'\0'),
                                           capture_output=True, timeout=10, check=True)
                if hashlib.sha256(args.engine.read_bytes()).hexdigest() != engine_hash:
                    raise ValueError('simulator binary changed during execution')
                result = decode_result(completed.stdout)
                report = {'schema': 1, 'type': 'kernel-patch-simulation', 'simulated': True,
                          'console_validated': False, 'manifest_sha256': report['manifest_sha256'],
                          'image_sha256': report['image_sha256'], 'identity': identity,
                          'request_sha256': hashlib.sha256(request).hexdigest(),
                          'engine_sha256': engine_hash,
                          'operation': args.operation, 'fault': args.fault, 'result': result}
        save_new(args.output, (json.dumps(report, indent=2) + '\n').encode())
        if args.command == 'simulate':
            return 0 if report['result']['status'] == 'ok' else 1
        if args.command == 'probe-decode':
            return 0 if report['status'] == 'ok' else 1
        if args.command == 'stage3-decode':
            return 0 if report['owned_cell_restoration_verified'] or report['query_identity_checked'] else 1
        if args.command == 'stage2-decode':
            return 0 if report['adapter_identity_checked'] else 1
        return 0
    except (OSError, ValueError, TypeError, KeyError, struct.error,
            subprocess.SubprocessError) as error:
        parser.exit(2, f'error: {error}\n')


if __name__ == '__main__':
    raise SystemExit(main())
