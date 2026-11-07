#!/usr/bin/env python3
"""Encode/decode saved kernel-execution ABI records. No network or live target."""
import argparse
import json
from pathlib import Path
import struct

from analysis_common import integer

REQUEST = struct.Struct('<IIII6Q')
REPLY = struct.Struct('<IIII4Q8IQII18Q')
OPERATIONS = {'status': 1, 'stop': 2, 'registers': 3, 'step': 4, 'restore': 5, 'abort': 6}
STATES = ['idle', 'stopping', 'stopped', 'step_preparing', 'stepping', 'step_cleanup',
          'restoring', 'releasing', 'complete', 'failed']
ERRORS = ['ok', 'busy', 'invalid', 'stale', 'state', 'unsupported', 'io', 'timeout',
          'unexpected', 'limit', 'canceled']
REGISTERS = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip', 'rflags']


def unsigned(value, bits):
    value = integer(value)
    if not 0 <= value < 1 << bits:
        raise ValueError(f'value outside uint{bits}')
    return value


def encode_request(record):
    required = {'operation', 'session', 'sequence', 'epoch'}
    if not isinstance(record, dict) or not required <= record.keys() or record.keys() - required - {'cpu', 'deadline', 'argument'}:
        raise ValueError('request fields differ from ABI 1')
    operation = OPERATIONS[record['operation']]
    session = record['session']
    if not isinstance(session, list) or len(session) != 2:
        raise ValueError('session requires two uint64 words')
    session = [unsigned(word, 64) for word in session]
    sequence, epoch = unsigned(record['sequence'], 64), unsigned(record['epoch'], 64)
    cpu = unsigned(record.get('cpu', 0), 32)
    deadline, argument = (unsigned(record.get(key, 0), 64) for key in ('deadline', 'argument'))
    if not any(session) or not sequence or cpu >= 16:
        raise ValueError('invalid session, sequence or CPU')
    if (operation not in (3, 4) and cpu) or (operation != 2 and argument):
        raise ValueError('unused CPU/argument must be zero')
    if (operation in (2, 4, 5)) != bool(deadline):
        raise ValueError('deadline required only for stop, step and restore')
    if operation == 2 and not 1 <= argument <= 4096:
        raise ValueError('stop argument must be a step budget from 1 to 4096')
    return REQUEST.pack(1, REQUEST.size, operation, cpu, *session, sequence, epoch, deadline, argument)


def decode_reply(data):
    if len(data) != REPLY.size:
        raise ValueError('reply must contain exactly 240 bytes')
    (abi, size, result, state, session0, session1, sequence, epoch,
     cpus, parked, restored, released, need_stop, fault, step_cpu, registers_valid,
     step_ticket, steps, step_limit, *registers) = REPLY.unpack(data)
    if abi != 1 or size != REPLY.size or state >= len(STATES) or result >= len(ERRORS) or fault >= len(ERRORS):
        raise ValueError('unsupported reply ABI/state/error')
    if not (session0 or session1) or not sequence or not 0 < cpus <= 0xffff:
        raise ValueError('reply lacks session/sequence/CPU identity')
    if any(mask & ~cpus for mask in (parked, restored, released, need_stop)) or released & ~restored or released & parked:
        raise ValueError('inconsistent reply CPU masks')
    if step_cpu > 16 or not 0 <= steps <= step_limit <= 4096 or registers_valid not in (0, 1):
        raise ValueError('invalid step/register fields')
    if (registers_valid and (state != 2 or result)) or (not registers_valid and any(registers)):
        raise ValueError('unavailable or running registers must not contain a snapshot')
    return {
        'schema': abi, 'result': ERRORS[result], 'state': STATES[state],
        'session': [hex(session0), hex(session1)], 'sequence': sequence, 'epoch': epoch,
        'cpu_mask': hex(cpus), 'parked_mask': hex(parked), 'restored_mask': hex(restored),
        'released_mask': hex(released), 'need_stop_mask': hex(need_stop), 'fault': ERRORS[fault],
        'step_cpu': None if step_cpu == 16 else step_cpu, 'step_ticket': step_ticket,
        'steps': steps, 'step_limit': step_limit,
        'registers': dict(zip(REGISTERS, map(hex, registers))) if registers_valid else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    encode = commands.add_parser('encode', help='write one request for a separately implemented bridge')
    encode.add_argument('--request', type=Path, required=True)
    encode.add_argument('--output', type=Path, required=True)
    decode = commands.add_parser('decode', help='inspect one saved binary reply')
    decode.add_argument('--reply', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'encode':
            data = encode_request(json.loads(args.request.read_text()))
            with args.output.open('xb') as output:
                output.write(data)
        else:
            if args.reply.stat().st_size != REPLY.size:
                raise ValueError('reply must contain exactly 240 bytes')
            print(json.dumps(decode_reply(args.reply.read_bytes()), indent=2))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f'error: {error}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
