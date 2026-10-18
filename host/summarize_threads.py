#!/usr/bin/env python3
"""Validate v2 probe records and summarize processes/threads without kernel writes."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import struct


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]


def cstring(data):
    return bytes(data).split(b'\0', 1)[0].decode('ascii', errors='replace')


def summarize(text):
    records = {}
    owners = {}
    for line in text.splitlines():
        header = re.fullmatch(
            r'thread pid=(\d+) comm=(\S+) index=(\d+) tid=(\d+) '
            r'td=(0x[0-9a-f]+) proc=(0x[0-9a-f]+)', line)
        if header:
            pid, comm, index, tid, td, proc = header.groups()
            key = (int(pid), int(tid))
            value = (int(td, 16), int(proc, 16), comm)
            if key in owners and owners[key] != value:
                raise ValueError(f'owner changed for {key}')
            owners[key] = value
        raw = re.fullmatch(r'raw tag=(\S+) seq=(\d+) offset=(\d+) hex=([0-9a-f]+)', line)
        if not raw:
            continue
        tag, seq, offset, hexdata = raw.groups()
        buf = records.setdefault((tag, int(seq)), bytearray())
        if int(offset) != len(buf):
            raise ValueError(f'noncontiguous raw record {tag}/{seq}')
        buf.extend(bytes.fromhex(hexdata))

    if 'kernel_layout_validated=1' not in text or 'thread-probe: complete' not in text:
        raise ValueError('missing live self-validation or completion marker')

    procs = defaultdict(list)
    threads = defaultdict(list)
    for (tag, seq), data in records.items():
        if tag.startswith('all-'):
            if len(data) != 1096 or u32(data, 0) != len(data):
                raise ValueError(f'invalid process record {tag}/{seq}')
            procs[int(tag[4:])].append({
                'pid': u32(data, 72), 'comm': cstring(data[447:467]),
                'sysctl_thread_name': cstring(data[394:411]),
                'sysctl_wait_message': cstring(data[411:420]),
                'sysctl_state_raw': data[388],
                'sysctl_numthreads_candidate': u32(data, 596),
                'sysctl_tid_candidate': u32(data, 600),
            })
        elif tag.startswith('td-'):
            _, pid, tid, passno = tag.split('-')
            pid, tid, passno = int(pid), int(tid), int(passno)
            if len(data) != 0x480:
                raise ValueError(f'truncated thread record {tag}')
            td, proc, comm = owners[(pid, tid)]
            if u64(data, 8) != proc or u32(data, 0x9c) != tid:
                raise ValueError(f'owner/TID mismatch {tag}')
            threads[passno].append({
                'pid': pid, 'tid': tid, 'comm': comm,
                'td': hex(td), 'proc': hex(proc),
                # These fields are retained as candidates: name agrees with
                # self's sysctl name, PCB/frame offsets come from kstuff.
                # Do not infer a blocked instruction from the saved pointer.
                'name_candidate': cstring(data[0x294:0x2b4]),
                'state_candidate': u32(data, 0x400),
                'wchan_candidate': hex(u64(data, 0xf8)),
                'wmesg_pointer_candidate': hex(u64(data, 0x100)),
                'pcb_pointer': hex(u64(data, 0x3f8)),
                'trapframe_pointer': hex(u64(data, 0x460)),
            })

    if set(procs) != {0, 1, 2} or set(threads) != {0, 1, 2}:
        raise ValueError('missing snapshot')
    counts = {str(p): dict(Counter(t['pid'] for t in ts)) for p, ts in threads.items()}
    # v2 printed the SDK app-info layout. Firmware's four-byte prefix of
    # the title appears in the printed app_type field. Preserve this only
    # as a candidate, rather than silently calling the SDK layout correct.
    titles = []
    seen = set()
    for pid, appid, kind, tail in re.findall(
        r'^app pid=(\d+) rc=0 appid=(0x[0-9a-f]+) type=(0x[0-9a-f]+) title=(\S*)$',
        text, re.M):
        prefix = struct.pack('<I', int(kind, 16)).decode('ascii', errors='replace')
        title = prefix + tail
        if re.fullmatch(r'[A-Z]{4}[0-9]{5}', title) and (pid, title) not in seen:
            seen.add((pid, title))
            titles.append({'pid': int(pid), 'appid': appid, 'title_candidate': title})
    return {
        'process_counts': {str(p): len(ps) for p, ps in procs.items()},
        'captured_thread_counts': counts,
        'processes': dict(procs), 'threads': dict(threads),
        'app_title_candidates': titles,
        'limits': [
            'ShellCore reached the v2 cap of 256 threads; its list is incomplete.',
            'Kernel field offsets except owner, TID, and list links remain candidates.',
            'Thread snapshots are observations without stopping threads.',
            'App titles reconstruct a firmware layout different from the SDK sample.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    args = parser.parse_args()
    try:
        result = summarize(args.capture.read_text(encoding='utf-8', errors='backslashreplace'))
    except KeyError as error:
        parser.exit(2, f'error: thread record without a matching header: {error}\n')
    except (OSError, ValueError, struct.error) as error:
        parser.exit(2, f'error: {error}\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
