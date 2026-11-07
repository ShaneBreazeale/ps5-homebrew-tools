#!/usr/bin/env python3
"""Durable checkpoint receiver and offline resident evidence stream importer."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import sys
import time
import zlib

SIZE = 288
MAGIC = b'PS5EVID1'
KINDS = {1: 'hello', 2: 'checkpoint', 3: 'trace', 4: 'panic', 5: 'end'}
REGISTER_NAMES = 'rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip rflags'.split()


def identity(text, length):
    if not isinstance(text, str) or len(text) != length * 2:
        raise ValueError(f'identity must contain {length * 2} hexadecimal digits')
    try:
        value = bytes.fromhex(text)
    except ValueError as error:
        raise ValueError('identity must be hexadecimal') from error
    if len(value) != length or not any(value):
        raise ValueError('identity must be nonzero hexadecimal bytes')
    return value


def decode_record(raw):
    if len(raw) != SIZE or raw[:8] != MAGIC:
        raise ValueError('wrong record size or magic; stream resynchronization is refused')
    schema, kind = struct.unpack_from('<II', raw, 8)
    if schema != 1 or kind not in KINDS:
        raise ValueError('unsupported record schema or kind')
    if struct.unpack_from('<I', raw, 284)[0] != zlib.crc32(raw[:284]):
        raise ValueError('record CRC mismatch')
    session = raw[16:32]
    sequence, ticks, cpu, thread, site, phase = struct.unpack_from('<QQIIII', raw, 32)
    flags, dropped, subject_pid = struct.unpack_from('<III', raw, 272)
    registers = struct.unpack_from('<18Q', raw, 128)
    arguments = struct.unpack_from('<4Q', raw, 96)
    if not any(session) or not any(raw[64:96]) or not sequence or phase > 2 or flags & ~1:
        raise ValueError('invalid record fields')
    if not flags & 1 and any(registers):
        raise ValueError('register bytes present without validity flag')
    if kind in (1, 2, 5):
        if cpu != 0xffffffff or flags or dropped or (kind == 2 and not site):
            raise ValueError('invalid checkpoint fields')
        if kind != 2 and (thread or site or phase or any(arguments)):
            raise ValueError('invalid hello/end fields')
    else:
        if cpu >= 16 or not site or (kind == 4 and phase):
            raise ValueError('invalid resident fields')
    return {
        'schema': schema, 'kind': KINDS[kind], 'session': session.hex(),
        'build_id': raw[64:96].hex(), 'sequence': sequence, 'ticks': ticks,
        'clock': 'monotonic_milliseconds' if kind in (1, 2, 5) else 'adapter_ticks',
        'cpu': None if cpu == 0xffffffff else cpu, 'thread': thread,
        'subject_pid': subject_pid or None,
        'site': site, 'phase': ('point', 'before', 'after')[phase],
        'arguments': [f'0x{x:016x}' for x in arguments],
        'registers': dict(zip(REGISTER_NAMES, (f'0x{x:016x}' for x in registers))) if flags & 1 else None,
        'dropped': dropped, 'raw_hex': raw.hex(),
    }


def acknowledgement(raw):
    return b'PS5ACK01' + raw[16:32] + raw[32:40]


class Journal:
    """Only successful append+fsync permits an ACK. Output is never reopened."""
    def __init__(self, path, session, build_id, source, metadata=None, max_records=100000):
        if len(session) != 16 or not any(session) or len(build_id) != 32 or not any(build_id):
            raise ValueError('invalid session/build identity')
        if source not in ('checkpoint_tcp', 'resident_stream') or not 1 <= max_records <= 1000000:
            raise ValueError('invalid journal source/budget')
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError('metadata must be an object')
        self.session, self.build_id = session.hex(), build_id.hex()
        self.source, self.max_records = source, max_records
        self.count = 0
        self.sequences = {}
        self.ended = False
        self.panic_received = False
        self.subject_pid = None
        self.failed = False
        self.stream_hash = hashlib.sha256()
        # O_EXCL and mode 0600 also prevent following an existing symlink.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.file = os.fdopen(fd, 'wb', buffering=0)
        try:
            self._write({'type': 'manifest', 'schema': 1, 'session': self.session,
                         'build_id': self.build_id, 'source': source,
                         'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                         'durability': 'host_fsync_before_ack', 'max_records': max_records,
                         'metadata': metadata or {}, 'console_validated': False})
            # Persist the new directory entry before accepting any checkpoint.
            directory = os.open(str(Path(path).resolve().parent), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            self.file.close()
            raise

    def _write(self, value):
        if self.failed:
            raise OSError('journal has failed; refusing further writes/acknowledgements')
        data = (json.dumps(value, separators=(',', ':'), sort_keys=True, ensure_ascii=False) + '\n').encode()
        try:
            view = memoryview(data)
            while view:
                written = self.file.write(view)
                if not written:
                    raise OSError('short journal write')
                view = view[written:]
            os.fsync(self.file.fileno())
        except BaseException:
            self.failed = True
            raise

    def append(self, raw):
        if self.count >= self.max_records:
            raise ValueError('record budget exhausted')
        event = decode_record(raw)
        if event['session'] != self.session or event['build_id'] != self.build_id:
            raise ValueError('session/build identity mismatch')
        if self.source == 'checkpoint_tcp':
            expected = 'hello' if not self.count else None
            if (expected and event['kind'] != expected) or (self.count and event['kind'] not in ('checkpoint', 'end')) or self.ended:
                raise ValueError('invalid checkpoint lifecycle')
            key = 'checkpoint'
            previous = self.sequences.get(key, 0)
            if event['sequence'] != previous + 1:
                raise ValueError('checkpoint sequence is not contiguous; replay refused')
            if self.count and event['subject_pid'] != self.subject_pid:
                raise ValueError('checkpoint process identity changed')
        else:
            if event['kind'] not in ('trace', 'panic'):
                raise ValueError('resident import accepts trace/panic records only')
            key = (event['kind'], event['cpu'])
            previous = self.sequences.get(key, 0)
            if event['sequence'] <= previous or (event['kind'] == 'panic' and previous):
                raise ValueError('resident sequence duplicate or backwards')
            event['missing_sequences'] = event['sequence'] - previous - 1
        event['type'] = 'event'
        event['received_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._write(event)
        self.sequences[key] = event['sequence']
        if self.source == 'checkpoint_tcp':
            self.subject_pid = event['subject_pid']
        self.stream_hash.update(raw)
        self.count += 1
        self.ended = event['kind'] == 'end'
        self.panic_received |= event['kind'] == 'panic'
        return event

    def finish(self, outcome, fragment=b''):
        # EOF/timeout is never promoted to a kernel panic diagnosis.
        self._write({'type': 'transport_end', 'outcome': outcome, 'records': self.count,
                     'application_end_received': self.ended,
                     'panic_record_received': self.panic_received,
                     'kernel_crash_proven': False, 'stream_sha256': self.stream_hash.hexdigest(),
                     'fragment_hex': fragment.hex()})

    def close(self):
        self.file.close()


def receive_connection(connection, journal, timeout=10.0, total_seconds=3600.0):
    deadline = time.monotonic() + total_seconds
    fragment = bytearray()
    outcome = 'eof'
    try:
        while not journal.ended:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('total receive deadline')
            connection.settimeout(min(timeout, remaining))
            data = connection.recv(SIZE - len(fragment))
            if not data:
                outcome = 'truncated' if fragment else 'eof'
                break
            fragment.extend(data)
            if len(fragment) != SIZE:
                continue
            raw = bytes(fragment)
            journal.append(raw)  # fsync MUST succeed before sendall below.
            fragment.clear()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('deadline after durable write; ACK not sent')
            connection.settimeout(min(timeout, remaining))
            connection.sendall(acknowledgement(raw))
        if journal.ended:
            outcome = 'application_end'
    except (OSError, ValueError) as error:
        outcome = f'{type(error).__name__}: {error}'
    if not journal.failed:
        journal.finish(outcome, bytes(fragment))
    return outcome


def ingest(stream, journal):
    fragment = bytearray()
    outcome = 'eof'
    try:
        while True:
            data = stream.read(SIZE - len(fragment))
            if not data:
                outcome = 'truncated' if fragment else 'eof'
                break
            fragment.extend(data)
            if len(fragment) == SIZE:
                journal.append(bytes(fragment))
                fragment.clear()
    except (OSError, ValueError) as error:
        outcome = f'{type(error).__name__}: {error}'
    if not journal.failed:
        journal.finish(outcome, bytes(fragment))
    return outcome


def artifact_identity(path):
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        while True:
            block = stream.read(65536)
            if not block:
                break
            if not size and (len(block) < 64 or block[:6] != b'\x7fELF\x02\x01'):
                raise ValueError('artifact must be a complete ELF64 little-endian file')
            size += len(block)
            if size > 128 * 1024 * 1024:
                raise ValueError('artifact exceeds 128 MiB')
            digest.update(block)
    if not size:
        raise ValueError('empty artifact')
    return {'name': path.name, 'bytes': size, 'sha256': digest.hexdigest()}


def summarize(path, max_bytes=256*1024*1024):
    """Recheck raw records; report pending calls without inferring a panic."""
    digest = hashlib.sha256()
    total, count = 0, 0
    manifest, footer, last = None, None, None
    record_digest = hashlib.sha256()
    sequences, pending, resident_last = {}, {}, {}
    ended = False
    checkpoint_pid = None
    with path.open('rb') as stream:
        while True:
            line = stream.readline(131073)
            if not line:
                break
            total += len(line)
            if len(line) > 131072 or total > max_bytes:
                raise ValueError('journal line/file exceeds summary budget')
            digest.update(line)
            # A torn final JSON line is explicitly reported; earlier evidence
            # remains useful after a host crash or failed storage operation.
            if not line.endswith(b'\n'):
                footer = {'outcome': 'incomplete_final_json_line'}
                break
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError('journal entry must be an object')
            if manifest is None:
                if row.get('type') != 'manifest' or row.get('schema') != 1 or row.get('source') not in ('checkpoint_tcp', 'resident_stream'):
                    raise ValueError('missing/invalid journal manifest')
                identity(row.get('session', ''), 16); identity(row.get('build_id', ''), 32)
                if not isinstance(row.get('metadata'), dict):
                    raise ValueError('manifest metadata must be an object')
                manifest = row
                continue
            if footer:
                raise ValueError('data after transport_end')
            if row.get('type') == 'transport_end':
                footer = row
                if row.get('stream_sha256') != record_digest.hexdigest() or row.get('records') != count:
                    raise ValueError('footer stream hash/count mismatch')
                continue
            if row.get('type') != 'event':
                raise ValueError('unexpected journal entry')
            if not isinstance(row.get('raw_hex'), str):
                raise ValueError('event raw_hex must be a string')
            raw = bytes.fromhex(row['raw_hex'])
            event = decode_record(raw)
            if any(row.get(key) != value for key, value in event.items()):
                raise ValueError('decoded journal fields differ from raw evidence')
            if event['session'] != manifest['session'] or event['build_id'] != manifest['build_id']:
                raise ValueError('journal identity mismatch')
            record_digest.update(raw)
            if manifest['source'] == 'checkpoint_tcp':
                if ended or (not count and event['kind'] != 'hello') or (count and event['kind'] not in ('checkpoint', 'end')) or event['sequence'] != count+1:
                    raise ValueError('checkpoint lifecycle/sequence mismatch')
                ended = event['kind'] == 'end'
                if count and event['subject_pid'] != checkpoint_pid:
                    raise ValueError('checkpoint process identity changed')
                checkpoint_pid = event['subject_pid']
                if event['kind'] == 'checkpoint':
                    key = (event['thread'], event['site'])
                    if event['phase'] == 'before':
                        pending.setdefault(key, []).append(event)
                    elif event['phase'] == 'after' and pending.get(key):
                        pending[key].pop()
            else:
                if event['kind'] not in ('trace', 'panic'):
                    raise ValueError('unexpected resident record kind')
                key = (event['kind'], event['cpu'])
                previous = sequences.get(key, 0)
                if event['sequence'] <= previous or (event['kind'] == 'panic' and previous):
                    raise ValueError('resident sequence duplicate/backwards')
                sequences[key] = event['sequence']
                resident_last[f"{event['kind']}:cpu{event['cpu']}"] = event
            last = event
            count += 1
            if count > 1000000:
                raise ValueError('summary record budget exhausted')
    if manifest is None:
        raise ValueError('no manifest')
    def compact(event):
        if event is None:
            return None
        result = {key: value for key, value in event.items() if key not in ('raw_hex', 'session', 'build_id', 'schema')}
        sites = manifest.get('metadata', {}).get('sites', {})
        if isinstance(sites, dict) and str(event['site']) in sites:
            result['site_schema'] = sites[str(event['site'])]
        return result
    outstanding = sorted((event for stack in pending.values() for event in stack), key=lambda event: event['sequence'])
    return {'schema': 1, 'journal_sha256': digest.hexdigest(), 'manifest': manifest,
            'records': count, 'transport_outcome': (footer or {}).get('outcome', 'no_transport_footer'),
            'application_end_received': ended, 'kernel_crash_proven': False,
            'panic_record_received': any(key.startswith('panic:') for key in resident_last),
            'last_record_in_stream': compact(last),
            'pending_checkpoints': [compact(event) for event in outstanding[-128:]],
            'pending_count': len(outstanding), 'pending_omitted': max(0, len(outstanding)-128),
            'resident_last_per_domain': {key: compact(value) for key, value in resident_last.items()},
            'limits': ['A pending before record identifies an interval, not the faulty instruction.',
                       'EOF/timeout and ShellUI termination do not establish a kernel panic.',
                       'Resident CPU streams have no implied global time ordering.',
                       'A stored record does not prove its ACK reached the app.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('listen', 'ingest'):
        command = sub.add_parser(name)
        command.add_argument('--output', required=True, type=Path)
        command.add_argument('--session', required=True, help='32 hex digits, fresh for every run')
        command.add_argument('--build-id', required=True, help='64 hex digits, application/resident source identity')
        command.add_argument('--metadata', type=Path, help='local JSON object with ELF hash, firmware/model and run context')
        command.add_argument('--experiment', required=True, help='variant/run label, e.g. xeax-001; not an execution stage')
        command.add_argument('--artifact', type=Path, required=name == 'listen', help='exact ELF for hash/size provenance; never sent')
        command.add_argument('--max-records', type=int, default=100000)
    listener = sub.choices['listen']
    listener.add_argument('--bind', default='127.0.0.1', help='explicit host interface for console use; not console address')
    listener.add_argument('--port', type=int, default=10071)
    listener.add_argument('--timeout', type=float, default=30, help='accept/record/ACK timeout seconds')
    listener.add_argument('--total-seconds', type=float, default=3600)
    sub.choices['ingest'].add_argument('--input', required=True, help='raw saved/bridged stream, or - for stdin; no ACK')
    sub.add_parser('summary', help='offline: recheck a journal and show pending calls').add_argument('journal', type=Path)
    args = parser.parse_args(argv)
    try:
        import math
        if args.command == 'summary':
            print(json.dumps(summarize(args.journal), indent=2, sort_keys=True))
            return 0
        session, build_id = identity(args.session, 16), identity(args.build_id, 32)
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', args.experiment):
            raise ValueError('experiment must be 1..64 letters/digits/underscore/dot/hyphen')
        if not 1 <= args.max_records <= 1000000:
            raise ValueError('max-records must be 1..1000000')
        metadata = {}
        if args.metadata:
            with args.metadata.open('rb') as file:
                data = file.read(65537)
            if len(data) > 65536:
                raise ValueError('metadata exceeds 64 KiB')
            metadata = json.loads(data)
            if not isinstance(metadata, dict):
                raise ValueError('metadata must be an object')
        metadata['experiment'] = args.experiment
        if args.artifact:
            metadata['artifact'] = artifact_identity(args.artifact)
        if args.command == 'listen':
            if not 1 <= args.port <= 65535 or not all(math.isfinite(x) and 0 < x <= 86400 for x in (args.timeout, args.total_seconds)):
                raise ValueError('invalid port or timeout (maximum 86400 seconds)')
        journal = Journal(args.output, session, build_id,
                          'checkpoint_tcp' if args.command == 'listen' else 'resident_stream', metadata, args.max_records)
        try:
            if args.command == 'listen':
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                    server.bind((args.bind, args.port))
                    server.listen(1)
                    server.settimeout(args.timeout)
                    print(f'checkpoint listener {server.getsockname()[0]}:{server.getsockname()[1]}', flush=True)
                    try:
                        connection, _ = server.accept()
                    except OSError as error:
                        journal.finish(f'accept_error: {error}')
                        raise
                    with connection:
                        outcome = receive_connection(connection, journal, args.timeout, args.total_seconds)
            else:
                if args.input == '-':
                    outcome = ingest(sys.stdin.buffer, journal)
                else:
                    with open(args.input, 'rb') as stream:
                        outcome = ingest(stream, journal)
            print(outcome)
            return 0 if outcome == ('application_end' if args.command == 'listen' else 'eof') else 1
        finally:
            journal.close()
    except (OSError, ValueError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
