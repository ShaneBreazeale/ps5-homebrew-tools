"""Durability ordering, real C client/receiver, and scheduler-free core fixtures."""
import io
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'host'))
import checkpoints as cp

SESSION = bytes.fromhex('01000000000000000200000000000000')
BUILD = bytes.fromhex('22' + '00'*31)


def record(kind=1, seq=1, cpu=0xffffffff, site=0, phase=0, arguments=(0, 0, 0, 0)):
    raw = bytearray(cp.SIZE)
    raw[:8] = cp.MAGIC
    struct.pack_into('<II', raw, 8, 1, kind)
    raw[16:32] = SESSION
    struct.pack_into('<QQIIII', raw, 32, seq, 123, cpu, 0, site, phase)
    raw[64:96] = BUILD
    struct.pack_into('<4Q', raw, 96, *arguments)
    struct.pack_into('<I', raw, 284, zlib.crc32(raw[:284]))
    return bytes(raw)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        compiler = shlex.split(os.environ.get('HOST_CC', 'cc'))
        cls.client = cls.directory / 'checkpoint-demo'
        cls.core = cls.directory / 'resident-evidence'
        subprocess.run([*compiler, '-std=c11', '-D_POSIX_C_SOURCE=200809L', '-Wall', '-Wextra', '-Werror',
                        str(ROOT / 'examples/checkpoint-demo/main.c'), str(ROOT / 'lib/checkpoint/checkpoint.c'),
                        '-o', str(cls.client)], check=True)
        subprocess.run([*compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread',
                        str(ROOT / 'tests/test_resident_evidence.c'), '-o', str(cls.core)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def journal(self, directory, source='checkpoint_tcp', max_records=100):
        return cp.Journal(Path(directory) / 'run.jsonl', SESSION, BUILD, source, max_records=max_records)

    def test_c_core_bounds_nesting_concurrency_and_failures(self):
        subprocess.run([str(self.core)], check=True, timeout=30)

    def test_real_c_wire_to_python_resident_import(self):
        raw = subprocess.check_output([str(self.core), 'stream'], timeout=10)
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(directory, 'resident_stream')
            try:
                self.assertEqual(cp.ingest(io.BytesIO(raw), journal), 'eof')
            finally:
                journal.close()
            rows = [json.loads(line) for line in (Path(directory)/'run.jsonl').read_text().splitlines()]
            self.assertEqual([row['kind'] for row in rows[1:-1]], ['trace', 'panic'])
            self.assertEqual(rows[1]['arguments'][:2], ['0x0000000000000100', '0x0000000000000244'])
            self.assertEqual(rows[1]['registers']['r15'], '0xfedcba9876543210')
            self.assertEqual(rows[1]['subject_pid'], 77)
            self.assertTrue(rows[-1]['panic_record_received'])
            self.assertFalse(rows[-1]['kernel_crash_proven'])

    def test_ack_is_sent_only_after_fsync(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(directory)
            calls = []
            class Connection:
                data = [record(), record(5, 2)]
                def settimeout(self, value): pass
                def recv(self, limit): return self.data.pop(0)
                def sendall(self, data): calls.append(('ack', data))
            actual = os.fsync
            def fsync(fd):
                actual(fd)
                calls.append(('sync', fd))
            try:
                with patch.object(cp.os, 'fsync', side_effect=fsync):
                    self.assertEqual(cp.receive_connection(Connection(), journal), 'application_end')
            finally:
                journal.close()
            self.assertEqual([call[0] for call in calls], ['sync', 'ack', 'sync', 'ack', 'sync'])
            self.assertEqual(calls[1][1], cp.acknowledgement(record()))

    def test_storage_failure_never_acknowledges(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(directory)
            sent = []
            class Connection:
                def settimeout(self, value): pass
                def recv(self, limit): return record()
                def sendall(self, data): sent.append(data)
            try:
                with patch.object(cp.os, 'fsync', side_effect=OSError('disk failed')):
                    self.assertIn('disk failed', cp.receive_connection(Connection(), journal))
                self.assertTrue(journal.failed)
                self.assertEqual(sent, [])
            finally:
                journal.close()

    def test_c_client_end_to_end_and_runtime_group_filter(self):
        for groups, expected in [('1', ['hello', 'checkpoint', 'checkpoint', 'end']), ('0', ['hello', 'end'])]:
            with self.subTest(groups=groups), tempfile.TemporaryDirectory() as directory:
                journal = self.journal(directory)
                results = []
                with socket.socket() as server:
                    server.bind(('127.0.0.1', 0)); server.listen(1); server.settimeout(5)
                    def worker():
                        try:
                            connection, _ = server.accept()
                            with connection:
                                results.append(cp.receive_connection(connection, journal, 2, 10))
                        except BaseException as error:
                            results.append(error)
                    thread = threading.Thread(target=worker); thread.start()
                    try:
                        run = subprocess.run([str(self.client), '127.0.0.1', str(server.getsockname()[1]),
                                              SESSION.hex(), BUILD.hex(), groups], capture_output=True, timeout=10)
                        thread.join(10)
                        self.assertFalse(thread.is_alive())
                        self.assertEqual(run.returncode, 0, run.stderr)
                        self.assertEqual(results, ['application_end'])
                    finally:
                        journal.close()
                rows = [json.loads(line) for line in (Path(directory)/'run.jsonl').read_text().splitlines()]
                self.assertEqual([row['kind'] for row in rows[1:-1]], expected)
                report = cp.summarize(Path(directory)/'run.jsonl')
                self.assertEqual(report['pending_count'], 0)
                self.assertTrue(report['application_end_received'])

    def test_last_before_survives_lost_ack_and_summary_finds_interval(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(directory)
            class Connection:
                data = [record(), record(2, 2, site=100, phase=1, arguments=(0x100, 0x244, 0, 0))]
                acknowledgements = 0
                def settimeout(self, value): pass
                def recv(self, limit): return self.data.pop(0)
                def sendall(self, data):
                    self.acknowledgements += 1
                    if self.acknowledgements == 2:
                        raise ConnectionResetError('ACK lost')
            try:
                self.assertIn('ACK lost', cp.receive_connection(Connection(), journal))
            finally:
                journal.close()
            path = Path(directory)/'run.jsonl'
            report = cp.summarize(path)
            self.assertEqual(report['pending_count'], 1)
            self.assertEqual(report['pending_checkpoints'][0]['site'], 100)
            self.assertFalse(report['kernel_crash_proven'])
            # A host crash during the final append keeps the earlier evidence.
            data = path.read_bytes().splitlines(keepends=True)
            path.write_bytes(b''.join(data[:-1]) + b'{"type":')
            report = cp.summarize(path)
            self.assertEqual(report['pending_count'], 1)
            self.assertEqual(report['transport_outcome'], 'incomplete_final_json_line')

    def test_summary_empty_stream_and_raw_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(directory)
            journal.finish('accept_timeout'); journal.close()
            path = Path(directory)/'run.jsonl'
            self.assertEqual(cp.summarize(path)['records'], 0)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            rows[-1]['stream_sha256'] = '00'*32
            path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
            with self.assertRaises(ValueError): cp.summarize(path)

    def test_c_client_refuses_bad_ack_and_does_not_run_operation(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0)); server.listen(1); server.settimeout(5)
            received = []
            def worker():
                connection, _ = server.accept()
                with connection:
                    data = b''
                    while len(data) < cp.SIZE:
                        data += connection.recv(cp.SIZE-len(data))
                    received.append(cp.decode_record(data)['kind'])
                    connection.sendall(b'x'*32)
                    received.append(connection.recv(cp.SIZE))
            thread = threading.Thread(target=worker); thread.start()
            run = subprocess.run([str(self.client), '127.0.0.1', str(server.getsockname()[1]),
                                  SESSION.hex(), BUILD.hex()], capture_output=True, timeout=10)
            thread.join(10)
            self.assertEqual(run.returncode, 1)
            self.assertEqual(received, ['hello', b''])

    def test_c_client_stops_after_before_ack_is_lost(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(directory)
            received = []
            with socket.socket() as server:
                server.bind(('127.0.0.1', 0)); server.listen(1); server.settimeout(5)
                def worker():
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(5)
                        for index in range(2):
                            data = b''
                            while len(data) < cp.SIZE:
                                chunk = connection.recv(cp.SIZE-len(data))
                                if not chunk: raise RuntimeError('unexpected client EOF')
                                data += chunk
                            received.append(journal.append(data)['kind'])
                            if index == 0:
                                connection.sendall(cp.acknowledgement(data))
                        connection.shutdown(socket.SHUT_WR)  # before persisted, ACK lost
                        received.append(connection.recv(cp.SIZE))
                thread = threading.Thread(target=worker); thread.start()
                try:
                    run = subprocess.run([str(self.client), '127.0.0.1', str(server.getsockname()[1]),
                                          SESSION.hex(), BUILD.hex()], capture_output=True, timeout=10)
                    thread.join(10)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(run.returncode, 1)
                    self.assertEqual(received, ['hello', 'checkpoint', b''])
                finally:
                    journal.close()
            self.assertEqual(cp.summarize(Path(directory)/'run.jsonl')['pending_count'], 1)

    def test_partial_and_corrupt_records_preserved_without_resync(self):
        for raw, outcome in [(record()[:41], 'truncated'), (record(3, cpu=1, site=100)[:-1]+b'x', 'CRC')]:
            with tempfile.TemporaryDirectory() as directory:
                journal = self.journal(directory, 'resident_stream')
                try:
                    self.assertIn(outcome, cp.ingest(io.BytesIO(raw), journal))
                finally:
                    journal.close()
                rows = [json.loads(line) for line in (Path(directory)/'run.jsonl').read_text().splitlines()]
                self.assertEqual(bytes.fromhex(rows[-1]['fragment_hex']), raw)
                self.assertFalse(rows[-1]['kernel_crash_proven'])

    def test_identity_lifecycle_replay_budget_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(directory, max_records=2)
            try:
                with self.assertRaises(FileExistsError): self.journal(directory)
                with self.assertRaises(ValueError): journal.append(record(2, site=100))
                wrong = bytearray(record()); wrong[16] = 2
                struct.pack_into('<I', wrong, 284, zlib.crc32(wrong[:284]))
                with self.assertRaises(ValueError): journal.append(bytes(wrong))
                journal.append(record())
                with self.assertRaises(ValueError): journal.append(record())
                journal.append(record(2, 2, site=100, phase=1))
                with self.assertRaises(ValueError): journal.append(record(5, 3))
            finally:
                journal.close()

    def test_resident_sequence_gaps_and_separate_cpu_domains(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(directory, 'resident_stream')
            try:
                self.assertEqual(journal.append(record(3, 3, cpu=0, site=100))['missing_sequences'], 2)
                self.assertEqual(journal.append(record(3, 1, cpu=1, site=100))['missing_sequences'], 0)
                journal.append(record(4, 1, cpu=0, site=200))
                with self.assertRaises(ValueError): journal.append(record(4, 2, cpu=0, site=200))
            finally:
                journal.close()

    def test_bad_schema_flags_phase_and_cpu(self):
        for offset, value in [(8, 2), (12, 99), (48, 16), (60, 3), (272, 2)]:
            raw = bytearray(record(3, cpu=1, site=100))
            struct.pack_into('<I', raw, offset, value)
            struct.pack_into('<I', raw, 284, zlib.crc32(raw[:284]))
            with self.subTest(offset=offset), self.assertRaises(ValueError): cp.decode_record(bytes(raw))

    def test_checkpoint_subject_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(directory)
            try:
                journal.append(record())
                raw = bytearray(record(2, 2, site=100))
                struct.pack_into('<I', raw, 280, 77)
                struct.pack_into('<I', raw, 284, zlib.crc32(raw[:284]))
                with self.assertRaisesRegex(ValueError, 'process identity changed'):
                    journal.append(bytes(raw))
            finally:
                journal.close()

    def test_cli_ingest_records_exact_artifact_and_experiment(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            binary = directory / 'stream.bin'; binary.write_bytes(subprocess.check_output([str(self.core), 'stream']))
            artifact = directory / 'research.elf'; artifact.write_bytes(b'\x7fELF\x02\x01' + b'\0'*58)
            output = directory / 'run.jsonl'
            args = ['ingest', '--input', str(binary), '--output', str(output), '--session', SESSION.hex(),
                    '--build-id', BUILD.hex(), '--artifact', str(artifact), '--experiment', 'xeax-001']
            self.assertEqual(cp.main(args), 0)
            manifest = json.loads(output.read_text().splitlines()[0])
            self.assertEqual(manifest['metadata']['experiment'], 'xeax-001')
            self.assertEqual(manifest['metadata']['artifact']['bytes'], 64)
            self.assertEqual(cp.main(args), 2)


if __name__ == '__main__':
    unittest.main()
