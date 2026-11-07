"""Real nonblocking coordinator/mailbox, with simulated CPU/architecture adapters."""
import os
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'host'))
from kernel_control import decode_reply, encode_request


class KernelExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.folder.cleanup)
        cls.executable = Path(cls.folder.name) / 'kernel-execution-test'
        compiler = shlex.split(os.environ.get('HOST_CC', 'cc'))
        subprocess.run([*compiler, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-pthread', str(ROOT / 'tests/test_kernel_execution.c'),
                        '-o', str(cls.executable)], check=True)

    def run_scenario(self, mode):
        subprocess.run([str(self.executable), mode], check=True, timeout=30)

    def test_stop_requires_all_cpu_acknowledgements(self):
        self.run_scenario('stop')

    def test_step_isolated_and_verified_before_reuse(self):
        self.run_scenario('step')

    def test_restore_barrier_and_stale_tickets(self):
        self.run_scenario('restore')

    def test_timeout_recapture_and_no_unverified_release(self):
        self.run_scenario('timeout')

    def test_mailbox_publication_and_command_replay(self):
        self.run_scenario('mailbox')

    def test_sixteen_cpus_and_mailbox_concurrently(self):
        self.run_scenario('concurrent')

    def test_one_hundred_capture_drain_restore_release_windows_without_reinitializing_controller(self):
        self.run_scenario('reuse')

    def test_draining_ring_does_not_release_failed_restoration(self):
        self.run_scenario('drain-failed-restore')

    def test_draining_ring_does_not_manufacture_missing_cpu_acknowledgement(self):
        self.run_scenario('drain-missing-cpu')

    def test_host_codec_matches_actual_c_wire_and_cli(self):
        request = {'operation': 'stop', 'session': [11, 22], 'sequence': 1,
                   'epoch': 0, 'deadline': 1000, 'argument': 2}
        binary = encode_request(request)
        self.assertEqual(len(binary), 64)
        result = subprocess.run([str(self.executable), 'wire'], input=binary,
                                capture_output=True, check=True, timeout=30)
        reply = decode_reply(result.stdout)
        self.assertEqual((reply['state'], reply['epoch'], reply['need_stop_mask']), ('stopping', 1, '0x1'))
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / 'request.json').write_text(json.dumps(request))
            script = [sys.executable, str(ROOT / 'host/kernel_control.py')]
            command = [*script, 'encode', '--request', str(folder / 'request.json'),
                       '--output', str(folder / 'request.bin')]
            subprocess.run(command, check=True)
            self.assertEqual((folder / 'request.bin').read_bytes(), binary)
            exists = subprocess.run(command, capture_output=True)
            self.assertEqual(exists.returncode, 2)
            (folder / 'reply.bin').write_bytes(result.stdout)
            result = subprocess.run([*script, 'decode', '--reply', str(folder / 'reply.bin')],
                                    capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(result.stdout), reply)

    def test_codec_refuses_bad_ranges_and_inconsistent_reply(self):
        request = {'operation': 'stop', 'session': [11, 22], 'sequence': 1,
                   'epoch': 0, 'deadline': 1000, 'argument': 2}
        for key, value in [('sequence', True), ('sequence', -1), ('sequence', 1 << 64),
                           ('cpu', 16), ('argument', 5_000), ('session', [0, 0]),
                           ('deadline', 0), ('extra', 1)]:
            with self.subTest(key=key, value=value), self.assertRaises((ValueError, KeyError)):
                encode_request({**request, key: value})
        result = subprocess.run([str(self.executable), 'wire'], input=encode_request(request),
                                capture_output=True, check=True, timeout=30)
        for offset, value in [(0, 2), (12, 255), (48, 0), (60, 2), (76, 2), (96, 1)]:
            binary = bytearray(result.stdout)
            binary[offset:offset+4] = value.to_bytes(4, 'little')
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                decode_reply(binary)
        with self.assertRaises(ValueError):
            decode_reply(result.stdout[:-1])


if __name__ == '__main__':
    unittest.main()
