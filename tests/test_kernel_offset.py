"""Kernel inspection checks; no console, SDK or captured kernel required."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'host'))
from kernel_offset import DEFAULT_PROFILE, load_profile, load_probe, plan


class KernelOffsetTests(unittest.TestCase):
    def setUp(self):
        self.profile = load_profile(DEFAULT_PROFILE)
        self.profile['dump_size'] = '0x1000'
        self.profile['anchors'] = {'text': '0x0', 'data': '0x1000', 'exec': '0x100'}
        site = self.profile['sites']['exec-error-join']
        site['text_offset'] = '0x112'
        self.dump = bytearray(4096)
        self.dump[0x112:0x119] = bytes.fromhex(site['signature'])
        self.dump = bytes(self.dump)
        self.profile['dump_sha256'] = hashlib.sha256(self.dump).hexdigest()
        self.probe = {
            'schema': 1, 'profile': self.profile['id'], 'status': 'site_signature_match',
            'firmware_raw': '0x13600007', 'soc_id': '0x840fd0',
            'kernel_text_va': '0xffffffff90000000', 'kernel_data_va': '0xffffffff90001000',
            'text_offset': '0x112', 'address': '0xffffffff90000112',
            'observed': site['signature'], 'bytes_read': 7, 'trap_supported': False,
            'pid': 42, 'observed_at_unix': 1792310400
        }

    def test_anchor_equivalence_and_no_guessed_runtime(self):
        for anchor, offset in [('text', 0x112), ('exec', 0x12), ('data', -0xeee)]:
            report = plan(self.dump, self.profile, anchor, offset)
            self.assertEqual(report['text_offset'], '0x112')
            self.assertEqual(report['data_offset'], '-0xeee')
            self.assertEqual(report['known_instruction']['name'], 'exec-error-join')
            self.assertIsNone(report['runtime_observation'])
            self.assertFalse(report['trap_supported'])
        report = plan(self.dump, self.profile, 'text', 0x12)
        self.assertIsNone(report['known_instruction'])

    def test_relocates_from_observation_and_labels_unobserved_bytes(self):
        for offset in (0x112, 0x113):
            observation = plan(self.dump, self.profile, 'text', offset, self.probe)['runtime_observation']
            self.assertEqual(observation['address'], hex(0xffffffff90000000+offset))
            self.assertEqual(observation['target_bytes_observed'], offset == 0x112)
            self.assertFalse(observation['whole_kernel_identity_verified'])

    def test_rejects_image_mismatch_bounds_and_ambiguous_anchor(self):
        for dump, anchor, offset in [(self.dump[:-1], 'text', 0), (b'x'*4096, 'text', 0),
                                     (self.dump, 'guess', 0x12), (self.dump, 'text', -1),
                                     (self.dump, 'text', 4096), (self.dump, 'text', True)]:
            with self.subTest(anchor=anchor, offset=offset), self.assertRaises(ValueError):
                plan(dump, self.profile, anchor, offset)
        profile = copy.deepcopy(self.profile)
        profile['sites']['exec-error-join']['signature'] = '00'*7
        with self.assertRaises(ValueError):
            plan(self.dump, profile, 'text', 0x112)

    def test_rejects_failed_or_inconsistent_probe(self):
        changes = {
            'schema': True, 'profile': 'different', 'status': 'page_protected',
            'firmware_raw': '0x12000000', 'soc_id': 0,
            'kernel_text_va': '0xffff000090000000', 'kernel_data_va': '0xffffffff90002000',
            'text_offset': '0x113', 'address': '0xffffffff90000113',
            'observed': '00'*7, 'bytes_read': 6, 'trap_supported': True,
            'pid': 0, 'observed_at_unix': 0
        }
        for key, value in changes.items():
            probe = {**self.probe, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                plan(self.dump, self.profile, 'text', 0x112, probe)

    def test_cli_and_single_record_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            dump, profile, probe = (directory / name for name in ('dump.bin', 'profile.json', 'probe.log'))
            dump.write_bytes(self.dump)
            profile.write_text(json.dumps(self.profile))
            probe.write_text('loader chatter\nKOFFSET_JSON='+json.dumps(self.probe)+'\n')
            self.assertEqual(load_probe(probe), self.probe)
            command = [sys.executable, str(ROOT/'host/kernel_offset.py'), '--dump', str(dump),
                       '--profile', str(profile), '--anchor', 'data', '--offset=-0xeee', '--probe', str(probe)]
            result = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['runtime_observation']['address'], self.probe['address'])
            probe.write_text(probe.read_text()*2)
            result = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn('Traceback', result.stderr)
            profile.write_text('{"schema":true}')
            with self.assertRaises(ValueError):
                load_profile(profile)

    def test_native_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp)/'kernel-offset-test'
            compiler = shlex.split(os.environ.get('HOST_CC', 'cc'))
            subprocess.run([*compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(ROOT/'tests/test_kernel_offset.c'), '-o', str(executable)], check=True)
            subprocess.run([str(executable)], check=True)

    def test_shipped_profile_and_payload_constants_agree(self):
        profile = load_profile(DEFAULT_PROFILE)
        source = (ROOT/'payloads/kernel-offset/backend.h').read_text()
        self.assertIn('"'+profile['id']+'"', source)
        self.assertIn('"'+profile['dump_sha256']+'"', source)
        for key, value in [('KO_TEXT_OFFSET', profile['sites']['exec-error-join']['text_offset']),
                           ('KO_EXEC_ANCHOR', profile['anchors']['exec'])]:
            self.assertIn(f'#define {key} UINT64_C({value})', source)
        self.assertEqual(int(profile['anchors']['exec'], 0)+0xcfc12, int(profile['sites']['exec-error-join']['text_offset'], 0))


if __name__ == '__main__':
    unittest.main()
