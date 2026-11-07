"""Patch manifests, real C transaction failures and the offline CLI. No console."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'host'))
import kernel_patch as kp


def fixture():
    dump = b'original' + bytes(24)
    manifest = {'schema': 1, 'id': 'synthetic-owned-variable', 'firmware': '0x13600000',
                'soc': '0x840fd0', 'image': {'sha256': hashlib.sha256(dump).hexdigest(),
                'size': len(dump), 'anchors': {'resident': 0, 'data': '-0x1000000'}},
                'patches': [{'id': 'test-variable', 'kind': 'test_data', 'anchor': 'resident',
                             'offset': 0, 'alignment': 8, 'expected': b'original'.hex(),
                             'replacement': b'modified'.hex(), 'undo': b'original'.hex(),
                             'review': 'Synthetic host-owned bytes only.'}]}
    identity = {'schema': 1, 'firmware': '0x13600000', 'soc': '0x840fd0',
                'capabilities': 7, 'generation': 1, 'text_base': '0xffffffff80000000',
                'data_base': '0xffffffff81000000', 'resident_base': '0xffffffff82000000',
                'session': '01' + '00' * 15, 'build': '02' + '00' * 31}
    return manifest, dump, identity


class KernelPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.folder.cleanup)
        cls.native = Path(cls.folder.name) / 'test-kernel-patch'
        cls.simulator = Path(cls.folder.name) / 'kernel-patch-sim'
        compiler = shlex.split(os.environ.get('HOST_CC', 'cc'))
        for source, target in (('tests/test_kernel_patch.c', cls.native),
                               ('tooling/kernel_patch_sim.c', cls.simulator)):
            subprocess.run([*compiler, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
                            str(ROOT / source), '-o', str(target)], check=True)

    def test_native_transactions_policy_rollback_quarantine_replay_and_revert(self):
        subprocess.run([str(self.native)], check=True, timeout=20)

    def wire(self, fault='none', operation='apply'):
        manifest, dump, identity = fixture()
        binary = kp.encode_request(manifest, dump, identity, 'test-variable', 1, operation)
        completed = subprocess.run([str(self.simulator), fault], input=binary + kp.encode_identity(identity)
                                   + dump[:8].ljust(64, b'\0'), capture_output=True, check=True, timeout=10)
        return binary, completed.stdout

    def test_host_codec_and_c_service_agree(self):
        request, binary = self.wire()
        self.assertEqual(len(request), 320)
        result = kp.decode_result(binary)
        self.assertEqual((result['status'], result['state']), ('ok', 'committed'))
        self.assertEqual(result['preimage'], b'original'.hex())
        self.assertEqual(result['observed'], b'modified'.hex())
        self.assertEqual(result['final'], None)
        self.assertIn('complete_saved', result['flags'])
        result = kp.decode_result(self.wire(operation='exercise')[1])
        self.assertEqual((result['status'], result['state']), ('ok', 'restored'))
        self.assertEqual(result['final'], b'original'.hex())
        self.assertEqual(kp.decode_result(self.wire(operation='revert')[1])['status'], 'policy')

    def test_faults_preserve_actual_evidence(self):
        expected = {'original-mismatch': ('mismatch', 'unchanged'),
                    'partial-write': ('write', 'restored'), 'write-error': ('write', 'restored'),
                    'readback-mismatch': ('verify_failed', 'restored'),
                    'restore-failure': ('restore', 'unknown'), 'stale-before': ('stale', 'unchanged'),
                    'stale-after': ('stale', 'unknown'), 'prepare-journal': ('journal', 'unchanged'),
                    'outcome-journal': ('journal', 'restored'), 'complete-journal': ('journal', 'committed'),
                    'mapping-refused': ('mapping', 'unchanged'), 'short-read': ('read', 'unchanged'),
                    'read-error': ('read', 'unchanged'), 'acquire-error': ('acquire', 'unchanged'),
                    'release-error': ('release', 'unknown')}
        for fault, pair in expected.items():
            with self.subTest(fault=fault):
                result = kp.decode_result(self.wire(fault)[1])
                self.assertEqual((result['status'], result['state']), pair)
                if pair[1] == 'restored':
                    self.assertEqual(result['final'], b'original'.hex())
                if fault == 'short-read':
                    self.assertIsNone(result['preimage'])
                if fault == 'stale-after':
                    self.assertNotIn('restore_attempted', result['flags'])

    def test_manifest_identity_and_expected_bytes(self):
        manifest, dump, identity = fixture()
        report = kp.plan(manifest, dump)
        self.assertEqual(report['patches'][0]['capture_offset'], '0x0')
        self.assertFalse(report['live_capability_verified'])
        self.assertFalse(report['whole_kernel_identity_verified'])
        self.assertEqual(kp.plan(dict(reversed(list(manifest.items()))), dump)['manifest_sha256'],
                         report['manifest_sha256'])
        for data in (dump[:-1], b'x' + dump[1:]):
            with self.assertRaises(ValueError):
                kp.plan(manifest, data)
        for key, value in [('schema', True), ('firmware', True), ('soc', -1), ('id', '../bad'),
                           ('patches', []), ('extra', None)]:
            bad = copy.deepcopy(manifest)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                kp.plan(bad, dump)
        for key, value in [('offset', -1), ('offset', 25), ('offset', 1 << 63),
                           ('alignment', 3), ('expected', '0'), ('expected', 'aa' * 65),
                           ('expected', '11' * 8), ('undo', '11' * 8), ('replacement', 'ff'),
                           ('replacement', b'original'.hex()), ('kind', 'unknown'),
                           ('anchor', 'text'), ('review', ''), ('extra', 1)]:
            bad = copy.deepcopy(manifest)
            bad['patches'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                kp.plan(bad, dump)
        bad = copy.deepcopy(manifest)
        duplicate = copy.deepcopy(bad['patches'][0])
        duplicate.update(id='alias', kind='data', anchor='data', offset='0x1000000')
        bad['patches'].append(duplicate)
        with self.assertRaisesRegex(ValueError, 'overlap'):
            kp.plan(bad, dump)
        bad['patches'][1]['id'] = 'test-variable'
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            kp.plan(bad, dump)

    def test_identity_ranges_firmware_and_canonical_addresses(self):
        manifest, dump, identity = fixture()
        for key, value in [('schema', True), ('capabilities', 0), ('capabilities', 2),
                           ('capabilities', 8), ('generation', 0), ('generation', 1 << 64),
                           ('text_base', '0xffff800000000001'), ('resident_base', 0x8000),
                           ('session', '00' * 16), ('build', '00' * 32), ('extra', 1)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                kp.encode_identity({**identity, key: value})
        for key, value in [('firmware', '0x14000000'), ('soc', 1),
                           ('resident_base', '0xffffffffffffffff'),
                           ('resident_base', '0xffffffff82000ffc'), ('data_base', '0xffffffff81001000')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                kp.encode_request(manifest, dump, {**identity, key: value}, 'test-variable', 1, 'apply')
        for seq in (True, -1, 0, 1 << 64):
            with self.subTest(sequence=seq), self.assertRaises(ValueError):
                kp.encode_request(manifest, dump, identity, 'test-variable', seq, 'apply')

    def test_decoder_refuses_malformed_results(self):
        _, binary = self.wire()
        for offset, value in ((0, 2), (4, 1), (8, 99), (12, 99), (16, 1 << 20), (20, 65)):
            bad = bytearray(binary)
            struct.pack_into('<I', bad, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                kp.decode_result(bad)
        bad = bytearray(binary)
        bad[56 + 63] = 1
        with self.assertRaises(ValueError):
            kp.decode_result(bad)
        with self.assertRaises(ValueError):
            kp.decode_result(binary[:-1])

    def probe_wire(self, mode='probe-empty', request=None):
        if request is None:
            request = kp.encode_probe_request(fixture()[2]['build'], '04' + '00' * 15)
        completed = subprocess.run([str(self.native), mode], input=request, capture_output=True,
                                   check=True, timeout=10)
        return request, completed.stdout

    def test_probe_actual_c_wire_identity_and_cached_command(self):
        for mode, sequence, cached in [('probe-empty', 0, False), ('probe-last', 1, True),
                                       ('probe-poisoned', 1, True)]:
            request, binary = self.probe_wire(mode)
            report = kp.decode_probe_reply(binary, request)
            self.assertEqual(len(binary), 720)
            self.assertEqual(report['sequence'], sequence)
            self.assertEqual(report['last_command'] is not None, cached)
            self.assertEqual(report['engine_poisoned'], mode == 'probe-poisoned')
            self.assertEqual(report['adapter_identity_checked'], mode != 'probe-poisoned')
            self.assertFalse(report['present_readiness_verified'])
            self.assertFalse(report['whole_kernel_identity_verified'])
            self.assertEqual(report['identity']['build'], fixture()[2]['build'])
            if cached:
                self.assertEqual(report['last_command']['result']['state'], 'committed')
                self.assertEqual(report['last_command']['request']['operation'], 'apply')
                self.assertEqual(report['last_command']['result']['observed'], b'modified'.hex())

    def test_probe_refuses_wrong_challenge_build_and_inconsistent_cache(self):
        request, binary = self.probe_wire('probe-last')
        for offset, value in [(0, 2), (4, 1), (8, 6), (12, 4), (16, 0xff),
                              (136, 2), (144, 1 << 16), (148, 2),
                              (152 + 16, 2), (472 + 24, 2), (472 + 32, 1),
                              (472 + 56, 0xff), (472 + 120, 0xff)]:
            bad = bytearray(binary)
            struct.pack_into('<I', bad, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                kp.decode_probe_reply(bad, request)
        with self.assertRaisesRegex(ValueError, 'challenge'):
            kp.decode_probe_reply(binary, kp.encode_probe_request(fixture()[2]['build'], '05' + '00' * 15))
        with self.assertRaises(ValueError):
            kp.decode_probe_reply(binary[:-1], request)
        different = kp.encode_probe_request('03' + '00' * 31, '04' + '00' * 15)
        report = kp.decode_probe_reply(self.probe_wire('probe-last', different)[1], different)
        self.assertEqual(report['status'], 'stale')
        self.assertIsNone(report['identity'])
        self.assertIsNone(report['last_command'])
        for payload in [bytes(64), request[:-1]]:
            with self.assertRaises(ValueError):
                kp.decode_probe_reply(binary, payload)

    def test_probe_cli_fresh_queries_and_exclusive_saved_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            base = [sys.executable, str(ROOT / 'host/kernel_patch.py')]
            for name in ['one', 'two']:
                subprocess.run([*base, 'probe-request', '--build', fixture()[2]['build'],
                                '--output', str(folder / name)], check=True, capture_output=True)
            one, two = (folder / 'one').read_bytes(), (folder / 'two').read_bytes()
            self.assertNotEqual(kp.decode_probe_request(one)[0], kp.decode_probe_request(two)[0])
            reply = self.probe_wire('probe-last', one)[1]
            (folder / 'reply').write_bytes(reply)
            cmd = [*base, 'probe-decode', '--request', str(folder / 'one'),
                   '--reply', str(folder / 'reply'), '--output', str(folder / 'report.json')]
            subprocess.run(cmd, check=True, capture_output=True)
            report = json.loads((folder / 'report.json').read_text())
            self.assertTrue(report['adapter_identity_checked'])
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 2)
            bad = [*base, 'probe-decode', '--request', str(folder / 'two'),
                   '--reply', str(folder / 'reply'), '--output', str(folder / 'bad.json')]
            self.assertEqual(subprocess.run(bad, capture_output=True).returncode, 2)
            self.assertFalse((folder / 'bad.json').exists())
            (folder / 'reply').write_bytes(self.probe_wire('probe-poisoned', one)[1])
            failed = [*base, 'probe-decode', '--request', str(folder / 'one'),
                      '--reply', str(folder / 'reply'), '--output', str(folder / 'poisoned.json')]
            self.assertEqual(subprocess.run(failed, capture_output=True).returncode, 1)
            self.assertTrue(json.loads((folder / 'poisoned.json').read_text())['engine_poisoned'])

    def test_generated_policy_compiles_and_pins_reviewed_operation(self):
        manifest, dump, identity = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / 'policy.h').write_bytes(kp.policy_header(manifest, dump))
            (folder / 'policy.c').write_text('#include "policy.h"\nint main(void) {\n    return !(KP_REVIEWED_FIRMWARE == 0x13600000 && KP_REVIEWED_SOC == 0x840fd0\n        && KP_REVIEWED_POLICY_COUNT == 1 && kp_reviewed_policies[0].kind == KP_TEST_DATA\n        && kp_reviewed_policies[0].length == 8 && kp_reviewed_policies[0].expected[0] == \'o\');\n}\n')
            compiler = shlex.split(os.environ.get('HOST_CC', 'cc'))
            subprocess.run([*compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(ROOT),
                            str(folder / 'policy.c'), '-o', str(folder / 'policy')], check=True)
            subprocess.run([str(folder / 'policy')], check=True)

    def test_cli_offline_workflow_and_exclusive_evidence(self):
        manifest, dump, identity = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / 'manifest.json').write_text(json.dumps(manifest))
            (folder / 'identity.json').write_text(json.dumps(identity))
            (folder / 'dump.bin').write_bytes(dump)
            base = [sys.executable, str(ROOT / 'host/kernel_patch.py')]
            common = ['--manifest', str(folder / 'manifest.json'), '--dump', str(folder / 'dump.bin')]
            bind = ['--identity', str(folder / 'identity.json'), '--patch', 'test-variable']
            for command in ('plan', 'policy', 'encode', 'simulate'):
                output = folder / (command + '.out')
                cmd = [*base, command, *common, '--output', str(output)]
                if command not in ('plan', 'policy'):
                    cmd += bind
                if command == 'simulate':
                    cmd += ['--engine', str(self.simulator), '--operation', 'exercise']
                subprocess.run(cmd, check=True, capture_output=True, timeout=10)
                original = output.read_bytes()
                self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 2)
                self.assertEqual(output.read_bytes(), original)
            report = json.loads((folder / 'simulate.out').read_text())
            self.assertTrue(report['simulated'])
            self.assertFalse(report['console_validated'])
            self.assertEqual(report['result']['state'], 'restored')
            bad = [*base, 'simulate', *common, *bind, '--operation', 'apply', '--fault', 'restore-failure',
                   '--engine', str(self.simulator), '--output', str(folder / 'failed.json')]
            self.assertEqual(subprocess.run(bad, capture_output=True, timeout=10).returncode, 1)
            self.assertEqual(json.loads((folder / 'failed.json').read_text())['result']['state'], 'unknown')
            (folder / 'duplicate.json').write_text('{"schema":1,"schema":2}')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                kp.strict_json(folder / 'duplicate.json')


if __name__ == '__main__':
    unittest.main()
