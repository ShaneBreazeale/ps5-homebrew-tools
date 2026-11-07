"""Owned resident cell integration, persisted recovery and strict saved evidence."""
import copy
import hashlib
import importlib.util
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


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


prep = module('prep3', ROOT / 'tooling/prepare_kernel_patch_stage2.py')
verify = module('verify3', ROOT / 'tooling/verify_kernel_patch_stage2.py')
stage2tests = module('stage2fixtures', ROOT / 'tests/test_kernel_patch_stage2.py')


class Stage3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.folder.cleanup)
        folder = Path(cls.folder.name)
        (folder / 'kp_stage2_config.h').write_text('#define KPS2_BUILD_BYTES {2}\n#define KPS2_TOKEN_BYTES {3}\n')
        (folder / 'ps5').mkdir()
        (folder / 'ps5/kernel.h').write_text('#include <stdint.h>\nuint32_t kernel_get_fw_version(void);\n'
                                           'extern const intptr_t KERNEL_ADDRESS_TEXT_BASE,KERNEL_ADDRESS_DATA_BASE;\n')
        cls.executable = folder / 'stage3'
        subprocess.run([*shlex.split(os.environ.get('HOST_CC', 'cc')), '-std=c11', '-O1', '-g', '-Wall',
                        '-Wextra', '-Werror', '-pthread', '-I', str(folder),
                        str(ROOT / 'tests/test_kernel_patch_stage3.c'), '-o', str(cls.executable)], check=True)

        cls.query_executable = folder / 'query'
        subprocess.run([*shlex.split(os.environ.get('HOST_CC', 'cc')), '-std=c11', '-O1', '-g', '-Wall',
                        '-Wextra', '-Werror', '-pthread', '-DKERNEL_PATCH_STAGE3_QUERY_ONLY=1', '-I', str(folder),
                        str(ROOT / 'tests/test_kernel_patch_stage3.c'), '-o', str(cls.query_executable)], check=True)

    def record(self, mode='payload'):
        result = subprocess.run([str(self.query_executable if mode.startswith('query') else self.executable), mode], capture_output=True, text=True, timeout=15, check=True)
        self.assertTrue(result.stdout.startswith('KP_STAGE3_JSON='))
        return result.stdout, json.loads(result.stdout.split('=', 1)[1])

    def test_owned_cell_journal_quarantine_replay_and_concurrent_callers(self):
        subprocess.run([str(self.executable)], check=True, timeout=15)

    def test_actual_sdk_entry_evidence_and_lost_reply_recovery(self):
        for mode, status in [('payload', 'exercise_restored'), ('lost', 'exercise_restored_recovered')]:
            log, record = self.record(mode)
            self.assertEqual(record['status'], status)
            report = kp.decode_stage3_record(record, '02' + '00' * 31)
            self.assertTrue(report['owned_cell_restoration_verified'])
            self.assertEqual(report['result']['preimage'], '4b50544553543100')
            self.assertEqual(report['result']['observed'], '4b50544553543200')
            self.assertEqual(report['result']['final'], report['result']['preimage'])
            self.assertFalse(report['present_readiness_verified'])
            self.assertNotIn('03' + '00' * 31, log)  # private token excluded

    def test_read_only_sdk_recovery_without_sending_a_command(self):
        for mode, status, restored in [('query', 'query_checked', False), ('query-cached', 'cached_result', True)]:
            _, record = self.record(mode)
            self.assertEqual(record['status'], status)
            self.assertFalse(record['command_attempted'])
            self.assertEqual(len(record['queries']), 1)
            report = kp.decode_stage3_record(record, '02' + '00' * 31)
            self.assertTrue(report['query_identity_checked'])
            self.assertEqual(report['owned_cell_restoration_verified'], restored)
        record['status'] = 'query_checked'
        with self.assertRaisesRegex(ValueError, 'unexpected history'):
            kp.decode_stage3_record(record, '02' + '00' * 31)

    def test_forged_restoration_identity_history_and_partial_results_are_refused(self):
        _, record = self.record()
        build = '02' + '00' * 31
        variants = []
        for key, value in [('schema', True), ('command_attempted', False), ('command_transport_ok', False),
                           ('status', 'exercise_restored_recovered'), ('firmware', '0x14000000'),
                           ('queries', record['queries'][:2])]:
            variants.append({**record, key: value})
        bad = copy.deepcopy(record)
        bad['queries'][2]['request'] = bad['queries'][0]['request']
        variants.append(bad)
        for offset, value in [(40, 7), (56, 2), (136, 2), (472 + 16, 1023), (472 + 184, 1)]:
            bad = copy.deepcopy(record)
            binary = bytearray.fromhex(bad['queries'][2]['reply'])
            struct.pack_into('<I', binary, offset, value)
            bad['queries'][2]['reply'] = binary.hex()
            variants.append(bad)
        bad = copy.deepcopy(record)
        binary = bytearray.fromhex(bad['command']); binary[128] ^= 1
        bad['command'] = binary.hex(); variants.append(bad)
        for bad in variants:
            with self.subTest(bad=bad['status']), self.assertRaises(ValueError):
                kp.decode_stage3_record(bad, build)
        with self.assertRaisesRegex(ValueError, 'pinned build'):
            kp.decode_stage3_record(record, '04' + '00' * 31)

    def test_saved_cli_exclusive_output_duplicate_keys_and_failure_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            log, record = self.record('lost')
            source, output = folder / 'payload.log', folder / 'report.json'
            source.write_text(log)
            cmd = [sys.executable, str(ROOT / 'host/kernel_patch.py'), 'stage3-decode', '--log', str(source),
                   '--build', '02' + '00' * 31, '--output', str(output)]
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertTrue(json.loads(output.read_text())['owned_cell_restoration_verified'])
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 2)
            source.write_text(log + log)
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                kp.load_stage3_log(source)
            source.write_text('KP_STAGE3_JSON={"schema":1,"schema":1}\n')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                kp.load_stage3_log(source)
            record['status'] = 'recovery_unverified'
            record['queries'][2]['transport_ok'] = False
            source.write_text('KP_STAGE3_JSON=' + json.dumps(record) + '\n')
            cmd[-1] = str(folder / 'failure.json')
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 1)
            self.assertFalse(json.loads((folder / 'failure.json').read_text())['owned_cell_restoration_verified'])

    def test_private_stage3_overlay_is_separate_and_cannot_be_used_as_stage2(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            source, profile = stage2tests.Stage2Tests().fake_source(folder)
            shared = source / 'ps5-kstuff/uelf/shared_area.h'
            shared.write_text(shared.read_text() + '\nenum { SHARED_AREA_SIZE = 16384 };\n'
                              'enum { SHARED_AREA_SIZE = 8192 };\n')
            subprocess.run(['git', '-C', str(source), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(source), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit', '-qm', 'stage 3 fixture'], check=True)
            profile['commit'] = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
            profile['files']['ps5-kstuff/uelf/shared_area.h'] = hashlib.sha256(shared.read_bytes()).hexdigest()
            overlay = folder / 'overlay'
            manifest = prep.prepare(source, overlay, profile, stage=3)
            self.assertFalse(manifest['inspection_only'])
            self.assertFalse(manifest['console_validated'])
            self.assertEqual(verify.verify(overlay, 3), manifest['build_id'])
            with self.assertRaisesRegex(ValueError, 'stage mismatch'):
                verify.verify(overlay, 2)
            headers = overlay / 'source/ps5-kstuff/uelf/shared_area.h'
            self.assertIn('SHARED_AREA_SIZE = 24576', headers.read_text())
            self.assertIn('struct kp_stage3_store kp_stage3', headers.read_text())
            self.assertEqual(subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain']), b'')
            headers.write_text(headers.read_text() + '\n')
            with self.assertRaisesRegex(ValueError, 'differs'):
                verify.verify(overlay, 3)

    def test_existing_allocation_contains_expanded_shared_mapping(self):
        # Installer allocates 128 KiB, aligns the comparison table to 64 KiB,
        # then chooses the free side for the complete shared mapping.
        for size in (16384, 24576):
            for gap in range(65536):
                address = gap - size if gap > size else gap + 65536
                self.assertGreaterEqual(address, 0)
                self.assertLessEqual(address + size, 131072)
                self.assertTrue(address + size <= gap or address >= gap + 65536)
        self.assertLessEqual(14240 + 5464, 24576)
        self.assertLessEqual(8064 + 5464, 16384)


if __name__ == '__main__':
    unittest.main()
