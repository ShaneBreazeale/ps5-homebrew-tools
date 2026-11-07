"""Stage 2 bootstrap, authenticated syscall bridge and real SDK entry-point logic."""
import copy
import hashlib
import struct
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'host'))
import kernel_patch as kp


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tooling' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


prepare = module('prepare_kernel_patch_stage2')
verify = module('verify_kernel_patch_stage2')


class Stage2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.folder.cleanup)
        folder = Path(cls.folder.name)
        (folder / 'kp_stage2_config.h').write_text('#define KPS2_BUILD_BYTES {2}\n#define KPS2_TOKEN_BYTES {3}\n')
        (folder / 'ps5').mkdir()
        (folder / 'ps5/kernel.h').write_text('''#include <stdint.h>
uint32_t kernel_get_fw_version(void);
extern const intptr_t KERNEL_ADDRESS_TEXT_BASE, KERNEL_ADDRESS_DATA_BASE;
''')
        cls.executable = folder / 'stage2-native'
        compiler = shlex.split(os.environ.get('HOST_CC', 'cc'))
        subprocess.run([*compiler, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-I', str(folder), str(ROOT / 'tests/test_kernel_patch_stage2.c'),
                        '-o', str(cls.executable)], check=True)

    def test_bootstrap_bridge_client_and_permission_checks(self):
        subprocess.run([str(self.executable)], check=True, timeout=15)

    def test_actual_payload_entry_point_preserves_queries_without_credential(self):
        result = subprocess.run([str(self.executable), 'payload'], check=True, capture_output=True,
                                text=True, timeout=15)
        self.assertTrue(result.stdout.startswith('KP_STAGE2_JSON='))
        record = json.loads(result.stdout.split('=', 1)[1])
        self.assertEqual(record['status'], 'identity_match')
        self.assertFalse(record['write_enabled'])
        self.assertEqual(len(record['queries']), 2)
        reports = [kp.decode_probe_reply(bytes.fromhex(q['reply']), bytes.fromhex(q['request']))
                   for q in record['queries']]
        self.assertNotEqual(reports[0]['challenge'], reports[1]['challenge'])
        self.assertEqual(reports[0]['identity'], reports[1]['identity'])
        self.assertEqual(reports[0]['identity']['capabilities'], 1)
        self.assertNotIn('03' + '00' * 31, result.stdout)
        denied = subprocess.run([str(self.executable), 'payload-denied'], capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(denied.returncode, 1)
        record = json.loads(denied.stdout.split('=', 1)[1])
        self.assertEqual(record['status'], 'transport_error')
        self.assertEqual(len(record['queries']), 1)
        self.assertFalse(record['queries'][0]['transport_ok'])

    def stage2_record(self, mode='payload'):
        result = subprocess.run([str(self.executable), mode], capture_output=True, text=True, timeout=15)
        return result.stdout, json.loads(result.stdout.split('=', 1)[1])

    def test_saved_stage2_observation_checks_two_exchanges_and_environment(self):
        _, record = self.stage2_record()
        build = '02' + '00' * 31
        report = kp.decode_stage2_record(record, build)
        self.assertTrue(report['adapter_identity_checked'])
        self.assertFalse(report['present_readiness_verified'])
        self.assertFalse(report['write_enabled'])
        for key, value in [('firmware', '0x14000000'), ('soc', 1), ('text_base', 0),
                           ('write_enabled', True), ('queries', [record['queries'][0]]), ('schema', True)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                kp.decode_stage2_record({**record, key: value}, build)
        bad = copy.deepcopy(record)
        bad['queries'][1] = copy.deepcopy(bad['queries'][0])
        with self.assertRaisesRegex(ValueError, 'challenge'):
            kp.decode_stage2_record(bad, build)
        bad = copy.deepcopy(record)
        binary = bytearray.fromhex(bad['queries'][1]['reply'])
        struct.pack_into('<Q', binary, 56, 2)  # changed generation
        bad['queries'][1]['reply'] = binary.hex()
        with self.assertRaisesRegex(ValueError, 'identity/challenge'):
            kp.decode_stage2_record(bad, build)
        with self.assertRaisesRegex(ValueError, 'pinned build'):
            kp.decode_stage2_record(record, '03' + '00' * 31)
        _, denied = self.stage2_record('payload-denied')
        self.assertFalse(kp.decode_stage2_record(denied, build)['adapter_identity_checked'])

    def test_stage2_saved_log_cli_and_duplicate_record_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            log, _ = self.stage2_record()
            (folder / 'payload.log').write_text(log)
            cmd = [sys.executable, str(ROOT / 'host/kernel_patch.py'), 'stage2-decode',
                   '--log', str(folder / 'payload.log'), '--build', '02' + '00' * 31,
                   '--output', str(folder / 'report.json')]
            subprocess.run(cmd, check=True, capture_output=True)
            report = json.loads((folder / 'report.json').read_text())
            self.assertTrue(report['adapter_identity_checked'])
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 2)
            (folder / 'duplicate.log').write_text(log + log)
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                kp.load_stage2_log(folder / 'duplicate.log')
            (folder / 'bad.json.log').write_text('KP_STAGE2_JSON={"schema":1,"schema":2}\n')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                kp.load_stage2_log(folder / 'bad.json.log')
            denied, _ = self.stage2_record('payload-denied')
            (folder / 'payload.log').write_text(denied)
            cmd[-1] = str(folder / 'denied.json')
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 1)
            self.assertEqual(json.loads((folder / 'denied.json').read_text())['client_status'], 'transport_error')

    def fake_source(self, folder):
        source = folder / 'base'
        source.mkdir()
        main = ('static int strcmp(const char* a, const char* b)\n'
                'if(!strcmp(symbols[i], name))\n!strcmp(symbols[i]+1, name)\n'
                'void notify(const char* s)\n'
                '    uint64_t percpu_ist4[NCPUS];\n'
                '#endif\n    }\n\n    //kmemzero((char*)(IDT+16*1), 16);\n'
                '#ifndef DEBUG\n\n    const char *console_type\n')
        shared = ('#include <stdint.h>\n    struct kstuff_msg_log msg_log;\n#endif\n};\n'
                  '== 14064, "unexpected shared_area size"\n'
                  '== 7888, "unexpected non-OBS shared_area size"\n')
        files = {'ps5-kstuff/main.c': main, 'ps5-kstuff/uelf/shared_area.h': shared,
                 'ps5-kstuff/uelf/kekcall.c': 'int handle_kekcall(uint64_t* regs, uint64_t* args, uint32_t nr)\n{\n',
                 'ps5-kstuff/uelf/main.c': 'fixture\n', 'ps5-kstuff/uelf/utils.h': 'fixture\n',
                 'ps5-kstuff/uelf/utils.c': 'fixture\n', 'ps5-kstuff/structs-ps5.inc': '%define field 1\n',
                 'ps5-kstuff/Makefile': 'fixture\n'}
        extras = {'freebsd-headers/sys/errno.h': 'fixture\n', 'prosper0gdb/r0gdb.h': 'fixture\n',
                  'prosper0gdb/offsets.h': 'fixture\n', 'prosper0gdb/offsets/offset_list.txt': 'fixture\n',
                  'gdb_stub/dbg.h': 'fixture\n', 'lib/shellcore-imports.h': 'fixture\n'}
        for name, data in {**files, **extras}.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)
        (source / 'freebsd-headers/errno.h').symlink_to('sys/errno.h')
        subprocess.run(['git', 'init', '-q', str(source)], check=True)
        subprocess.run(['git', '-C', str(source), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(source), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '-qm', 'fixture'], check=True)
        commit = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
        profile = {'schema': 1, 'id': 'test-only', 'commit': commit,
                   'files': {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in files}}
        return source, profile

    def test_private_overlay_pins_source_and_credentials_without_editing_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            source, profile = self.fake_source(folder)
            output = folder / 'overlay'
            first = prepare.prepare(source, output, profile)
            self.assertEqual(verify.verify(output), first['build_id'])
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            config = output / 'client-config/kp_stage2_config.h'
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertEqual(config.read_bytes(), (output / 'source/ps5-kstuff/uelf/kp_stage2/kp_stage2_config.h').read_bytes())
            token_line = next(line for line in config.read_text().splitlines() if 'TOKEN_BYTES' in line)
            token_hex = ''.join(re.findall(r'0x([0-9a-f]{2})', token_line))
            self.assertEqual(len(token_hex), 64)
            self.assertNotIn(token_hex, json.dumps(first))
            self.assertEqual(subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain']), b'')
            second = prepare.prepare(source, folder / 'another', profile)
            self.assertNotEqual(first['build_id'], second['build_id'])
            with self.assertRaisesRegex(ValueError, 'exists'):
                prepare.prepare(source, output, profile)
            config.write_text(config.read_text() + '\n')
            with self.assertRaisesRegex(ValueError, 'config'):
                verify.verify(output)
            (source / 'ps5-kstuff/uelf/utils.c').write_text('dirty\n')
            refused = folder / 'refused'
            with self.assertRaisesRegex(ValueError, 'changed/unreviewed'):
                prepare.prepare(source, refused, profile)
            self.assertFalse(refused.exists())

    def test_overlay_refuses_changed_markers_and_escaping_source_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            source, profile = self.fake_source(folder)
            target = source / 'freebsd-headers/errno.h'
            target.unlink()
            target.symlink_to('/etc/passwd')
            subprocess.run(['git', '-C', str(source), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(source), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit', '-qm', 'bad-link'], check=True)
            profile['commit'] = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
            output = folder / 'refused'
            with self.assertRaisesRegex(ValueError, 'unsafe source symlink'):
                prepare.prepare(source, output, profile)
            self.assertTrue((output / 'INCOMPLETE').is_file())
        with self.assertRaisesRegex(ValueError, 'marker'):
            prepare.patch_sources({'ps5-kstuff/main.c': b'changed source'})


if __name__ == '__main__':
    unittest.main()
