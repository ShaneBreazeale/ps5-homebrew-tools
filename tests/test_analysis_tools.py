import struct
import subprocess
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'host'))
from analysis_common import elf_loads, load_table
from audit_patches import audit, classify, load_patches
from validate_offsets import validate
from wrap_dump import wrap


class AnalysisTests(unittest.TestCase):
    def test_wrapper_alignment_and_bytes(self):
        data = wrap(b'hello', 0x1003, 0x9000)
        loads = elf_loads(data)
        self.assertEqual(len(loads), 1)
        va, offset, size = loads[0]
        self.assertEqual(offset % 4096, va % 4096)
        self.assertEqual(data[offset:offset+size], b'hello')

    def test_wrapper_bad_inputs(self):
        for args in [(b'', 0), (b'a', -1), (b'ab', (1 << 64)-1), (b'a', 0, None, 3), (b'abc', 0, 1)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                wrap(*args)

    def test_bad_elf(self):
        valid = wrap(b'hello', 0x1000)
        bad_align = bytearray(valid)
        struct.pack_into('<Q', bad_align, 64+48, 3)
        bad_size = bytearray(valid)
        struct.pack_into('<Q', bad_size, 64+32, len(valid)+1)
        for data in (b'', b'garbage', valid[:70], bad_align, bad_size):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                elf_loads(data)

    def test_table_parser(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'table.h'
            path.write_text('DEF(a, -0x10)\nDEF(b, a + 0x20)\n')
            self.assertEqual(load_table(path), {'a': -16, 'b': 16})
            for source in ('DEF(a, a)\n', 'DEF(a, missing)\n', 'DEF(a, __import__("os"))\n', 'DEF(a, 1)\nDEF(a, 2)\n', 'nonsense'):
                path.write_text(source)
                with self.subTest(source=source), self.assertRaises(ValueError):
                    load_table(path)

    def test_signature_bounds_and_missing(self):
        rows = validate(b'\x0f\x32', {'good': 0, 'end': 1, 'data': 2}, 100, 100,
                        {'good': '0f32', 'end': '3200', 'missing': '00'})
        self.assertEqual({r['name']: r['status'] for r in rows},
                         {'good': 'match', 'end': 'outside_capture', 'data': 'outside_capture', 'missing': 'missing'})
        self.assertEqual(validate(b'abc', {'x': 0}, 0, 0, {})[0]['status'], 'unverified')

    def test_patch_shapes(self):
        self.assertEqual(classify(b'\x75\x02', b'\xeb')[0], 'shape_match')
        self.assertEqual(classify(b'\x0f\x85\0\0\0\0', b'\xeb')[0], 'mismatch')
        self.assertEqual(classify(b'\x75\x02', b'\xeb\x04')[0], 'mismatch')
        self.assertEqual(classify(b'\xcc'*8, b'\xc3')[0], 'manual_review')
        rows = audit(wrap(b'\x75\x02', 0x1000), [(0, b'\xeb'), (1, b'\x66\x90')])
        self.assertEqual([r['status'] for r in rows], ['shape_match', 'outside_capture'])

    def test_cli_reports_and_refuses_overwrite(self):
        scripts = Path(__file__).resolve().parents[1] / 'host'
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            dump, output = directory / 'raw.bin', directory / 'wrapped.elf'
            left, right = directory / 'left.json', directory / 'right.json'
            dump.write_bytes(b'abc')
            left.write_text('{"symbol": 1}')
            right.write_text('{"symbol": 2}')
            def run(script, *args):
                return subprocess.run([sys.executable, str(scripts / script), *map(str, args)], capture_output=True, text=True)
            comparison = run('validate_offsets.py', left, '--compare', right)
            self.assertEqual(comparison.returncode, 1)
            self.assertFalse(json.loads(comparison.stdout)['comparison'][0]['equal'])
            result = run('wrap_dump.py', dump, output, '--base', '0x1000')
            self.assertEqual(result.returncode, 0, result.stderr)
            saved = output.read_bytes()
            result = run('wrap_dump.py', dump, output, '--base', '0x1000')
            self.assertEqual(result.returncode, 2)
            self.assertEqual(output.read_bytes(), saved)
            dump.write_bytes(b'not ELF')
            result = run('audit_patches.py', dump, left)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn('Traceback', result.stderr)

    def test_patch_parser_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'patch.h'
            path.write_text('patches[] = {{0x0, "\\xeb", 1}};')
            self.assertEqual(load_patches(path, 'patches'), [(0, b'\xeb')])
            for source in ('patches[] = {{0x0, "\\xeb", 2}};', 'patches[] = {{macro, "\\xeb", 1}};', 'patches[] = {};'):
                path.write_text(source)
                with self.subTest(source=source), self.assertRaises(ValueError):
                    load_patches(path, 'patches')


if __name__ == '__main__':
    unittest.main()
