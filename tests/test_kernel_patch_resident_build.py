"""Pinned link inputs and the loader's ELF contract; no SDK or console needed."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tooling'))
import build_kernel_patch_resident as builder
import prepare_kernel_patch_stage2 as prepare
import verify_kernel_patch_stage2 as verify
import test_kernel_patch_stage2 as stage2


def fixture_elf():
    data = bytearray(1024)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, b'\x7fELF\x02\x01\x01' + bytes(9),
                     3, 62, 1, 0x100, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 7, 0, 0, 0, 1024, 2048, 4096)
    struct.pack_into('<IIQQQQQQ', data, 120, 2, 6, 0x200, 0x200, 0, 128, 128, 8)
    tags = [(5, 0x300), (10, 16), (6, 0x320), (11, 24), (7, 0x360), (8, 24), (9, 24), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into('<QQ', data, 0x200 + index * 16, *tag)
    data[0x300:0x310] = b'\0shared_area\0xxx'
    struct.pack_into('<IBBHQQ', data, 0x338, 1, 0x10, 0, 0, 0, 0)
    struct.pack_into('<QQq', data, 0x360, 0x400, (1 << 32) | 6, 0)
    return data


class ResidentBuildTests(unittest.TestCase):
    def test_loader_audit_accepts_only_reviewed_imports(self):
        data = fixture_elf()
        result = builder.audit_elf(data, {'shared_area'})
        self.assertEqual(result['imports'], ['shared_area'])
        self.assertEqual(result['relocations'], {'6': 1})
        with self.assertRaisesRegex(ValueError, 'unexpected resident import'):
            builder.audit_elf(data, set())
        data[0x300:0x310] = b'\0memcpy\0xxxxxxxx'
        with self.assertRaisesRegex(ValueError, 'memcpy'):
            builder.audit_elf(data, {'shared_area'})

    def test_loader_refuses_unsupported_relocations_and_tables(self):
        for info, addend in ((7, 0), (37, 0), (6, 1), ((1 << 32) | 8, 0)):
            with self.subTest(info=info, addend=addend), self.assertRaises(ValueError):
                data = fixture_elf()
                struct.pack_into('<QQq', data, 0x360, 0x400, info, addend)
                builder.audit_elf(data, {'shared_area'})
        for offset, fmt, value in ((0x360, '<Q', 0x1000), (0x238, '<Q', 16),
                                   (0x220 + 8, '<Q', 0x10000), (64 + 40, '<Q', 0x200000),
                                   (64 + 48, '<Q', 16384), (0x338, '<I', 16)):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                data = fixture_elf()
                struct.pack_into(fmt, data, offset, value)
                builder.audit_elf(data, {'shared_area'})
        for size in (0, 64, 128, 900):
            with self.subTest(size=size), self.assertRaises(ValueError):
                builder.audit_elf(fixture_elf()[:size], {'shared_area'})

    def test_loader_rejects_system_loader_features_and_wrong_entry(self):
        for tag in (1, 2, 17, 18, 20, 23, 35, 36, 37):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                data = fixture_elf()
                struct.pack_into('<QQ', data, 0x270, tag, 1)
                builder.audit_elf(data, {'shared_area'})
        data = fixture_elf()
        struct.pack_into('<I', data, 68, 6)
        with self.assertRaisesRegex(ValueError, 'entry point'):
            builder.audit_elf(data, {'shared_area'})
        self.assertTrue(builder.audit_elf(data, {'shared_area'}, False)['loader_subset_checked'])
        data = fixture_elf()
        struct.pack_into('<IBBHQQ', data, 0x338, 1, 0x10, 0, 1, 0x100, 0)
        with self.assertRaisesRegex(ValueError, 'load-bias'):
            builder.audit_elf(data, {'shared_area'})

    def test_object_only_overlay_cannot_be_misreported_as_a_complete_link(self):
        # Reuse the ordinary overlay fixture without requiring real research sources.
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            source, profile = stage2.Stage2Tests().fake_source(folder)
            overlay = folder / 'overlay'
            prepare.prepare(source, overlay, profile)
            manifest_path = overlay / 'manifest.json'
            manifest = json.loads(manifest_path.read_text())
            # A regular overlay has no full dependency inventory and cannot link.
            with self.assertRaisesRegex(ValueError, 'link-inputs'):
                builder.build(overlay, folder / 'build', folder / 'sdk')
            self.assertFalse((folder / 'build').exists())

    def test_complete_overlay_pins_dependencies_and_refuses_changed_inventory(self):
        def git(path, *args):
            return subprocess.check_output(['git', '-C', str(path), *args], stderr=subprocess.DEVNULL)

        def commit(path):
            git(path, 'add', '.')
            git(path, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'link fixture')
            return git(path, 'rev-parse', 'HEAD').decode().strip()

        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            source, profile = stage2.Stage2Tests().fake_source(folder)
            for name in prepare.LINK_EXPORT:
                path = source / name
                if path.is_file():
                    continue
                if name.endswith(('shellcore_hook', 'shellcore_patches')):
                    path = path / 'fixture.c'
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('link fixture\n')
            for name in prepare.LINK_SUBMODULES:
                dependency = source / name
                dependency.mkdir()
                subprocess.run(['git', 'init', '-q', str(dependency)], check=True)
                (dependency / 'fixture.h').write_text('dependency\n')
                commit(dependency)
            profile['commit'] = commit(source)
            overlay = folder / 'full'
            manifest = prepare.prepare(source, overlay, profile, link_inputs=True)
            self.assertEqual(verify.verify(overlay), manifest['build_id'])
            inputs = manifest['identity_inputs']
            self.assertEqual(len(inputs['link_inputs']['submodules']), 2)
            self.assertIn('ps5-kstuff/BearSSL/fixture.h', inputs['sources'])
            extra = overlay / 'source/ps5-kstuff/uelf/unreviewed.c'
            extra.write_text('unreviewed translation unit\n')
            with self.assertRaisesRegex(ValueError, 'unpinned'):
                verify.verify(overlay)
            extra.unlink()
            generated = overlay / 'source/ps5-kstuff/structs.h'
            generated.write_text('changed generated layout\n')
            with self.assertRaisesRegex(ValueError, 'generated structs'):
                verify.verify(overlay)
            generated.write_text('#define field 1\n')
            dependency = overlay / 'source/ps5-kstuff/BearSSL/fixture.h'
            dependency.write_text('changed dependency\n')
            with self.assertRaisesRegex(ValueError, 'source differs'):
                verify.verify(overlay)
            # A dirty submodule contributes only its pinned committed bytes.
            (source / 'ps5-kstuff/BearSSL/fixture.h').write_text('dirty checkout\n')
            other = folder / 'other'
            prepare.prepare(source, other, profile, link_inputs=True)
            self.assertEqual((other / 'source/ps5-kstuff/BearSSL/fixture.h').read_text(), 'dependency\n')

    def test_pinned_symbol_inventory_does_not_admit_arbitrary_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            offsets = folder / 'prosper0gdb/offsets'
            offsets.mkdir(parents=True)
            (offsets / 'offset_list.txt').write_text('KDATA_OFFSET(copyin)\n// KDATA_OFFSET(fake)\n')
            symbols = builder.loader_symbols(folder)
            self.assertIn('copyin', symbols)
            self.assertIn('shared_area', symbols)
            self.assertNotIn('fake', symbols)
            self.assertNotIn('memcpy', symbols)


if __name__ == '__main__':
    unittest.main()
