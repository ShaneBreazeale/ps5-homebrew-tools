"""Verify fingerprints invalidate on source/LLVM changes and retain stable mtimes."""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class BuildIdentityTests(unittest.TestCase):
    def test_stable_header_and_source_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            files = ["mk/payloads.mk", "tooling/debugger_build_id.py",
                     "vendor/prosper0gdb/rsp_transport.h", "vendor/prosper0gdb/trap_state.h"]
            files += [str(p.relative_to(ROOT)) for p in (ROOT / "payloads/process-debugger").iterdir()
                      if p.suffix in {".c", ".h"}]
            for name in files:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            output = root / "out/build.h"
            command = [sys.executable, str(root / "tooling/debugger_build_id.py"),
                       "--llvm-version", "18.1.8", "--output", str(output)]
            subprocess.run(command, check=True)
            original, mtime = output.read_bytes(), output.stat().st_mtime_ns
            subprocess.run(command, check=True)
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(output.stat().st_mtime_ns, mtime)
            with (root / "payloads/process-debugger/target.h").open("a") as out:
                out.write("\n/* Different input */\n")
            subprocess.run(command, check=True)
            self.assertNotEqual(output.read_bytes(), original)
            changed = output.read_bytes()
            command[command.index("18.1.8")] = "18.1.9"
            subprocess.run(command, check=True)
            self.assertNotEqual(output.read_bytes(), changed)


if __name__ == "__main__":
    unittest.main()
