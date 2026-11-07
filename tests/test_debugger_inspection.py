"""Exercise real discovery code against bounded sysctl and SDK test doubles."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class InspectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = str(pathlib.Path(cls.tmp.name) / "inspection")
        subprocess.run(["cc", "-D_GNU_SOURCE", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-I", str(ROOT / "tests"), str(ROOT / "tests/test_debugger_inspection.c"),
                        "-o", cls.exe], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_process_metadata_and_refusals(self):
        subprocess.run([self.exe, "metadata"], check=True)

    def test_bounded_map_decoding_and_refusals(self):
        subprocess.run([self.exe, "maps"], check=True)

    def test_sdk_module_lookup_and_refusals(self):
        subprocess.run([self.exe, "modules"], check=True)


if __name__ == "__main__":
    unittest.main()
