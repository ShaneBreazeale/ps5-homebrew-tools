"""Exercise the cooperative kernel event capture core without a resident/console."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class KernelCaptureTests(unittest.TestCase):
    def test_four_slot_capture_and_ownership(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / 'kernel-capture-test'
            compiler = shlex.split(os.environ.get('HOST_CC', 'cc'))
            subprocess.run([*compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(ROOT / 'tests/test_kernel_capture.c'), '-o', str(executable)], check=True)
            subprocess.run([str(executable)], check=True)


if __name__ == '__main__':
    unittest.main()
