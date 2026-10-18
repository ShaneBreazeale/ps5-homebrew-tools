import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

spec = importlib.util.spec_from_file_location('receive_capture', Path(__file__).resolve().parents[1] / 'host/receive_capture.py')
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)

class Socket:
    def __init__(self, data):
        self.data = io.BytesIO(data)
    def recv(self, n):
        return self.data.read(min(n, 7))

def frame(name, data):
    return struct.pack('<4sIQ', b'FPK1', len(name), len(data)) + name.encode() + data

def transfer(payload=b'example', **changes):
    manifest = dict(status='complete', complete=True, written_bytes=len(payload), expected_bytes=len(payload), crc32_of_written_bytes=f'{zlib.crc32(payload):08x}')
    manifest.update(changes)
    return frame('manifest.json', json.dumps(manifest).encode()) + frame('kernel_text.bin', payload) + struct.pack('<4sIQ', b'END1', 0, 0)

class CaptureTests(unittest.TestCase):
    def test_verified_capture(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'capture'
            result = receiver.receive(Socket(transfer()), out)
            self.assertEqual((out / 'kernel_text.bin').read_bytes(), b'example')
            self.assertEqual(result['kernel_text.bin']['size'], 7)
            self.assertTrue((out / 'transfer.json').exists())
    def assert_rejected(self, data, **kwargs):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'capture'
            with self.assertRaises((ValueError, EOFError)):
                receiver.receive(Socket(data), out, **kwargs)
            self.assertFalse(out.exists())
            self.assertEqual(list(Path(d).iterdir()), [])
    def test_traversal(self):
        for name in ['../escape', '/tmp/escape', 'a/b', 'a\\b']:
            self.assert_rejected(frame(name, b'x'))
    def test_truncation(self):
        data = transfer()
        for size in [0, 1, 15, 30, len(data)-16, len(data)-1]:
            self.assert_rejected(data[:size])
    def test_integrity(self):
        self.assert_rejected(transfer(crc32_of_written_bytes='00000000'))
        self.assert_rejected(transfer(written_bytes=6))
        self.assert_rejected(transfer(complete=False))
        self.assert_rejected(transfer(status='partial'))
    def test_limits_duplicates_trailing(self):
        self.assert_rejected(transfer(), max_bytes=1)
        self.assert_rejected(transfer() + b'extra')
        self.assert_rejected(frame('manifest.json', b'{}') + transfer())
    def test_existing_output(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(FileExistsError):
                receiver.receive(Socket(transfer()), Path(d))

if __name__ == '__main__':
    unittest.main()
