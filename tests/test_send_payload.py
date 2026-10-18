# SPDX-License-Identifier: GPL-3.0-or-later
from contextlib import redirect_stderr, redirect_stdout
import json
import io
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from host import send_payload as sender


class SenderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.elf = self.root / 'test.elf'
        self.data = b'\x7fELF\x02\x01' + bytes(58)
        self.elf.write_bytes(self.data)
        self.log = self.root / 'capture.log'
        self.args = [str(self.elf), '--host', 'console.invalid', '--log', str(self.log)]
        self.output = io.StringIO()
        self.stdout = redirect_stdout(self.output)
        self.stderr = redirect_stderr(self.output)
        self.stdout.__enter__()
        self.stderr.__enter__()
        self.addCleanup(self.stdout.__exit__, None, None, None)
        self.addCleanup(self.stderr.__exit__, None, None, None)

    @patch.object(sender.socket, 'create_connection')
    def test_send_once_and_preserve_raw_output(self, connect):
        connection = MagicMock()
        connect.return_value.__enter__.return_value = connection
        connection.recv.side_effect = [b'ready\n', b'raw\xff\n', b'']
        self.assertEqual(sender.main(self.args), 0)
        connect.assert_called_once_with(('console.invalid', 9021), timeout=8)
        connection.sendall.assert_called_once_with(self.data)
        connection.shutdown.assert_called_once_with(socket.SHUT_WR)
        self.assertEqual(self.log.read_bytes(), b'ready\nraw\xff\n')
        metadata = json.loads(Path(str(self.log) + '.json').read_text())
        self.assertEqual(metadata['transport']['outcome'], 'eof')
        self.assertEqual(metadata['capture']['bytes'], 11)
        self.assertEqual(metadata['payload_execution'], 'unknown')

    @patch.object(sender.socket, 'create_connection')
    def test_existing_capture_prevents_any_connection(self, connect):
        self.log.write_bytes(b'previous capture')
        self.assertEqual(sender.main(self.args), 1)
        connect.assert_not_called()
        self.assertEqual(self.log.read_bytes(), b'previous capture')

    @patch.object(sender.socket, 'create_connection')
    def test_invalid_or_truncated_elf_prevents_any_connection(self, connect):
        for invalid in (b'not an elf', b'\x7fELF\x02\x01'):
            with self.subTest(invalid=invalid):
                self.elf.write_bytes(invalid)
                with self.assertRaises(SystemExit) as error:
                    sender.main(self.args)
                self.assertEqual(error.exception.code, 2)
        connect.assert_not_called()
        self.assertFalse(self.log.exists())

    @patch.object(sender.socket, 'create_connection')
    def test_idle_timeout_keeps_partial_capture_without_resending(self, connect):
        connection = MagicMock()
        connect.return_value.__enter__.return_value = connection
        # socket.timeout is distinct from TimeoutError before Python 3.10.
        connection.recv.side_effect = [b'partial\n', socket.timeout()]
        self.assertEqual(sender.main(self.args), 2)
        connect.assert_called_once()
        connection.sendall.assert_called_once()
        self.assertEqual(self.log.read_bytes(), b'partial\n')
        metadata = json.loads(Path(str(self.log) + '.json').read_text())
        self.assertEqual(metadata['transport']['outcome'], 'idle_timeout')

    @patch.object(sender.socket, 'create_connection')
    def test_existing_manifest_prevents_connection(self, connect):
        sidecar = Path(str(self.log) + '.json')
        sidecar.write_text('preserved')
        self.assertEqual(sender.main(self.args), 1)
        connect.assert_not_called()
        self.assertEqual(sidecar.read_text(), 'preserved')
        self.assertFalse(self.log.exists())

    @patch.object(sender.socket, 'create_connection', side_effect=OSError('unreachable'))
    def test_connection_failure_does_not_retry(self, connect):
        self.assertEqual(sender.main(self.args), 1)
        connect.assert_called_once()

    @patch.object(sender.socket, 'create_connection')
    def test_bad_connection_options_fail_before_connect(self, connect):
        for option in (['--idle-timeout', '0'], ['--idle-timeout', 'nan'],
                       ['--idle-timeout', 'inf'], ['--port', '65536']):
            with self.subTest(option=option), self.assertRaises(SystemExit):
                sender.main(self.args + option)
        connect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
