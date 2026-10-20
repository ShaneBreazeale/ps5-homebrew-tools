# SPDX-License-Identifier: GPL-3.0-or-later
from contextlib import redirect_stderr, redirect_stdout
import errno
import io
import json
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from host import session_health as health


class ClassifyTests(unittest.TestCase):
    def test_three_black_session_classes(self):
        dump = health.classify('alive', 'open')
        self.assertEqual(dump['class'], 'loader_ready')
        self.assertFalse(dump['probed_loader'])
        self.assertIn('resident-snapshot', dump['next'])

        elfldr = health.classify('alive', 'refused')
        self.assertEqual(elfldr['class'], 'elfldr_dead')
        self.assertIn('power-hold', elfldr['next'])
        self.assertEqual(health.exit_status(elfldr), 1)

        kernel = health.classify('dead', 'unknown')
        self.assertEqual(kernel['class'], 'kernel_unreachable')
        self.assertIn('power-hold', kernel['next'])
        self.assertEqual(health.exit_status(kernel), 1)

    def test_preflight_does_not_claim_loader_state(self):
        report = health.classify('alive', 'unknown', host='192.0.2.1')
        self.assertEqual(report['class'], 'kernel_answers')
        self.assertEqual(report['loader'], 'unknown')
        self.assertFalse(report['probed_loader'])
        self.assertEqual(health.exit_status(report), 0)
        self.assertIn('do not probe port 9021', report['next'])

    def test_hdmi_two_beep_is_display_sync(self):
        report = health.classify('alive', 'open', hdmi_two_beep=True)
        self.assertEqual(report['class'], 'display_sync')
        self.assertTrue(report['hdmi_two_beep'])
        self.assertIn('Safe Mode', report['next'])

    def test_ping_dead_wins_over_loader_refused(self):
        report = health.classify('dead', 'refused')
        self.assertEqual(report['class'], 'kernel_unreachable')

    def test_connect_timeout_is_silent_loader(self):
        report = health.classify('alive', 'timeout')
        self.assertEqual(report['class'], 'loader_silent')
        self.assertEqual(health.exit_status(report), 1)

    def test_rejects_unknown_tokens(self):
        with self.assertRaises(ValueError):
            health.classify('up', 'unknown')
        with self.assertRaises(ValueError):
            health.classify('alive', 'listening')


class LoaderErrorTests(unittest.TestCase):
    def test_errno_and_message(self):
        self.assertEqual(
            health.loader_from_oserror(OSError(errno.ECONNREFUSED, 'Connection refused')),
            'refused')
        self.assertEqual(health.loader_from_oserror(OSError('Connection refused')), 'refused')
        self.assertEqual(
            health.loader_from_oserror(OSError(errno.ETIMEDOUT, 'timed out')), 'timeout')
        self.assertEqual(
            health.loader_from_oserror(TimeoutError('timed out')), 'timeout')
        self.assertEqual(
            health.loader_from_oserror(OSError(errno.EHOSTUNREACH, 'unreachable')),
            'unreachable')
        self.assertEqual(health.loader_from_oserror(OSError('other')), 'error')
        self.assertEqual(health.loader_from_oserror(None), 'unknown')

    def test_classify_connect_failure_pings_once(self):
        error = OSError(errno.ECONNREFUSED, 'Connection refused')
        pinger = MagicMock(return_value='alive')
        report = health.classify_connect_failure('192.0.2.1', error, pinger=pinger)
        pinger.assert_called_once_with('192.0.2.1')
        self.assertEqual(report['class'], 'elfldr_dead')
        self.assertEqual(report['loader'], 'refused')
        self.assertFalse(report['probed_loader'])


class PingCommandTests(unittest.TestCase):
    def test_platform_commands(self):
        with patch.object(health.platform, 'system', return_value='Darwin'):
            self.assertEqual(health.ping_command('192.0.2.1'),
                             ['ping', '-c', '1', '-t', '2', '192.0.2.1'])
        with patch.object(health.platform, 'system', return_value='Linux'):
            self.assertEqual(health.ping_command('192.0.2.1'),
                             ['ping', '-c', '1', '-W', '2', '192.0.2.1'])

    def test_ping_host_maps_return_codes(self):
        runner = MagicMock(return_value=MagicMock(returncode=0, stdout='', stderr=''))
        self.assertEqual(health.ping_host('192.0.2.1', runner=runner), 'alive')
        runner.assert_called_once()
        self.assertNotIn(9021, runner.call_args[0][0])

        runner.return_value.returncode = 1
        self.assertEqual(health.ping_host('192.0.2.1', runner=runner), 'dead')

        runner.return_value.returncode = 2
        runner.return_value.stderr = 'ping: cannot resolve console.invalid: Unknown host'
        self.assertEqual(health.ping_host('console.invalid', runner=runner), 'unresolved')

        runner.side_effect = subprocess.TimeoutExpired(cmd='ping', timeout=5)
        self.assertEqual(health.ping_host('192.0.2.1', runner=runner), 'unknown')


class CliTests(unittest.TestCase):
    def run_main(self, argv):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            code = health.main(argv)
        return code, output.getvalue()

    @patch.object(health, 'ping_host', return_value='alive')
    def test_preflight_never_opens_a_socket(self, _ping):
        with patch('socket.socket') as sock, patch('socket.create_connection') as create:
            code, text = self.run_main(['--host', '192.0.2.1'])
        self.assertEqual(code, 0)
        self.assertIn('class=kernel_answers', text)
        self.assertIn('loader=unknown', text)
        sock.assert_not_called()
        create.assert_not_called()

    def test_loader_result_skips_guessing_9021(self):
        code, text = self.run_main([
            '--host', '192.0.2.1', '--ping-result', 'alive',
            '--loader-result', 'refused', '--json',
        ])
        self.assertEqual(code, 1)
        report = json.loads(text)
        self.assertEqual(report['class'], 'elfldr_dead')
        self.assertFalse(report['probed_loader'])
        self.assertEqual(report['loader_port'], 9021)

    def test_loader_error_text(self):
        code, text = self.run_main([
            '--host', '192.0.2.1', '--ping-result', 'alive',
            '--loader-error', 'Connection refused',
        ])
        self.assertEqual(code, 1)
        self.assertIn('class=elfldr_dead', text)

    def test_hdmi_flag(self):
        code, text = self.run_main([
            '--host', '192.0.2.1', '--ping-result', 'alive', '--hdmi-two-beep',
        ])
        self.assertEqual(code, 1)
        self.assertIn('class=display_sync', text)

    @patch.object(health, 'ping_host')
    def test_ping_result_skips_icmp(self, ping):
        code, _text = self.run_main([
            '--host', '192.0.2.1', '--ping-result', 'dead',
        ])
        self.assertEqual(code, 1)
        ping.assert_not_called()


if __name__ == '__main__':
    unittest.main()
