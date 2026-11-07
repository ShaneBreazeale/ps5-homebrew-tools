# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for dev_ctl.py; no SDK or console required.

A fake dev-control server answers one connection, the same way the
payload does: text commands end with OK:/ERR: lines, SHOT answers with
an "OK:SHOT <fmt> <bytes>" header followed by exactly that many bytes.
"""
from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from host import dev_ctl

TOKEN = '0123456789abcdef' * 4


class FakeServer:
    """Serve one canned reply (bytes or a callable) on an ephemeral port."""

    def __init__(self, reply):
        self.reply = reply
        self.received = b''
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(1)
        self.sock.settimeout(2)
        self.errors = []
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.thread.join(timeout=5)
        self.sock.close()
        if self.thread.is_alive():
            raise AssertionError('fake server did not finish')
        if self.errors:
            raise self.errors[0]
        return False

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
            with conn:
                conn.settimeout(2)
                while not self.received.endswith(b'\n'):
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    self.received += chunk
                reply = self.reply(self.received) if callable(self.reply) else self.reply
                conn.sendall(reply)
        except Exception as error:
            self.errors.append(error)


def shot_reply(_received):
    payload = b'\x89PNG\r\n\x1a\n' + bytes(100)
    return b'OK:SHOT png %d\n' % len(payload) + payload


class DevCtlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / 'capture.png'
        self.output = io.StringIO()
        stdout = redirect_stdout(self.output)
        stderr = redirect_stderr(self.output)
        stdout.__enter__()
        stderr.__enter__()
        self.addCleanup(stdout.__exit__, None, None, None)
        self.addCleanup(stderr.__exit__, None, None, None)

    def args(self, port, *command):
        return ['--host', '127.0.0.1', '--token', TOKEN,
                '--port', str(port), '--timeout', '2', *command]

    def test_ping_ok(self):
        with FakeServer(b'OK:PONG\n') as server:
            self.assertEqual(dev_ctl.main(self.args(server.port, 'ping')), 0)
            self.assertEqual(server.received, f'PING {TOKEN}\n'.encode())

    def test_kill_text_reply(self):
        with FakeServer(b'OK:KILLED pid=123 count=1\n') as server:
            reply = dev_ctl.run_text_command('127.0.0.1', server.port, 2,
                                             'KILL eboot.bin', TOKEN)
            self.assertEqual(reply, 'OK:KILLED pid=123 count=1\n')
            self.assertEqual(server.received, f'KILL {TOKEN} eboot.bin\n'.encode())

    def test_default_kill_is_active(self):
        with FakeServer(b'OK:KILLED app=123\n') as server:
            self.assertEqual(dev_ctl.main(self.args(server.port, 'kill')), 0)
            self.assertEqual(server.received, f'KILL {TOKEN} ACTIVE\n'.encode())

    def test_list_final_ok_line_exits_zero(self):
        body = (b'proc pid=1 ppid=0 stat=2 nthr=3 comm=SceShellCore title=\n'
                b'OK:LIST n=1\n\n')
        with FakeServer(body) as server:
            self.assertEqual(dev_ctl.main(self.args(server.port, 'list')), 0)
            self.assertEqual(server.received, f'LIST {TOKEN}\n'.encode())
            self.assertIn('OK:LIST n=1', self.output.getvalue())

    def test_comm_containing_ok_list_is_not_success(self):
        for suffix in (b'', b'ERR:QUERY_FAILED\n'):
            with self.subTest(suffix=suffix):
                with FakeServer(b'proc pid=42 comm=OK:LIST title=\n' + suffix) as server:
                    self.assertEqual(dev_ctl.main(self.args(server.port, 'list')), 1)

    def test_only_last_nonempty_line_determines_success(self):
        for reply in (b'OK:LIST n=1\nERR:QUERY_FAILED\n', b'', b' OK:LIST n=1\n'):
            with self.subTest(reply=reply), FakeServer(reply) as server:
                self.assertEqual(dev_ctl.main(self.args(server.port, 'list')), 1)

    def test_shot_saves_png_bytes(self):
        with FakeServer(shot_reply) as server:
            self.assertEqual(dev_ctl.main(self.args(server.port, 'shot',
                                                   '-o', str(self.out))), 0)
            self.assertEqual(self.out.read_bytes(), shot_reply(None).split(b'\n', 1)[1])
            self.assertEqual(server.received, f'SHOT {TOKEN}\n'.encode())

    def test_default_shot_filename_matches_format(self):
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            with FakeServer(b'OK:SHOT jpg 3\nabc') as server:
                self.assertEqual(dev_ctl.main(self.args(server.port, 'shot')), 0)
            self.assertEqual((self.root / 'capture.jpg').read_bytes(), b'abc')
        finally:
            os.chdir(previous)

    def test_shot_error_writes_nothing(self):
        with FakeServer(b'ERR:NO_SCREENSHOT\n') as server:
            self.assertEqual(dev_ctl.main(self.args(server.port, 'shot',
                                                   '-o', str(self.out))), 1)
            self.assertFalse(self.out.exists())

    def test_shot_truncated_is_an_error_and_writes_nothing(self):
        with FakeServer(b'OK:SHOT png 100\nshort') as server:
            self.assertEqual(dev_ctl.main(self.args(server.port, 'shot',
                                                   '-o', str(self.out))), 1)
            self.assertFalse(self.out.exists())
            self.assertIn('truncated transfer', self.output.getvalue())

    @patch.object(dev_ctl, '_connect')
    def test_shot_refuses_to_overwrite(self, connect):
        self.out.write_bytes(b'old')
        self.assertEqual(dev_ctl.main(self.args(9098, 'shot', '-o', str(self.out))), 1)
        self.assertEqual(self.out.read_bytes(), b'old')
        connect.assert_not_called()

    @patch.object(dev_ctl, '_connect')
    def test_shot_refuses_symlink_even_if_dangling(self, connect):
        target = self.root / 'absent'
        self.out.symlink_to(target)
        self.assertEqual(dev_ctl.main(self.args(9098, 'shot', '-o', str(self.out))), 1)
        self.assertTrue(self.out.is_symlink())
        self.assertFalse(target.exists())
        connect.assert_not_called()

    @patch.object(dev_ctl, 'run_shot')
    def test_output_created_during_transfer_is_not_overwritten(self, shot):
        def received(*args):
            self.out.write_bytes(b'created meanwhile')
            return 'png', b'new'
        shot.side_effect = received
        self.assertEqual(dev_ctl.main(self.args(9098, 'shot', '-o', str(self.out))), 1)
        self.assertEqual(self.out.read_bytes(), b'created meanwhile')

    def test_existing_default_output_is_not_overwritten(self):
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            self.out.write_bytes(b'old')
            with FakeServer(shot_reply) as server:
                self.assertEqual(dev_ctl.main(self.args(server.port, 'shot')), 1)
            self.assertEqual(self.out.read_bytes(), b'old')
        finally:
            os.chdir(previous)

    def test_kill_error_exit_code(self):
        for reply in (b'ERR:NOT_FOUND\n', b'ERR:PARTIAL killed=1 failed=1\n',
                      b'ERR:QUERY_FAILED\n', b'ERR:TRUNCATED\n', b'ERR:REFUSED\n'):
            with self.subTest(reply=reply), FakeServer(reply) as server:
                self.assertEqual(dev_ctl.main(self.args(server.port, 'kill', 'nope')), 1)
                self.assertIn(reply.decode().strip(), self.output.getvalue())

    def test_unreachable_host_is_an_error(self):
        # Reserve a port without listening, so no unrelated service is contacted.
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
            with self.assertRaises(dev_ctl.DevControlError):
                dev_ctl.run_text_command('127.0.0.1', port, 1, 'PING', TOKEN)
            self.assertEqual(dev_ctl.main(self.args(port, 'ping')), 1)

    @patch.object(dev_ctl, '_connect')
    def test_invalid_shot_size_is_rejected_before_reading_body(self, connect):
        sock = connect.return_value.__enter__.return_value
        for size in (64 * 1024 * 1024 + 1, 0, -1):
            with self.subTest(size=size):
                header = f'OK:SHOT png {size}\n'.encode()
                sock.reset_mock()
                sock.recv.side_effect = [bytes([byte]) for byte in header]
                with patch.object(dev_ctl, '_read_exact') as body:
                    with self.assertRaisesRegex(dev_ctl.DevControlError, 'SHOT size'):
                        dev_ctl.run_shot('console.invalid', 9098, 2, TOKEN)
                    body.assert_not_called()
                self.assertEqual(sock.recv.call_count, len(header))
                self.assertTrue(all(call.args == (1,) for call in sock.recv.call_args_list))

    def test_incomplete_shot_header_writes_nothing(self):
        with FakeServer(b'OK:SHOT png 3') as server:
            self.assertEqual(dev_ctl.main(self.args(server.port, 'shot',
                                                   '-o', str(self.out))), 1)
            self.assertFalse(self.out.exists())

    @patch.object(dev_ctl, '_connect')
    def test_missing_or_invalid_token_fails_before_connection(self, connect):
        for token in ('', '0' * 63, '0' * 65, 'g' * 64, 'a' * 63 + '\n'):
            with self.subTest(token=token), self.assertRaises(SystemExit):
                dev_ctl.main(['--host', 'console.invalid', '--token', token, 'ping'])
        with self.assertRaises(SystemExit):
            dev_ctl.main(['--host', 'console.invalid', 'ping'])
        connect.assert_not_called()

    @patch.object(dev_ctl, '_connect')
    def test_invalid_port_or_timeout_fails_before_connection(self, connect):
        for option in (['--port', '0'], ['--port', '65536'], ['--timeout', '0'],
                       ['--timeout', 'nan'], ['--timeout', 'inf']):
            with self.subTest(option=option), self.assertRaises(SystemExit):
                dev_ctl.main(['--host', 'console.invalid', '--token', TOKEN,
                              *option, 'ping'])
        connect.assert_not_called()

    @patch.object(dev_ctl, '_connect')
    def test_command_injection_is_not_sent(self, connect):
        for target in ('x\nPING', 'x\rPING', 'x\0'):
            with self.subTest(target=target):
                self.assertEqual(dev_ctl.main(self.args(9098, 'kill', target)), 1)
        connect.return_value.__enter__.return_value.sendall.assert_not_called()

    @patch.object(dev_ctl.time, 'monotonic')
    @patch.object(dev_ctl, '_connect')
    def test_trickling_text_cannot_reset_total_deadline(self, connect, monotonic):
        clock = [0.0]
        monotonic.side_effect = lambda: clock[0]
        sock = connect.return_value.__enter__.return_value

        def trickle(_size):
            clock[0] += 0.4
            return b'x'

        sock.recv.side_effect = trickle
        with self.assertRaisesRegex(dev_ctl.DevControlError, 'deadline'):
            dev_ctl.run_text_command('console.invalid', 9098, 1, 'LIST', TOKEN)
        self.assertEqual(sock.recv.call_count, 3)
        timeouts = [call.args[0] for call in sock.settimeout.call_args_list]
        self.assertLess(timeouts[-1], timeouts[0])

    @patch.object(dev_ctl.time, 'monotonic')
    @patch.object(dev_ctl, '_connect')
    def test_shot_body_shares_header_and_connection_deadline(self, connect, monotonic):
        clock = [0.0]
        monotonic.side_effect = lambda: clock[0]
        sock = connect.return_value.__enter__.return_value
        header = iter(b'OK:SHOT png 4\n')

        def trickle(size):
            if size == 1:
                clock[0] += 0.05
                return bytes([next(header)])
            clock[0] += 0.4
            return b'ab'

        sock.recv.side_effect = trickle
        with self.assertRaisesRegex(dev_ctl.DevControlError, 'deadline'):
            dev_ctl.run_shot('console.invalid', 9098, 1, TOKEN)

    @patch.object(dev_ctl.socket, 'getaddrinfo')
    def test_dns_is_bounded_by_exchange_deadline(self, resolve):
        release = threading.Event()
        resolve.side_effect = lambda *args, **kwargs: release.wait(2) or []
        try:
            with self.assertRaisesRegex(dev_ctl.DevControlError, 'deadline'):
                dev_ctl.run_text_command('console.invalid', 9098, 0.02, 'PING', TOKEN)
        finally:
            release.set()


# Compile the resident against host-only process/SDK stubs. Keep this harness
# here so the port needs no additional source files or build-system changes.
RESIDENT_STUBS = r"""
#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#define CTL_KERN 1
#define KERN_PROC 14
#define sysctl test_sysctl
#define kill test_kill
#define send test_send
#define main resident_main
static const char *test_shot_dir;
int test_sysctl(const int *, unsigned, void *, size_t *, const void *, size_t);
uint32_t kernel_get_fw_version(void);
"""

RESIDENT_CHECKS = r"""
#undef main
static unsigned char records[600 * (MAX_PROCS + 1) + 3];
static size_t records_size;
static int query_failed, queries, signals, fail_pid, module_missing = 1;
static int symbols_missing;
static char output[65536];
static size_t output_size;

uint32_t kernel_get_fw_version(void) { return 0; }
int test_sysctl(const int *mib, unsigned mlen, void *p, size_t *n,
               const void *newp, size_t newlen) {
    (void)mib; (void)mlen; (void)newp; (void)newlen;
    ++queries;
    if (query_failed) { errno = EIO; return -1; }
    if (p) { assert(*n >= records_size); memcpy(p, records, records_size); }
    *n = records_size;
    return 0;
}
int test_kill(pid_t pid, int sig) {
    assert(pid > 1 && pid != getpid() && sig == SIGKILL);
    ++signals;
    if (pid == fail_pid) { errno = EPERM; return -1; }
    return 0;
}
ssize_t test_send(int fd, const void *p, size_t n, int flags) {
    (void)fd; (void)flags;
    assert(output_size + n < sizeof(output));
    memcpy(output + output_size, p, n);
    output_size += n;
    output[output_size] = 0;
    return (ssize_t)n;
}
int sceKernelGetAppInfo(pid_t pid, struct app_info *info) {
    (void)pid;
    memcpy(info->title_id, "PPSA12345", 10);
    return 0;
}
int sceKernelLoadStartModule(const char *name, size_t argc, const void *argv,
                            uint32_t flags, void *opt, int *res) {
    (void)argc; (void)argv; (void)flags; (void)opt; (void)res;
    assert(strcmp(name, "libSceSystemService.sprx") == 0);
    return module_missing ? -1 : 1;
}
static int system_kill(int app) { (void)app; assert(0); return -1; }
int sceKernelDlsym(int handle, const char *name, void **addr) {
    (void)handle;
    if (!symbols_missing && strcmp(name, "sceLncUtilKillApp") == 0)
        *addr = (void *)system_kill;
    return 0;
}
static void deadline(int ms) {
    assert(clock_gettime(CLOCK_MONOTONIC, &g_deadline) == 0);
    g_deadline.tv_nsec += (ms % 1000) * 1000000L;
    g_deadline.tv_sec += ms / 1000 + g_deadline.tv_nsec / 1000000000L;
    g_deadline.tv_nsec %= 1000000000L;
}
static void put32(size_t at, uint32_t value) {
    memcpy(records + at, &value, sizeof(value));
}
static void rows(int count) {
    memset(records, 0, sizeof(records));
    records_size = (size_t)count * 600;
    queries = signals = query_failed = fail_pid = 0;
    for (int i = 0; i < count; ++i) {
        size_t at = (size_t)i * 600;
        put32(at, 600);
        put32(at + PID_OFFSET, 20 + (uint32_t)i);
        put32(at + NTHR_OFFSET, 7);
        memcpy(records + at + COMM_OFFSET, "eboot.bin", 10);
    }
}
static void request(const char *line) {
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    assert(write(fds[0], line, strlen(line)) == (ssize_t)strlen(line));
    shutdown(fds[0], SHUT_WR);
    output[0] = 0;
    output_size = 0;
    deadline(1000);
    handle_client(fds[1]);
    close(fds[0]); close(fds[1]);
}
static void command(const char *verb, const char *target, const char *expected) {
    char line[512];
    snprintf(line, sizeof(line), "%s %s%s%s\n", verb, g_token,
             target ? " " : "", target ? target : "");
    request(line);
    assert(strcmp(output, expected) == 0);
}
static void check_layout(void) {
    for (uint32_t stride = 467; stride < 600; ++stride) {
        rows(1); put32(0, stride); records_size = stride;
        command("LIST", NULL, "ERR:QUERY_FAILED\n");
        command("KILL", "eboot.bin", "ERR:QUERY_FAILED\n");
        assert(signals == 0);
    }
    rows(1); ++records_size;
    command("KILL", "20", "ERR:QUERY_FAILED\n");
    command("LIST", NULL, "ERR:QUERY_FAILED\n");
    rows(1); put32(0, 601);
    command("KILL", "20", "ERR:QUERY_FAILED\n");
    rows(1); query_failed = 1;
    command("KILL", "eboot.bin", "ERR:QUERY_FAILED\n");
    command("LIST", NULL, "ERR:QUERY_FAILED\n");
    rows(MAX_PROCS + 1);
    command("KILL", "20", "ERR:TRUNCATED\n");
    assert(signals == 0);
    char line[128];
    snprintf(line, sizeof(line), "LIST %s\n", g_token);
    request(line);
    assert(strstr(output, "OK:LIST n=513 truncated\n"));
}
static void check_kill(void) {
    rows(2);
    memcpy(records + 600 + COMM_OFFSET, "SceShellCore", 13);
    command("KILL", "PPSA12345", "ERR:REFUSED\n");
    assert(signals == 0);
    rows(2); put32(600 + PID_OFFSET, 1);
    command("KILL", "eboot.bin", "ERR:REFUSED\n");
    assert(signals == 0);
    command("KILL", "1", "ERR:REFUSED\n");
    assert(signals == 0);
    rows(1); put32(PID_OFFSET, (uint32_t)getpid());
    memcpy(records + COMM_OFFSET, "SceShellCore", 13);
    command("KILL", "PPSA12345", "ERR:NOT_FOUND\n");
    assert(signals == 0);
    rows(2); fail_pid = 21;
    command("KILL", "eboot.bin", "ERR:PARTIAL killed=1 failed=1\n");
    assert(signals == 2);
    rows(1); fail_pid = 20;
    command("KILL", "20", "ERR:PARTIAL killed=0 failed=1\n");
    rows(2);
    command("KILL", "eboot.bin", "OK:KILLED pid=20 count=2\n");
    assert(signals == 2);
    rows(1);
    command("KILL", "ACTIVE", "ERR:UNAVAILABLE\n");
    assert(signals == 0 && queries == 0);
    module_missing = 0; symbols_missing = 1;
    command("KILL", "ACTIVE", "ERR:UNAVAILABLE\n");
    symbols_missing = 0;
    command("KILL", "ACTIVE", "ERR:NOT_FOUND\n");
    assert(signals == 0 && queries == 0);
    command("KILL", "PPSA12345", "OK:KILLED pid=20 count=1\n");
    rows(1);
    command("KILL", "PPSA1234", "ERR:NOT_FOUND\n");
    command("KILL", "eboot", "ERR:NOT_FOUND\n");
    command("KILL", "9999999999999999999999999", "ERR:NOT_FOUND\n");
    assert(signals == 0);
}
static void check_auth_and_lines(void) {
    rows(1);
    request("KILL 20\n"); assert(strcmp(output, "ERR:AUTH\n") == 0);
    char line[512];
    snprintf(line, sizeof(line), "KILL %s 20\n", g_token);
    line[5] = line[5] == '0' ? '1' : '0';
    request(line); assert(strcmp(output, "ERR:AUTH\n") == 0);
    assert(signals == 0 && queries == 0);
    snprintf(line, sizeof(line), "KILL %s 20", g_token);
    request(line); assert(output_size == 0 && signals == 0 && queries == 0);
    memset(line, 'x', 300); line[300] = '\n'; line[301] = 0;
    request(line); assert(output_size == 0);
    command("PING", NULL, "OK:PONG\n");
    int fds[2]; char buf[8];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    assert(write(fds[0], "abc", 3) == 3);
    memset(buf, 'x', sizeof(buf)); deadline(20);
    assert(read_line(fds[1], buf, sizeof(buf)) == -1);
    assert(strcmp(buf, "abc") == 0);
    close(fds[0]); close(fds[1]);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    assert(write(fds[0], "12345678\n", 9) == 9);
    memset(buf, 'x', sizeof(buf)); deadline(1000);
    assert(read_line(fds[1], buf, sizeof(buf)) == -1 && buf[7] == 0);
    close(fds[0]); close(fds[1]);
    assert(resident_main() == 7); /* unsupported firmware, never bind */
}
static void check_shot(const char *dir) {
    test_shot_dir = dir;
    command("SHOT", NULL, "OK:SHOT jpg 3\nold");
    struct shot *shots = calloc(MAX_SHOT_ENTRIES, sizeof(*shots));
    assert(shots);
    int count = 0, scanned = 0;
    deadline(1000); scan_shot_dir(dir, 0, shots, &count, &scanned);
    assert(count == 0); /* depth zero must not reach the nested image */
    count = 0; scanned = MAX_SHOT_ENTRIES;
    scan_shot_dir(dir, 3, shots, &count, &scanned);
    assert(count == 0 && scanned == MAX_SHOT_ENTRIES);
    free(shots);
}
int main(int argc, char **argv) {
    assert(argc >= 2);
    assert(make_token() == 0 && strlen(g_token) == 64);
    assert(authenticated(g_token));
    for (size_t i = 0; i < 64; ++i)
        assert((g_token[i] >= '0' && g_token[i] <= '9') ||
               (g_token[i] >= 'a' && g_token[i] <= 'f'));
    if (!strcmp(argv[1], "layout")) check_layout();
    else if (!strcmp(argv[1], "kill")) check_kill();
    else if (!strcmp(argv[1], "auth")) check_auth_and_lines();
    else { assert(argc == 3); check_shot(argv[2]); }
    return 0;
}
"""


class ResidentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name).resolve()
        cls.exe = cls.root / 'resident-check'
        source = (Path(__file__).resolve().parents[1] /
                  'payloads/dev-control/main.c').read_text()
        source = source.replace('#include <ps5/kernel.h>', '')
        source = source.replace('#include <sys/sysctl.h>', '')
        source = source.replace('#define SHOT_DIR "/user/av_contents/photo"',
                                '#define SHOT_DIR test_shot_dir')
        result = subprocess.run(
            ['cc', '-std=c11', '-D_GNU_SOURCE', '-Wall', '-Wextra', '-Werror',
             '-x', 'c', '-', '-o', str(cls.exe)],
            input=RESIDENT_STUBS + source + RESIDENT_CHECKS,
            text=True, capture_output=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)

    def check_resident(self, case, *args):
        result = subprocess.run([str(self.exe), case, *map(str, args)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_layout_failures_and_truncation(self):
        self.check_resident('layout')

    def test_kill_preflight_and_error_accounting(self):
        self.check_resident('kill')

    def test_authentication_incomplete_lines_and_deadline(self):
        self.check_resident('auth')

    def test_shot_depth_symlinks_and_older_usable_file(self):
        photo = self.root / 'photo'
        nested = photo / 'NPXS40087' / 'PPSA12345' / 'abc'
        nested.mkdir(parents=True)
        old = nested / 'old.jpeg'
        old.write_bytes(b'old')
        os.utime(old, (100, 100))
        empty = nested / 'new.png'
        empty.touch()
        os.utime(empty, (200, 200))
        large = nested / 'large.jpg'
        with large.open('wb') as file:
            file.truncate(dev_ctl.MAX_SHOT_BYTES + 1)
        os.utime(large, (300, 300))
        external = self.root / 'outside'
        external.mkdir()
        (external / 'secret.png').write_bytes(b'secret')
        (nested / 'link.png').symlink_to(external / 'secret.png')
        (photo / 'linked-directory').symlink_to(external, target_is_directory=True)
        too_deep = nested / 'deeper'
        too_deep.mkdir()
        (too_deep / 'deep.png').write_bytes(b'deep')
        self.check_resident('shot', photo)


if __name__ == '__main__':
    unittest.main()
