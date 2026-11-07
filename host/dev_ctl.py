#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Talk to dev-control on TCP 9098 using its per-boot ready-line token.

    python3 host/dev_ctl.py --host CONSOLE --token TOKEN ping
    python3 host/dev_ctl.py --host CONSOLE --token TOKEN list
    python3 host/dev_ctl.py --host CONSOLE --token TOKEN kill PPSA12345
    python3 host/dev_ctl.py --host CONSOLE --token TOKEN shot -o capture.jpg

SHOT reads an existing image under /user/av_contents/photo on the console.
It is not a framebuffer capture. The default kill target, ACTIVE, asks the
system service to stop the running big app.
"""

import argparse
import os
from pathlib import Path
import queue
import re
import socket
import sys
import threading
import time

DEFAULT_PORT = 9098
MAX_SHOT_BYTES = 64 * 1024 * 1024


def port_number(value):
    result = int(value)
    if not 1 <= result <= 65535:
        raise argparse.ArgumentTypeError('port must be between 1 and 65535')
    return result


def positive_timeout(value):
    result = float(value)
    if not 0 < result < float('inf'):
        raise argparse.ArgumentTypeError('timeout must be positive and finite')
    return result


class DevControlError(Exception):
    pass


def token_value(value):
    if not re.fullmatch(r'[0-9a-fA-F]{64}', value):
        raise argparse.ArgumentTypeError('token must contain exactly 64 hex characters')
    return value.lower()


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DevControlError('exchange deadline exceeded')
    return remaining


def _connect(host, port, deadline):
    # getaddrinfo has no timeout. A daemon resolver keeps DNS within the same
    # deadline without leaving a connected socket behind after a timeout.
    answers = queue.Queue(maxsize=1)

    def resolve():
        try:
            answers.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError as error:
            answers.put(error)

    threading.Thread(target=resolve, daemon=True).start()
    try:
        addresses = answers.get(timeout=_remaining(deadline))
    except queue.Empty:
        raise DevControlError('exchange deadline exceeded during DNS') from None
    if isinstance(addresses, OSError):
        raise addresses
    last_error = OSError('no addresses found')
    for family, kind, proto, _canonname, address in addresses:
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(_remaining(deadline))
            sock.connect(address)
            _remaining(deadline)
            return sock
        except OSError as error:
            last_error = error
            sock.close()
        except BaseException:
            sock.close()
            raise
    raise last_error


def _send(sock, command, token, deadline):
    try:
        token = token_value(token)
    except argparse.ArgumentTypeError as error:
        raise DevControlError(str(error)) from error
    if any(c in command for c in '\r\n\0'):
        raise DevControlError('command must be a single line')
    verb, separator, target = command.partition(' ')
    line = f'{verb} {token}' + (f' {target}' if separator else '')
    try:
        data = line.encode('ascii') + b'\n'
    except UnicodeEncodeError:
        raise DevControlError('command must contain ASCII characters') from None
    if len(data) > 256:
        raise DevControlError('command is too long')
    sock.settimeout(_remaining(deadline))
    sock.sendall(data)


def _recv(sock, size, deadline):
    sock.settimeout(_remaining(deadline))
    data = sock.recv(size)
    _remaining(deadline)
    return data


def _read_line(sock, deadline):
    # Read only the header: an invalid size must never trigger a body read.
    line = bytearray()
    while len(line) < 4096:
        char = _recv(sock, 1, deadline)
        if not char:
            raise DevControlError('connection closed before a complete reply line')
        if char == b'\n':
            return line.decode('utf-8', errors='replace').strip()
        line.extend(char)
    raise DevControlError('reply header too long')


def _read_exact(sock, size, deadline):
    data = bytearray()
    while len(data) < size:
        chunk = _recv(sock, min(65536, size - len(data)), deadline)
        if not chunk:
            raise DevControlError(
                f'truncated transfer: received {len(data)}/{size} bytes')
        data.extend(chunk)
    return bytes(data)


def run_text_command(host, port, timeout, command, token):
    """Send one authenticated command within a single exchange deadline."""
    deadline = time.monotonic() + timeout
    try:
        with _connect(host, port, deadline) as sock:
            _send(sock, command, token, deadline)
            chunks = []
            while True:
                chunk = _recv(sock, 65536, deadline)
                if not chunk:
                    break
                chunks.append(chunk)
    except OSError as error:
        raise DevControlError(f'dev-control on {host}:{port}: {error}') from error
    return b''.join(chunks).decode('utf-8', errors='replace')


def run_shot(host, port, timeout, token):
    """Return (format, bytes) for a complete, bounded existing screenshot."""
    deadline = time.monotonic() + timeout
    try:
        with _connect(host, port, deadline) as sock:
            _send(sock, 'SHOT', token, deadline)
            header = _read_line(sock, deadline)
            if header.startswith('ERR:'):
                raise DevControlError(f'PS5: {header}')
            parts = header.split()
            if len(parts) != 3 or parts[0] != 'OK:SHOT' or parts[1] not in ('png', 'jpg'):
                raise DevControlError(f'unexpected SHOT header: {header!r}')
            try:
                size = int(parts[2])
            except ValueError:
                raise DevControlError(f'unexpected SHOT header: {header!r}') from None
            if not 0 < size <= MAX_SHOT_BYTES:
                raise DevControlError(f'unexpected SHOT size: {header!r}')
            return parts[1], _read_exact(sock, size, deadline)
    except OSError as error:
        raise DevControlError(f'dev-control on {host}:{port}: {error}') from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, help='console address or hostname')
    parser.add_argument('--token', required=True, type=token_value,
                        help='64 hex characters from the resident ready line')
    parser.add_argument('--port', type=port_number, default=DEFAULT_PORT,
                        help='dev-control TCP port (default: 9098)')
    parser.add_argument('--timeout', type=positive_timeout, default=30,
                        help='total seconds for the exchange (default: 30)')

    sub = parser.add_subparsers(dest='action', required=True)

    sub.add_parser('ping', help='check the daemon answers')
    sub.add_parser('list', help='list processes (pid, comm, title)')

    kill_p = sub.add_parser('kill', help='kill the active app or a target')
    kill_p.add_argument('target', nargs='?', default='ACTIVE',
                        help="'ACTIVE' (default), a title id such as "
                             'PPSA12345, a numeric pid, or an exact process name')

    shot_p = sub.add_parser('shot', help='fetch the newest system screenshot')
    shot_p.add_argument('-o', '--out', type=Path, default=None,
                        help='output file; default capture.<png|jpg> in the '
                             'current directory')

    args = parser.parse_args(argv)

    try:
        if args.action == 'ping':
            reply = run_text_command(args.host, args.port, args.timeout, 'PING', args.token)
        elif args.action == 'list':
            reply = run_text_command(args.host, args.port, args.timeout, 'LIST', args.token)
        elif args.action == 'kill':
            reply = run_text_command(args.host, args.port, args.timeout,
                                     f'KILL {args.target}', args.token)
        elif args.action == 'shot':
            if args.out and (args.out.exists() or args.out.is_symlink()):
                raise DevControlError(f'output already exists: {args.out}')
            fmt, data = run_shot(args.host, args.port, args.timeout, args.token)
            out = args.out or Path(f'capture.{fmt}')
            fd = os.open(out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(data)
            print(f'[+] Saved {len(data)} bytes ({fmt}) to {out}')
            return 0
    except (DevControlError, OSError) as error:
        print(f'dev_ctl: {error}', file=sys.stderr)
        return 1

    lines = [line for line in reply.splitlines() if line.strip()]
    reply = reply.strip()
    print(f'[PS5] {reply}' if reply else '[PS5] (empty reply)')
    ok = bool(lines) and lines[-1].startswith('OK:')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
