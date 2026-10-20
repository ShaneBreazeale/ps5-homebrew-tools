#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Classify a console session from ping and a real loader send; never probe 9021."""

import argparse
import errno
import json
import platform
import subprocess
import sys

NEXT = {
    'kernel_answers': (
        'send the intended ELF once if a payload is ready; do not probe port 9021'
    ),
    'loader_ready': (
        'if the picture is black after a title launch, send resident-snapshot once; '
        'extra non-kstuff diagnostics may follow; do not send a second kstuff, '
        'process-debugger, or kernel-offset'
    ),
    'elfldr_dead': (
        'power-hold recovery; do not send another ELF into this session'
    ),
    'kernel_unreachable': (
        'power-hold recovery; do not send payloads, process-debugger, '
        'kernel-offset, or a second kstuff'
    ),
    'loader_silent': (
        'do not retry the loader connect; power-hold if elfldr was expected'
    ),
    'loader_error': (
        'preserve the send error; do not probe port 9021 or retry automatically'
    ),
    'host_unresolved': (
        'check the configured address; do not probe port 9021'
    ),
    'ping_unknown': (
        'could not run ping; do not probe port 9021; establish host connectivity another way'
    ),
    'display_sync': (
        'HDMI 2-beep is a display-sync / Safe Mode issue; recover display, '
        'then establish ping and loader from a new send'
    ),
}

RECOVERY_CLASSES = frozenset({
    'elfldr_dead', 'kernel_unreachable', 'loader_silent', 'loader_error',
    'host_unresolved', 'ping_unknown', 'display_sync',
})

LOADER_RESULTS = ('unknown', 'open', 'refused', 'timeout', 'unreachable', 'reset', 'error')
PING_RESULTS = ('alive', 'dead', 'unresolved', 'unknown')

_UNRESOLVED_MARKERS = (
    'unknown host',
    'cannot resolve',
    'name or service',
    'nodename nor servname',
    'not known',
)


def ping_command(host):
    system = platform.system()
    if system == 'Darwin':
        return ['ping', '-c', '1', '-t', '2', host]
    if system == 'Windows':
        return ['ping', '-n', '1', '-w', '2000', host]
    return ['ping', '-c', '1', '-W', '2', host]


def ping_host(host, runner=subprocess.run):
    try:
        completed = runner(
            ping_command(host),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 'unknown'
    if completed.returncode == 0:
        return 'alive'
    text = f'{completed.stdout or ""} {completed.stderr or ""}'.lower()
    if any(marker in text for marker in _UNRESOLVED_MARKERS):
        return 'unresolved'
    return 'dead'


def loader_from_oserror(error):
    if error is None:
        return 'unknown'
    err = getattr(error, 'errno', None)
    if err == errno.ECONNREFUSED:
        return 'refused'
    if err == errno.ETIMEDOUT:
        return 'timeout'
    if err in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN, errno.ENETDOWN):
        return 'unreachable'
    if err == errno.ECONNRESET:
        return 'reset'
    text = str(error).lower()
    if 'connection refused' in text:
        return 'refused'
    if 'timed out' in text or 'timeout' in text:
        return 'timeout'
    if any(marker in text for marker in _UNRESOLVED_MARKERS):
        return 'unresolved'
    return 'error'


def classify(ping, loader='unknown', hdmi_two_beep=False, host=None, loader_port=9021):
    if ping not in PING_RESULTS:
        raise ValueError('unsupported ping result')
    if loader not in LOADER_RESULTS:
        raise ValueError('unsupported loader result')
    if hdmi_two_beep:
        name = 'display_sync'
    elif ping == 'unresolved':
        name = 'host_unresolved'
    elif ping == 'unknown':
        name = 'ping_unknown'
    elif ping == 'dead':
        name = 'kernel_unreachable'
    elif loader == 'refused':
        name = 'elfldr_dead'
    elif loader == 'timeout':
        name = 'loader_silent'
    elif loader == 'open':
        name = 'loader_ready'
    elif loader in ('unreachable', 'reset', 'error'):
        name = 'loader_error'
    else:
        name = 'kernel_answers'
    return {
        'schema': 1,
        'host': host,
        'loader_port': loader_port,
        'ping': ping,
        'loader': loader,
        'class': name,
        'next': NEXT[name],
        'probed_loader': False,
        'hdmi_two_beep': bool(hdmi_two_beep),
    }


def classify_connect_failure(host, error, loader_port=9021, pinger=None):
    if pinger is None:
        pinger = ping_host
    ping = pinger(host)
    loader = loader_from_oserror(error)
    if loader == 'unresolved':
        loader = 'error'
    return classify(ping, loader, host=host, loader_port=loader_port)


def format_report(report):
    return (
        f"session_health: class={report['class']} ping={report['ping']} "
        f"loader={report['loader']}\n"
        f"next: {report['next']}"
    )


def exit_status(report):
    return 1 if report['class'] in RECOVERY_CLASSES else 0


def port_number(value):
    result = int(value)
    if not 1 <= result <= 65535:
        raise argparse.ArgumentTypeError('port must be between 1 and 65535')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, help='console address or hostname')
    parser.add_argument(
        '--port', type=port_number, default=9021,
        help='loader TCP port identity only; this tool never connects to it',
    )
    parser.add_argument(
        '--loader-result', choices=LOADER_RESULTS, default='unknown',
        help='loader state from a send that already ran; default is unknown (not probed)',
    )
    parser.add_argument(
        '--loader-error',
        help='OSError text from a failed send; ignored when --loader-result is not unknown',
    )
    parser.add_argument(
        '--ping-result', choices=PING_RESULTS,
        help='use an already-observed ping result; skip ICMP',
    )
    parser.add_argument(
        '--hdmi-two-beep', action='store_true',
        help='operator saw HDMI black with two beeps (display-sync / Safe Mode)',
    )
    parser.add_argument('--json', action='store_true', help='print the report as JSON')
    args = parser.parse_args(argv)

    loader = args.loader_result
    if loader == 'unknown' and args.loader_error:
        parsed = loader_from_oserror(OSError(args.loader_error))
        loader = 'error' if parsed == 'unresolved' else parsed
    ping = args.ping_result if args.ping_result is not None else ping_host(args.host)
    report = classify(
        ping, loader, hdmi_two_beep=args.hdmi_two_beep,
        host=args.host, loader_port=args.port,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_report(report))
    return exit_status(report)


if __name__ == '__main__':
    raise SystemExit(main())
