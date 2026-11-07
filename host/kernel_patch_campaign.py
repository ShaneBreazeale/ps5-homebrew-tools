#!/usr/bin/env python3
"""Run the deterministic host-only patch fault campaign and preserve its evidence.

No SDK, console connection or deployment. A failed compile/run is retained as a
failed experiment, never converted into a successful campaign with zero cases.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ('tests/kernel_patch_campaign.c', 'tooling/kernel_patch_sim.h',
          'residents/patch/patch.h', 'residents/patch/probe.h', 'host/kernel_patch_campaign.py')
FLAGS = ('-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-UNDEBUG')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def invoke(argv, timeout):
    started = time.monotonic()
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {'argv': argv, 'exit_status': result.returncode, 'timed_out': False,
                'stdout': result.stdout, 'stderr': result.stderr,
                'elapsed_seconds': time.monotonic() - started}
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
        return {'argv': argv, 'exit_status': None, 'timed_out': True,
                'stdout': text(error.stdout), 'stderr': text(error.stderr),
                'elapsed_seconds': time.monotonic() - started}
    except OSError as error:
        return {'argv': argv, 'exit_status': None, 'timed_out': False,
                'stdout': '', 'stderr': str(error), 'elapsed_seconds': time.monotonic() - started}


def campaign(compiler):
    if not compiler or not all(isinstance(arg, str) and arg for arg in compiler):
        raise ValueError('HOST_CC must name a host compiler')
    inputs = {name: sha(ROOT / name) for name in INPUTS}
    report = {'schema': 1, 'hypothesis': 'H1-transfer-fault-containment',
              'observed_at_utc': datetime.now(timezone.utc).isoformat(),
              'environment': {'platform': platform.platform(), 'python': platform.python_version()},
              'source_sha256': inputs, 'compiler': invoke([*compiler, '--version'], 10),
              'scope': 'host_simulation', 'console_validated': False,
              'status': 'unverified', 'result': None}
    if report['compiler']['exit_status'] != 0:
        report['status'] = 'compiler_unavailable'
        return report
    with tempfile.TemporaryDirectory(prefix='kernel-patch-campaign-') as tmp:
        executable = Path(tmp) / 'campaign'
        report['compile'] = invoke([*compiler, *FLAGS, str(ROOT / INPUTS[0]), '-o', str(executable)], 30)
        if report['compile']['exit_status'] != 0:
            report['status'] = 'compile_failed'
            return report
        if not executable.is_file():
            report['status'] = 'executable_missing'
            return report
        report['executable_sha256'] = sha(executable)
        report['run'] = invoke([str(executable)], 30)
        if report['run']['exit_status'] != 0:
            report['status'] = 'run_failed'
            return report
        try:
            result = json.loads(report['run']['stdout'])
        except (ValueError, TypeError):
            report['status'] = 'invalid_result'
            return report
        # The finite documented grid is part of the experiment, not merely an
        # executable's self-reported "pass" string. Refuse incomplete coverage.
        short = 3 * sum(range(1, 65))
        errors = short + 3 * 64
        expected = {'schema': 1, 'lengths': 64, 'operations': 3, 'cases': 44256,
                    'scenarios': {'control': 192, 'primary_short': short, 'primary_error': errors,
                                  'restore_short': short, 'restore_error': errors, 'preimage_short': short,
                                  'readback_short': short, 'restore_check_short': short},
                    'counterexamples': 0}
        if result != expected:
            report['status'] = 'coverage_mismatch'
            report['result'] = result
            return report
        report['result'] = result
    report['source_sha256_after'] = {name: sha(ROOT / name) for name in INPUTS}
    report['status'] = 'passed' if report['source_sha256_after'] == inputs else 'source_changed'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='new evidence JSON file; existing paths are refused')
    args = parser.parse_args()
    handle = None
    try:
        # Reserve the evidence path before invoking a compiler or executable.
        if args.output:
            handle = args.output.open('x')
        report = campaign(shlex.split(os.environ.get('HOST_CC', 'cc')))
        data = json.dumps(report, indent=2) + '\n'
        if handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        print(data, end='')
        return 0 if report['status'] == 'passed' else 1
    except (OSError, ValueError) as error:
        parser.exit(2, f'error: {error}\n')
    finally:
        if handle:
            handle.close()


if __name__ == '__main__':
    raise SystemExit(main())
