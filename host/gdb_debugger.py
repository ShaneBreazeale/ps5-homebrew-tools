# SPDX-License-Identifier: GPL-3.0-or-later
"""Source in GDB: source /absolute/repo/host/gdb_debugger.py.

Uses the existing remote connection only. Explicit commands; no automatic stop
hook, target attach/resume, reconnect or network discovery.
"""
import argparse
import sys
from pathlib import Path
import gdb

sys.path.insert(0, str(Path(__file__).resolve().parent))
from debugger_report import save_report


def number(text):
    return int(text, 0)


def memory_range(text):
    parts = text.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("range must be ADDRESS:LENGTH")
    try:
        return tuple(map(number, parts))
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def parser():
    result = argparse.ArgumentParser(prog="ps5-report", description="Save raw evidence from the current stopped user target.")
    result.add_argument("output")
    result.add_argument("--stack-bytes", type=number, default=4096)
    result.add_argument("--code-bytes", type=number, default=128)
    result.add_argument("--frame-depth", type=int, default=16)
    result.add_argument("--thread-limit", type=int, default=256)
    result.add_argument("--range", type=memory_range, action="append", default=[])
    result.add_argument("--module", action="append", default=[])
    result.add_argument("--max-bytes", type=number, default=1024*1024)
    result.add_argument("--seconds", type=float, default=30)
    result.add_argument("--server-elf")
    result.add_argument("--target-elf")
    return result


class StopReport(gdb.Command):
    def __init__(self):
        super().__init__("ps5-report", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        self.dont_repeat()
        try:
            args = parser().parse_args(gdb.string_to_argv(arg))
        except SystemExit as error:
            if error.code:
                raise gdb.GdbError("invalid ps5-report arguments")
            return
        inferior = gdb.selected_inferior()
        connection = inferior.connection
        if not isinstance(connection, gdb.RemoteTargetConnection) or not hasattr(connection, "send_packet"):
            raise gdb.GdbError("ps5-report requires an existing remote connection with send_packet support")
        if not inferior.pid or any(thread.is_running() for thread in inferior.threads()):
            raise gdb.GdbError("attach and stop the authorized user target before ps5-report")
        try:
            report = save_report(args.output, connection.send_packet, expected_pid=inferior.pid,
                stack_bytes=args.stack_bytes, code_bytes=args.code_bytes, ranges=args.range, modules=args.module,
                frame_depth=args.frame_depth, thread_limit=args.thread_limit, max_bytes=args.max_bytes,
                seconds=args.seconds, server_elf=args.server_elf, target_elf=args.target_elf)
        except (OSError, ValueError) as error:
            raise gdb.GdbError(str(error)) from error
        gdb.write(f"Saved {report['status']} stop report to {args.output}; consistency={report['consistency']}\n")
        if report["selection_restored"] is not True:
            gdb.write("Remote register-thread selection is uncertain; inspect before another command.\n")


StopReport()
