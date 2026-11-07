#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run stock GDB against a loopback-only fake target; never a PS5 connection."""
import argparse
import json
import pathlib
import socket
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gdb", required=True)
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    parser.add_argument("--require-description", action="store_true", help="fail if this GDB rejects the FreeBSD target XML")
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory() as tmp:
        folder = pathlib.Path(tmp)
        fixture = folder / "fake-rsp"
        subprocess.run(["cc", "-D_GNU_SOURCE", "-std=c11", "-I", str(ROOT/"payloads/process-debugger"),
                        str(ROOT/"payloads/process-debugger/rsp.c"), str(ROOT/"tests/fake_debug_target.c"),
                        "-o", str(fixture)], check=True)
        report = args.evidence.resolve()/"report.json"
        protocol = args.evidence.resolve()/"rsp.log"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1",0)); listener.listen(1); listener.settimeout(10)
            script = folder/"commands.gdb"
            script.write_text(f"""set confirm off
set pagination off
set architecture i386:x86-64
set remotetimeout 3
source {ROOT}/docs/debugger/compat.gdb
set remotelogfile {protocol}
target extended-remote 127.0.0.1:{listener.getsockname()[1]}
attach 77
source {ROOT}/host/gdb_debugger.py
ps5-report {report} --stack-bytes 64 --code-bytes 0
python assert gdb.selected_inferior().connection is not None
detach
quit
""")
            with (args.evidence/"gdb.log").open("w") as output:
                gdb = subprocess.Popen([args.gdb,"-nx","-q","--batch","-x",str(script)],stdout=output,stderr=subprocess.STDOUT)
                fake = None
                try:
                    connection, _ = listener.accept()
                    with connection:
                        fake = subprocess.Popen([str(fixture),str(connection.fileno())],pass_fds=(connection.fileno(),))
                    gdb.wait(timeout=25)
                    if gdb.returncode:
                        raise RuntimeError(f"GDB returned {gdb.returncode}; see {args.evidence}/gdb.log")
                    if args.require_description:
                        output.flush()
                        assert "Architecture rejected target-supplied description" not in (args.evidence/"gdb.log").read_text()
                    result=json.loads(report.read_text())
                    assert result["status"]=="complete" and result["consistency"]=="same_observed_stop",result["errors"]
                    assert result["selection_restored"] and result["frame_walk"]["heuristic"]
                    assert sum(len(bytes.fromhex(r["data"])) for r in result["memory"] if r["role"]=="stack")==64
                    assert len(result["threads"])==2
                    fake.wait(timeout=5)
                    assert fake.returncode==0
                finally:
                    if gdb.poll() is None: gdb.kill(); gdb.wait()
                    if fake is not None and fake.poll() is None: fake.kill(); fake.wait()
    print("stock GDB same-connection stop report smoke passed")


if __name__ == "__main__":
    main()
