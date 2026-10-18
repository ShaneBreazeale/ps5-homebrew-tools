#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate the GDB server against its disposable test child, recording evidence."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import socket
import time


class Remote:
    def __init__(self, host, port, transcript):
        self.sock = socket.create_connection((host, port), timeout=5)
        self.sock.settimeout(10)
        self.transcript = transcript

    def close(self):
        self.sock.close()

    def byte(self):
        data = self.sock.recv(1)
        if not data:
            raise ConnectionError("debugger disconnected")
        return data

    def receive(self):
        while self.byte() != b"$":
            pass
        data = bytearray()
        while True:
            c = self.byte()
            if c == b"#":
                break
            data += c
            if len(data) > 8192:
                raise ValueError("oversized response")
        checksum = self.byte() + self.byte()
        if int(checksum, 16) != sum(data) & 255:
            raise ValueError("bad response checksum")
        self.sock.sendall(b"+")
        return data.decode("ascii")

    def request(self, command):
        data = command.encode("ascii")
        self.sock.sendall(b"$" + data + b"#" + f"{sum(data) & 255:02x}".encode())
        if self.byte() != b"+":
            raise ValueError("missing command acknowledgement")
        try:
            response = self.receive()
        except socket.timeout:
            self.sock.sendall(b"\x03")
            try:
                self.receive()
            except (OSError, ValueError):
                pass
            raise
        self.transcript.append({"command": command, "response": response})
        return response


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def validate(host, port, transcript):
    remote = Remote(host, port, transcript)
    attached = spawned = False
    checks = []
    try:
        require("hwbreak+" in remote.request("qSupported:hwbreak+"), "missing hardware support")
        response = remote.request("qPS5:spawn-test")
        require(not response.startswith("E"), f"test-child creation failed: {response}")
        spawned = True
        info = {k: int(v, 16) for k, v in (part.split(":") for part in response.split(";"))}
        pid, pc, watch = info["pid"], info["pc"], info["watch"]
        checks.append("spawn disposable child")

        def attach():
            nonlocal attached
            attached = True  # An error may follow PT_ATTACH but precede enumeration.
            response = remote.request(f"vAttach;{pid:x}")
            require(response.startswith("T") and "thread:" in response, f"attach failed: {response}")

        def ok(command):
            response = remote.request(command)
            require(response == "OK", f"{command}: {response}")

        def counter():
            response = remote.request(f"m{watch:x},8")
            require(len(response) == 16, f"counter read failed: {response}")
            return int.from_bytes(bytes.fromhex(response), "little")

        attach()
        require(remote.request("qAttached") == "1", "not attached")
        threads = remote.request("qfThreadInfo")
        require(threads.startswith("m"), f"thread enumeration failed: {threads}")
        tid = threads[1:].split(",")[0]
        ok("Hg" + tid)
        require(len(remote.request("g")) == 1120, "wrong register packet size")
        checks.append("attach, enumerate threads, read registers")
        saved_rax = remote.request("p0")
        ok("P0=8877665544332211")
        require(remote.request("p0").lower() == "8877665544332211", "register write failed")
        ok("P0=" + saved_rax)
        saved = counter()
        changed = saved ^ 0x12345678
        ok(f"M{watch:x},8:{changed.to_bytes(8, 'little').hex()}")
        require(counter() == changed, "memory write failed")
        ok(f"M{watch:x},8:{saved.to_bytes(8, 'little').hex()}")
        checks.append("register and memory write/read/restore")
        require(remote.request("vCont?") == "vCont;c;s", "vCont negotiation failed")
        response = remote.request("vCont;s:" + tid)
        require(response.startswith("T05"), f"single-step failed: {response}")
        checks.append("instruction single-step")
        debug_registers = remote.request("qPS5:dbregs")
        ok("qPS5:test-hardware")
        for kind, addr, length, reason in ((1, pc, 1, "hwbreak:;"),
                                          (2, watch, 8, f"watch:{watch:x};"),
                                          (4, watch, 8, f"awatch:{watch:x};")):
            ok(f"Z{kind},{addr:x},{length:x}")
            stop = remote.request("c")
            require(stop.startswith("T05") and reason in stop.lower(), f"missing hardware stop: {stop}")
            ok(f"z{kind},{addr:x},{length:x}")
        checks.append("hardware execution, write, and access breakpoints")
        require(remote.request(f"Z3,{watch:x},8") == "", "read-only watchpoint must be unsupported")
        require(remote.request(f"Z2,{watch+1:x},8").startswith("E"), "misaligned watchpoint accepted")
        before = counter()
        ok("D")
        attached = False
        time.sleep(0.05)
        attach()
        require(counter() > before, "child did not run after detach")
        checks.append("detach resumes child; reattach works")
        remote.close()  # Test EOF while attached, then reconnect and attach again.
        time.sleep(0.05)
        remote = Remote(host, port, transcript)
        attached = False
        attach()
        checks.append("disconnect cleanup permits reattachment")
        ok(f"M{info['done']:x},4:01000000")
        ok("D")
        attached = False
        ok("qPS5:finish-test")
        spawned = False
        checks.append("test-child cleanup")
        return {"checks": checks, "test_pid": pid, "threads": threads,
                "initial_debug_registers": debug_registers}
    finally:
        if attached:
            try:
                remote.request("D")
            except (OSError, ValueError):
                pass
        if spawned:
            try:
                remote.request("qPS5:finish-test")
            except (OSError, ValueError):
                pass
        remote.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=1234)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--elf", type=Path, help="record the tested payload's SHA-256")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    report = {"started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "host": args.host, "port": args.port, "outcome": "failed", "transcript": []}
    if args.elf:
        report["payload_sha256"] = hashlib.sha256(args.elf.read_bytes()).hexdigest()
    with args.report.open("x") as output:
        try:
            report.update(validate(args.host, args.port, report["transcript"]))
            report["outcome"] = "passed"
        except Exception as error:
            report["error"] = f"{type(error).__name__}: {error}"
        finally:
            report["ended_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            json.dump(report, output, indent=2)
            output.write("\n")
    print(f"{report['outcome']}: {args.report}")
    if report["outcome"] != "passed":
        print(report["error"])
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
