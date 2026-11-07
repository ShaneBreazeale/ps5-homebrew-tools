#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Capture a stopped user target through an existing request function.

No connection, attach, resume or target write is performed by this module.
GDB integration is in gdb_debugger.py; offline analysis is in debugger_analyze.py.
"""
import datetime
import hashlib
import json
import re
import struct
import time
from pathlib import Path

USER_END = 1 << 47
MAX_BYTES = 16 * 1024 * 1024
MAX_RANGES = 16
PACKET_BYTES = 1024
REG_NAMES = ("rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip "
             "rflags cs ss ds es fs gs").split()


class BudgetError(ValueError):
    pass


class RemoteError(ValueError):
    def __init__(self, errno, packet):
        self.errno, self.packet = errno, packet
        super().__init__(f"{packet}: target errno 0x{errno:x}")


def hexint(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{1,16}", value):
        raise ValueError("invalid hexadecimal integer")
    return int(value, 16)


def fields(response):
    if re.fullmatch(r"E[0-9a-fA-F]{2}", response):
        raise RemoteError(int(response[1:], 16), "inspection")
    result = {}
    for item in response.split(";"):
        key, separator, value = item.partition(":")
        if not separator or not key or key in result:
            raise ValueError("malformed/duplicate reply field")
        result[key] = value
    return result


def user_range(address, length):
    if type(address) is not int or type(length) is not int or not 0 <= address < USER_END or not 0 < length <= USER_END-address:
        raise ValueError("expected a nonempty user address range")
    return address, length


def decode_registers(packet):
    if len(packet) != 1120 or not re.fullmatch(r"[0-9a-fA-F]{328}x{792}", packet):
        raise ValueError("unexpected GP register layout")
    return dict(zip(REG_NAMES, struct.unpack("<17Q7I", bytes.fromhex(packet[:328]))))


class Inspection:
    def __init__(self, request, *, seconds=30, max_bytes=1024*1024, max_requests=32768):
        if not 0 < seconds <= 300 or not 0 < max_bytes <= MAX_BYTES or not 0 < max_requests <= 65536:
            raise ValueError("invalid inspection budget")
        self.request = request
        self.deadline = time.monotonic()+seconds
        self.max_bytes, self.max_requests = max_bytes, max_requests
        self.bytes_requested = 0
        self.transcript = []
        self.transport_failed = False

    def ask(self, packet, *, cleanup=False):
        if not isinstance(packet, str) or not 0 < len(packet) <= 4096 or any(not 32 <= ord(c) < 127 for c in packet):
            raise ValueError("invalid/oversized inspection command")
        if not cleanup and (time.monotonic() >= self.deadline or len(self.transcript) >= self.max_requests):
            raise BudgetError("inspection time/request budget exhausted")
        entry = {"command": packet}
        self.transcript.append(entry)
        try:
            response = self.request(packet)
            if isinstance(response, bytes):
                response = response.decode("ascii")
            if not isinstance(response, str) or len(response) > 8192:
                raise ValueError("invalid/oversized packet response")
        except BaseException as error:
            self.transport_failed = True
            entry["transport_error"] = str(error)
            raise
        entry["response"] = response
        if re.fullmatch(r"E[0-9a-fA-F]{2}", response):
            raise RemoteError(int(response[1:], 16), packet)
        if not response:
            raise ValueError(f"unsupported packet: {packet}")
        return response

    def state(self):
        result = {key: hexint(value) for key, value in fields(self.ask("qPS5:state")).items()}
        for key in ("pid", "stopped", "stop_id", "selected", "thread"):
            if key not in result:
                raise ValueError("incomplete target state")
        return result

    def readv(self, ranges):
        if not ranges or len(ranges) > MAX_RANGES:
            raise ValueError("readv requires 1..16 ranges")
        for address, length in ranges:
            user_range(address, length)
        total = sum(length for _, length in ranges)
        if total > PACKET_BYTES or self.bytes_requested+total > self.max_bytes:
            raise BudgetError("memory byte budget exceeded")
        self.bytes_requested += total
        reply = fields(self.ask("qPS5:readv:" + ";".join(f"{a:x},{n:x}" for a, n in ranges)))
        if set(reply) != {"count", *(f"{i:x}" for i in range(len(ranges)))} or hexint(reply["count"]) != len(ranges):
            raise ValueError("readv result count mismatch")
        results = []
        for i, (address, length) in enumerate(ranges):
            parts = reply[f"{i:x}"].split(",")
            if len(parts) != 3:
                raise ValueError("malformed readv entry")
            error, returned = map(hexint, parts[:2])
            if error > 255 or returned != (0 if error else length) or len(parts[2]) != 2*returned or not re.fullmatch(r"[0-9a-fA-F]*", parts[2]):
                raise ValueError("invalid/partial readv entry")
            data = bytes.fromhex(parts[2])
            results.append({"address": address, "requested": length, "errno": error,
                            "data": data.hex(), "sha256": hashlib.sha256(data).hexdigest() if not error else None})
        return results

    def memory(self, ranges, *, output=None):
        """Ranges are (address, length, metadata). Preserve every failed chunk."""
        total = sum(length for _, length, _ in ranges)
        if total+self.bytes_requested > self.max_bytes:
            raise BudgetError("memory byte budget exceeded")
        chunks = []
        for address, length, metadata in ranges:
            user_range(address, length)
            while length:
                size = min(length, PACKET_BYTES, 4096-(address & 4095))
                chunks.append((address, size, metadata))
                address += size
                length -= size
        if output is None:
            output = []
        first = len(output)
        i = 0
        while i < len(chunks):
            batch, amount = [], 0
            while i < len(chunks) and len(batch) < MAX_RANGES and amount+chunks[i][1] <= PACKET_BYTES:
                batch.append(chunks[i]); amount += chunks[i][1]; i += 1
            output.extend(dict(result, **meta) for result, (_, _, meta) in zip(
                self.readv([(a, n) for a, n, _ in batch]), batch))
        return output[first:]


def process_info(reply):
    info = fields(reply)
    for name in ("pid", "ppid", "start_sec", "start_usec", "fields", "app_id", "app_type"):
        info[name] = hexint(info[name])
    for name in ("name", "path", "title"):
        info[name] = bytes.fromhex(info[name]).decode("utf-8", "replace")
    return info


def collect_maps(session):
    result, fingerprint, total = [], None, None
    for i in range(2048):
        item = fields(session.ask(f"qPS5:maps:{i:x}"))
        for key in ("index", "count", "snapshot", "start", "end", "offset", "permissions", "truncated"):
            item[key] = hexint(item[key])
        if item["index"] != i or not 0 < item["count"] <= 2048 or item["start"] >= item["end"] or item["end"] > USER_END:
            raise ValueError("invalid map entry")
        if i == 0:
            total, fingerprint = item["count"], item["snapshot"]
        if item["count"] != total or item["snapshot"] != fingerprint or (result and item["start"] < result[-1]["end"]):
            raise ValueError("mapping list changed during capture")
        item["name"] = bytes.fromhex(item["name"]).decode("utf-8", "replace")
        result.append(item)
        if len(result) == total:
            return {"status": "ok", "fingerprint": fingerprint, "items": result}
    raise ValueError("mapping count exceeded limit")


def heuristic_frames(session, rbp, rsp, depth, memory, thread):
    frames, seen, reason = [], set(), "depth_limit"
    for _ in range(depth):
        if not rbp:
            reason = "end_of_chain"; break
        if rbp in seen:
            reason = "cycle"; break
        if rbp & 7 or rbp < rsp or rbp > min(USER_END-16, rsp+1024*1024):
            reason = "invalid_frame_pointer"; break
        seen.add(rbp)
        row = dict(session.readv([(rbp, 16)])[0], role="frame_record", thread=thread)
        memory.append(row)
        if row["errno"]:
            reason = "unreadable_frame"; break
        saved, returned = struct.unpack("<QQ", bytes.fromhex(row["data"]))
        frames.append({"rbp": rbp, "saved_rbp": saved, "return_address": returned})
        if returned >= USER_END:
            reason = "invalid_return_address"; break
        if saved and saved <= rbp:
            reason = "cycle" if saved in seen else "nonincreasing_frame_pointer"; break
        rbp = saved
    return {"method": "rbp_chain", "heuristic": True, "unwind_verified": False,
            "limitation": "Frame pointers may be omitted; these candidates are not a proven call stack.",
            "frames": frames, "stop_reason": reason}


def file_identity(path):
    if path is None:
        return None
    path = Path(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""):
            digest.update(block)
    return {"path": str(path.resolve()), "sha256": digest.hexdigest(), "match_verified": False}


def capture_report(request, *, expected_pid, stack_bytes=4096, code_bytes=128, ranges=(),
                   modules=(), frame_depth=16, thread_limit=256, seconds=30,
                   max_bytes=1024*1024, server_elf=None, target_elf=None):
    """Capture only an already attached/stopped target, retaining raw evidence.

    Report errors/partial data survive; transport failure causes no further packets.
    Successful checks establish one observed stop, not atomic shared-memory state.
    """
    if type(expected_pid) is not int or not 1 < expected_pid <= 0x7fffffff or not 0 <= stack_bytes <= 65536 or not 0 <= code_bytes <= 4096 or not 0 <= frame_depth <= 64 or not 1 <= thread_limit <= 256:
        raise ValueError("invalid capture limits/PID")
    if len(ranges) > 64 or len(modules) > 64:
        raise ValueError("too many ranges/modules")
    for address, length in ranges:
        user_range(address, length)
    for name in modules:
        if not isinstance(name, str) or not 1 <= len(name) <= 255 or "/" in name or any(not 32 <= ord(c) < 127 for c in name):
            raise ValueError("module must be a printable ASCII basename of at most 255 bytes")
    if sum(n for _, n in ranges)+stack_bytes+code_bytes+frame_depth*16 > max_bytes:
        raise ValueError("capture plan exceeds byte budget")
    identities = {"server_elf": file_identity(server_elf), "target_elf": file_identity(target_elf)}
    session = Inspection(request, seconds=seconds, max_bytes=max_bytes)
    report = {"schema": 1, "kind": "ps5-user-stop", "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "expected_pid": expected_pid, "files": identities, "status": "partial", "consistency": "unknown",
              "memory_atomic": False, "memory_view": "logical_user_memory_with_software_breakpoint_shadows", "memory": [], "threads": [], "errors": [], "selection_restored": None,
              "limits": {"stack_bytes": stack_bytes, "code_bytes": code_bytes, "frame_depth": frame_depth,
                         "thread_limit": thread_limit, "max_bytes": max_bytes, "seconds": seconds}}
    selected, changed = None, False
    def optional(name, function):
        try:
            return function()
        except RemoteError as error:
            report["errors"].append({"operation": name, "errno": error.errno})
            return {"status": "unavailable", "errno": error.errno}
        except ValueError as error:
            if session.transport_failed or isinstance(error, BudgetError):
                raise
            report["errors"].append({"operation": name, "message": str(error)})
            return {"status": "invalid", "message": str(error)}
    try:
        caps = fields(session.ask("qPS5:capabilities")); report["capabilities"] = caps
        if hexint(caps["schema"]) != 1 or hexint(caps["implemented"]) & 0x600 != 0x600:
            raise ValueError("server lacks readv/stop identifier support")
        initial = session.state(); report["state_before"] = initial
        if initial["pid"] != expected_pid or not initial["stopped"] or not initial["stop_id"]:
            raise ValueError("expected target is not attached/stopped")
        selected = initial["selected"]
        report["process"] = optional("process", lambda: process_info(session.ask("qPS5:process")))
        report["maps"] = optional("maps", lambda: collect_maps(session))
        report["modules"] = [{"name": name, "result": optional("module:"+name,
            lambda name=name: fields(session.ask("qPS5:module:"+name.encode("ascii").hex())))} for name in modules]
        listing = session.ask("qfThreadInfo")
        if not listing.startswith("m"):
            raise ValueError("unexpected thread list")
        tids = [hexint(tid) for tid in listing[1:].split(",")]
        if not tids or len(tids) > 256 or len(set(tids)) != len(tids) or selected not in tids:
            raise ValueError("invalid target thread list")
        ordered = [selected]+[tid for tid in tids if tid != selected]
        report["threads_omitted"] = ordered[thread_limit:]
        for tid in ordered[:thread_limit]:
            if tid != selected or changed:
                changed = True
                if session.ask(f"Hg{tid:x}") != "OK":
                    raise ValueError("thread selection failed")
            registers = optional("registers", lambda: decode_registers(session.ask("g")))
            report["threads"].append({"tid": tid, "registers": registers})
        chosen = report["threads"][0]["registers"]
        tasks = [(a, n, {"role": "requested"}) for a, n in ranges]
        if "rsp" in chosen and stack_bytes:
            tasks.insert(0, (chosen["rsp"], stack_bytes, {"role": "stack", "thread": selected}))
        if "rip" in chosen and code_bytes:
            tasks.insert(0, (chosen["rip"], code_bytes, {"role": "code", "thread": selected}))
        session.memory(tasks, output=report["memory"])
        if frame_depth and "rbp" in chosen and "rsp" in chosen:
            report["frame_walk"] = heuristic_frames(session, chosen["rbp"], chosen["rsp"], frame_depth, report["memory"], selected)
        final = session.state(); report["state_after"] = final
        if final["pid"] != initial["pid"] or final["stop_id"] != initial["stop_id"] or not final["stopped"]:
            report["consistency"] = "changed"
            raise ValueError("target stop changed during capture")
        report["consistency"] = "same_observed_stop"
        failed_reads = sum(bool(row["errno"]) for row in report["memory"])
        report["status"] = "partial" if report["errors"] or failed_reads or report["threads_omitted"] else "complete"
    except (Exception, KeyboardInterrupt) as error:
        report["errors"].append({"operation": "capture", "message": str(error)})
    finally:
        if selected is not None:
            if not changed:
                report["selection_restored"] = True
            elif not session.transport_failed:
                try:
                    report["selection_restored"] = session.ask(f"Hg{selected:x}", cleanup=True) == "OK"
                except Exception as error:
                    report["errors"].append({"operation": "restore_selection", "message": str(error)})
            if not report["selection_restored"]:
                report["status"] = "partial"
        report["bytes_requested"] = session.bytes_requested
        report["transcript"] = session.transcript
    return report


def save_report(path, request, **options):
    # Reserve the output before touching a target; never overwrite evidence.
    with Path(path).open("x") as stream:
        report = capture_report(request, **options)
        json.dump(report, stream, indent=2); stream.write("\n")
    return report
