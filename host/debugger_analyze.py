#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline wildcard searches and x86-64 cross-references in stop reports/raw bytes."""
import argparse
import hashlib
import json
import re
import time
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
U64 = 1 << 64


def bounded_file(path, maximum):
    with Path(path).open("rb") as stream:
        data = stream.read(maximum+1)
    if len(data) > maximum:
        raise ValueError("input exceeds size limit")
    return data


def segments_from_report(report, *, role=None):
    if report.get("schema") != 1 or report.get("kind") != "ps5-user-stop":
        raise ValueError("unsupported stop report")
    rows = report.get("memory")
    if not isinstance(rows, list) or len(rows) > 32768:
        raise ValueError("invalid report memory list")
    pieces, size = [], 0
    for row in rows:
        if role and row.get("role") != role:
            continue
        address, length, error = row.get("address"), row.get("requested"), row.get("errno")
        if type(address) is not int or type(length) is not int or type(error) is not int or not 0 <= address < U64 or not 0 < length <= 1024 or address+length > U64 or not 0 <= error <= 255:
            raise ValueError("invalid report memory range")
        text = row.get("data")
        if not isinstance(text, str) or len(text) != (0 if error else length*2) or not re.fullmatch(r"[0-9a-fA-F]*", text):
            raise ValueError("invalid report memory bytes")
        if error:
            continue
        size += length
        if size > MAX_BYTES:
            raise ValueError("report memory exceeds analysis limit")
        data = bytes.fromhex(text)
        if row.get("sha256") != hashlib.sha256(data).hexdigest():
            raise ValueError("report memory hash mismatch")
        pieces.append((address, data))
    return merge_segments(pieces)


def merge_segments(pieces):
    merged = []
    for address, data in sorted(pieces):
        if not merged or address > merged[-1][0]+len(merged[-1][1]):
            merged.append((address, bytearray(data))); continue
        start, previous = merged[-1]
        offset = address-start
        overlap = min(len(data), len(previous)-offset)
        if previous[offset:offset+overlap] != data[:overlap]:
            raise ValueError("conflicting overlapping observations; choose a narrower role")
        previous.extend(data[overlap:])
    return [(address, bytes(data)) for address, data in merged]


def select_segments(segments, start=None, length=None):
    if (start is None) != (length is None):
        raise ValueError("start and length must be supplied together")
    if start is None:
        return segments
    if not 0 <= start < U64 or not 0 < length <= MAX_BYTES or start+length > U64:
        raise ValueError("invalid analysis range")
    result = []
    for base, data in segments:
        lo, hi = max(base, start), min(base+len(data), start+length)
        if lo < hi:
            result.append((lo, data[lo-base:hi-base]))
    return result


def compile_pattern(text):
    tokens = text.split()
    if not 1 <= len(tokens) <= 256:
        raise ValueError("pattern must contain 1..256 byte tokens")
    values, masks = bytearray(), bytearray()
    for token in tokens:
        if token == "?":
            token = "??"
        if not re.fullmatch(r"[0-9a-fA-F?]{2}", token):
            raise ValueError("use hex bytes, ??, A? or ?F wildcard tokens")
        value, mask = 0, 0
        for digit in token:
            value <<= 4; mask <<= 4
            if digit != "?":
                value |= int(digit, 16); mask |= 15
        values.append(value); masks.append(mask)
    return bytes(values), bytes(masks)


def analysis_budget(segments, max_results, seconds):
    if not 1 <= max_results <= 100000 or not 0 < seconds <= 300 or sum(len(data) for _, data in segments) > MAX_BYTES:
        raise ValueError("analysis budget exceeded/invalid")
    previous = 0
    for address, data in segments:
        if type(address) is not int or not data or address < previous or address+len(data) > U64:
            raise ValueError("invalid/overlapping analysis segments")
        previous = address+len(data)
    return time.monotonic()+seconds


def mapping_at(address, maps):
    for item in maps:
        if item["start"] <= address < item["end"]:
            return {"name": item["name"], "truncated": bool(item["truncated"]),
                    "mapping_start": item["start"], "object_offset": item["offset"]+address-item["start"]}
    return None


def wildcard_search(segments, pattern, *, max_results=1000, seconds=5, maps=()):
    values, masks = compile_pattern(pattern)
    deadline = analysis_budget(segments, max_results, seconds)
    # Longest literal run supplies a C-level candidate search. Masked nibbles
    # are still verified. Patterns without literal bytes use bounded iteration.
    runs = list(re.finditer(b"\xff+", masks))
    anchor = max(runs, key=lambda m: m.end()-m.start(), default=None)
    results, tested = [], 0
    for base, data in segments:
        end = len(data)-len(values)
        position = 0
        while position <= end:
            if time.monotonic() >= deadline:
                return {"matches": results, "complete": False, "stop_reason": "time_limit", "candidates_tested": tested}
            if anchor:
                found = data.find(values[anchor.start():anchor.end()], position+anchor.start(), end+anchor.end())
                if found < 0:
                    break
                position = found-anchor.start()
            tested += 1
            if all(data[position+i] & mask == value for i, (value, mask) in enumerate(zip(values, masks))):
                address = base+position
                results.append({"address": address, "mapping": mapping_at(address, maps)})
                if len(results) == max_results:
                    return {"matches": results, "complete": False, "stop_reason": "result_limit", "candidates_tested": tested}
            position += 1
    return {"matches": results, "complete": True, "stop_reason": "captured_bytes_exhausted", "candidates_tested": tested}


def instruction_stream(engine, data, base, limit):
    # Capstone materializes a batch before yielding. Bound each C allocation
    # and decode call, so the outer loop can enforce its deadline regularly.
    offset = 0
    while offset < len(data) and limit:
        advanced = count = 0
        for insn in engine.disasm(data[offset:offset+4096], base+offset, count=min(256, limit)):
            advanced += insn.size; count += 1
            yield insn
        if not advanced:
            return
        offset += advanced; limit -= count


def cross_references(segments, *, target=None, max_results=1000, max_instructions=100000, seconds=5):
    deadline = analysis_budget(segments, max_results, seconds)
    if not 1 <= max_instructions <= 1000000 or (target is not None and not 0 <= target < U64):
        raise ValueError("invalid instruction limit/target")
    try:
        import capstone
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP, X86_INS_LEA
    except ImportError as error:
        raise ValueError("cross-references require capstone==5.0.7; see host/requirements-debugger.txt") from error
    if capstone.__version__ != "5.0.7":
        raise ValueError("cross-references require the tested capstone==5.0.7")
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    engine.detail = True
    # Do not resynchronize arbitrary bytes after a decoding failure.
    engine.skipdata = False
    result = {"decoder": "capstone-"+capstone.__version__, "method": "linear_decode_from_supplied_boundaries",
              "references": [], "unresolved_indirect": [], "undecoded": [], "instructions": 0,
              "bytes_decoded": 0, "complete": True, "stop_reason": "captured_bytes_exhausted"}
    for base, data in segments:
        if result["instructions"] == max_instructions:
            result.update(complete=False, stop_reason="instruction_limit"); break
        decoded = 0
        for insn in instruction_stream(engine, data, base, max_instructions-result["instructions"]):
            if time.monotonic() >= deadline:
                result.update(complete=False, stop_reason="time_limit"); return result
            result["instructions"] += 1; result["bytes_decoded"] += insn.size; decoded += insn.size
            control = insn.group(capstone.CS_GRP_CALL) or insn.group(capstone.CS_GRP_JUMP)
            references = []
            direct = False
            for operand in insn.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    offset = (insn.address+insn.size+operand.mem.disp) % U64
                    references.append({"kind": "rip_relative", "target": None if operand.mem.segment else offset,
                        "segment": insn.reg_name(operand.mem.segment) if operand.mem.segment else None,
                        "segment_offset": offset if operand.mem.segment else None,
                        "target_role": "pointer_slot" if control else "address" if insn.id == X86_INS_LEA else "memory",
                        "operand_access": operand.access})
                elif control and operand.type == X86_OP_IMM:
                    direct = True
                    references.append({"kind": "direct_call" if insn.group(capstone.CS_GRP_CALL) else "direct_branch",
                                       "target": operand.imm % U64, "target_role": "instruction"})
            for ref in references:
                if target is None or ref["target"] == target:
                    result["references"].append(dict(ref, address=insn.address, size=insn.size,
                        bytes=bytes(insn.bytes).hex(), mnemonic=insn.mnemonic, operands=insn.op_str))
                    if len(result["references"]) == max_results:
                        result.update(complete=False, stop_reason="result_limit"); return result
            if control and not direct:
                result["unresolved_indirect"].append({"address": insn.address, "mnemonic": insn.mnemonic,
                    "operands": insn.op_str, "reason": "callee_requires_memory_or_register_state"})
                if len(result["unresolved_indirect"]) >= max_results:
                    result.update(complete=False, stop_reason="unresolved_limit"); return result
        if decoded < len(data):
            result["undecoded"].append({"address": base+decoded, "length": len(data)-decoded})
            result["complete"] = False
            result["stop_reason"] = "instruction_limit" if result["instructions"] == max_instructions else "decode_stopped"
            if result["instructions"] == max_instructions:
                break
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    for name in ("search", "xrefs"):
        command = sub.add_parser(name)
        command.add_argument("input", type=Path)
        command.add_argument("--binary", action="store_true", help="input is raw bytes; requires --base")
        command.add_argument("--base", type=lambda s: int(s, 0))
        command.add_argument("--role", choices=["code", "stack", "requested", "frame_record"])
        command.add_argument("--start", type=lambda s: int(s, 0))
        command.add_argument("--length", type=lambda s: int(s, 0))
        command.add_argument("--max-results", type=int, default=1000)
        command.add_argument("--seconds", type=float, default=5)
        command.add_argument("--output", type=Path, required=True)
        if name == "search":
            command.add_argument("--pattern", required=True)
        else:
            command.add_argument("--target", type=lambda s: int(s, 0))
            command.add_argument("--max-instructions", type=int, default=100000)
    args = parser.parse_args(argv)
    try:
        raw = bounded_file(args.input, MAX_BYTES if args.binary else MAX_FILE)
        maps, consistency = [], None
        if args.binary:
            if args.base is None or args.role:
                raise ValueError("raw input requires --base and cannot use --role")
            segments = [(args.base, raw)]
        else:
            if args.base is not None:
                raise ValueError("--base is for raw inputs only")
            report = json.loads(raw)
            segments = segments_from_report(report, role=args.role)
            consistency = report.get("consistency", "unknown")
            if report.get("maps", {}).get("status") == "ok":
                maps = report["maps"]["items"]
                if not isinstance(maps, list) or len(maps) > 2048:
                    raise ValueError("invalid map metadata")
                previous = 0
                for item in maps:
                    if any(type(item.get(key)) is not int for key in ("start", "end", "offset", "truncated")) or not isinstance(item.get("name"), str):
                        raise ValueError("invalid map metadata")
                    if not previous <= item["start"] < item["end"] <= U64 or item["offset"] < 0 or item["truncated"] not in (0, 1):
                        raise ValueError("invalid map metadata")
                    previous = item["end"]
        segments = select_segments(segments, args.start, args.length)
        if not segments:
            raise ValueError("no captured bytes in the selected range")
        options = {"max_results": args.max_results, "seconds": args.seconds}
        if args.operation == "search":
            result = wildcard_search(segments, args.pattern, maps=maps, **options)
        else:
            result = cross_references(segments, target=args.target, max_instructions=args.max_instructions, **options)
        result.update(schema=1, operation=args.operation, input=str(args.input), input_sha256=hashlib.sha256(raw).hexdigest(),
                      source_consistency=consistency, selected_bytes=sum(len(data) for _, data in segments),
                      coverage="captured successful ranges only; faults and gaps are not searched",
                      ranges=[{"address": base, "length": len(data)} for base, data in segments])
        with args.output.open("x") as stream:
            json.dump(result, stream, indent=2); stream.write("\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
