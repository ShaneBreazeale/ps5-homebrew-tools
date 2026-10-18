#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Decode resident-snapshot text using an explicitly selected event schema."""
import argparse
import json
from pathlib import Path
import re
import sys

WORD = re.compile(r"^log-word\[(\d+)\]=0x([0-9a-fA-F]{1,16})$")
PAIR = re.compile(r"(?:^|\s)([\w]+)=(-?(?:0x[0-9a-fA-F]+|\d+))(?=\s|$)")
PROCESS = re.compile(r"^(base|birth|death|zombie|app)\s")


def load_profile(path):
    profile = json.loads(Path(path).read_text())
    if profile.get("schema_version") != 1:
        raise ValueError("unsupported profile schema_version")
    if not isinstance(profile.get("id"), str) or not isinstance(profile.get("events"), dict):
        raise ValueError("profile requires id and events")
    for marker, event in profile["events"].items():
        if len(marker.encode("ascii")) != 8:
            raise ValueError("markers must contain exactly eight ASCII bytes")
        if not isinstance(event.get("name"), str) or not isinstance(event.get("fields"), list):
            raise ValueError("each event requires name and fields")
        if not all(isinstance(field, str) for field in event["fields"]):
            raise ValueError("event fields must be strings")
        if len(set(event["fields"])) != len(event["fields"]):
            raise ValueError("duplicate event fields")
        if event.get("interpretation") not in (None, "path_le", "read_entry"):
            raise ValueError("unsupported event interpretation")
        required = {"path_le": ["path_word_0", "path_word_1"],
                    "read_entry": ["kind_fd", "count", "offset"]}
        if event.get("interpretation") in required and event["fields"] != required[event["interpretation"]]:
            raise ValueError("interpretation fields do not match")
    return profile


def parse_capture(text):
    """Keep each printed window separate: ring output precedes its core metrics."""
    snapshots = []
    current = None
    session = 0

    def begin():
        return {"session": session, "words": [], "metrics": {}, "processes": [],
                "errors": [], "core_seen": False, "lines": []}

    def flush():
        nonlocal current
        if current is not None and current["lines"]:
            current["snapshot"] = len(snapshots)
            del current["core_seen"]
            snapshots.append(current)
        current = None

    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if line == "debug-reader: start" or line.startswith("baseline "):
            if current and any(current[key] for key in ("words", "metrics", "processes", "errors")):
                flush()
            session += 1
            if current:
                current["session"] = session
        starts_ring = line.startswith(("log-word[", "log-msg:"))
        if current and current["core_seen"] and (starts_ring or line.startswith("core ")):
            flush()
        if current is None:
            current = begin()
        current["lines"].append({"line": number, "text": raw})
        match = WORD.fullmatch(line)
        if match:
            current["words"].append({"sequence": int(match[1]), "word": "0x" + match[2].lower().zfill(16), "line": number})
        elif line.startswith("log-word"):
            current["errors"].append({"line": number, "message": "malformed ring word", "text": raw})
        elif PROCESS.match(line):
            fields = {key: int(value, 16 if "0x" in value else 10) for key, value in PAIR.findall(line)}
            if " comm=" in line:
                fields["comm"] = line.split(" comm=", 1)[1]
            if " title=" in line:
                fields["title"] = line.split(" title=", 1)[1]
            current["processes"].append({"kind": line.split()[0], "fields": fields, "text": line})
        elif line.startswith("core ") or (PAIR.search(line) and ":" not in line and not line.startswith(("baseline ", "tick "))):
            group = line.split()[0]
            if group == "core":
                current["core_seen"] = True
            for key, value in PAIR.findall(line):
                current["metrics"][group + "." + key] = int(value, 16 if "0x" in value else 10)
        if re.search(r"failed|invalid|not loaded|self_missing", line, re.I):
            current["errors"].append({"line": number, "message": "payload diagnostic", "text": raw})
    flush()
    return snapshots


def decode_window(words, profile):
    schemas = {int.from_bytes(marker.encode("ascii"), "big"): (marker, event)
               for marker, event in profile["events"].items()}
    ambiguous = {int.from_bytes(marker.encode("ascii"), "big"): message
                 for marker, message in profile.get("ambiguous_markers", {}).items()}
    records = []
    index = 0
    while index < len(words):
        first = words[index]
        value = int(first["word"], 16)
        base = {"sequence": first["sequence"], "line": first["line"]}
        if value not in schemas:
            records.append({**base, "status": "unknown", "words": [first["word"]],
                            "reason": ambiguous.get(value, "unknown marker or overwritten event fragment")})
            index += 1
            continue
        marker, schema = schemas[value]
        count = len(schema["fields"]) + 1
        chunk = [first]
        for word in words[index + 1:index + count]:
            if word["sequence"] != chunk[-1]["sequence"] + 1:
                break
            chunk.append(word)
        record = {**base, "marker": marker, "event": schema["name"],
                  "words": [word["word"] for word in chunk]}
        if len(chunk) < count:
            record.update(status="truncated", expected_words=count)
        else:
            fields = dict(zip(schema["fields"], (int(word["word"], 16) for word in chunk[1:])))
            record.update(status="decoded", fields=fields)
            if schema.get("interpretation") == "path_le":
                path = b"".join(value.to_bytes(8, "little") for value in fields.values()).split(b"\0", 1)[0]
                record["path"] = path.decode("utf-8", errors="backslashreplace")
            elif schema.get("interpretation") == "read_entry":
                kind = fields["kind_fd"] >> 32
                record["read"] = {"kind": kind, "name": {1: "read", 2: "readv", 3: "pread", 4: "preadv"}.get(kind, "unknown"),
                                  "fd": fields["kind_fd"] & 0xffffffff,
                                  "count_unit": "iovecs" if kind in (2, 4) else "bytes" if kind in (1, 3) else "unknown"}
        records.append(record)
        index += len(chunk)
    return records


def decode_capture(text, profile):
    snapshots = parse_capture(text)
    previous = None
    seen_words = {}
    seen_records = set()
    epoch = -1
    for snapshot in snapshots:
        reasons = []
        words = snapshot["words"]
        if previous is None or snapshot["session"] != previous["session"]:
            reasons.append("capture/session start; resident continuity unverified")
        else:
            old_core = {key: value for key, value in previous["metrics"].items() if key.startswith("core.")}
            if any(snapshot["metrics"].get(key, value) < value for key, value in old_core.items()):
                reasons.append("core counter decreased; reset or inconsistent capture")
            if words and seen_words and max(word["sequence"] for word in words) < max(seen_words):
                reasons.append("ring sequence regressed; reset or out-of-order capture")
            if any(word["sequence"] in seen_words and seen_words[word["sequence"]] != word["word"] for word in words):
                reasons.append("ring sequence reused with different data")
        if reasons:
            epoch += 1
            seen_words = {}
            seen_records = set()
        snapshot["epoch"] = epoch
        snapshot["boundary_reasons"] = reasons
        snapshot["records"] = decode_window(words, profile)
        snapshot["ring_gaps"] = []
        if words and words[0]["sequence"] > 0:
            snapshot["ring_gaps"].append({"before_sequence": words[0]["sequence"], "reason": "earlier ring words unavailable in this snapshot"})
        for left, right in zip(words, words[1:]):
            if right["sequence"] != left["sequence"] + 1:
                snapshot["ring_gaps"].append({"after_sequence": left["sequence"], "before_sequence": right["sequence"], "reason": "non-contiguous ring words"})
        for record in snapshot["records"]:
            identity = (record["sequence"], record["status"], tuple(record["words"]))
            record["repeated"] = identity in seen_records
            seen_records.add(identity)
        for word in words:
            seen_words[word["sequence"]] = word["word"]
        previous = snapshot
    return {"schema_version": 1, "profile": profile["id"], "snapshots": snapshots}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--profile", required=True, type=Path, help="explicit profiles/events/*.json schema")
    args = parser.parse_args(argv)
    try:
        result = decode_capture(args.capture.read_text(errors="backslashreplace"), load_profile(args.profile))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    json.dump(result, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
