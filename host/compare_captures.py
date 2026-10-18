#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare resident metrics, process observations, and ring events as JSON."""
import argparse
import json
from pathlib import Path
import sys

from decode_events import decode_capture, load_profile


def metric_changes(before, after, allow_deltas=False):
    changes = []
    for key in sorted(before.keys() | after.keys()):
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        change = {"metric": key, "before": old, "after": new}
        # Only core fields are known cumulative counters. Other fields include
        # gauges, packed values, addresses, command IDs and percentages.
        if allow_deltas and key.startswith("core.") and old is not None and new is not None and new >= old:
            change["delta"] = new - old
        changes.append(change)
    return changes


def summarize(capture):
    previous = None
    result = []
    for snapshot in capture["snapshots"]:
        continuous = previous is not None and snapshot["epoch"] == previous["epoch"]
        result.append({"snapshot": snapshot["snapshot"], "session": snapshot["session"], "epoch": snapshot["epoch"],
                       "boundary_reasons": snapshot["boundary_reasons"],
                       "metric_changes": metric_changes(previous["metrics"] if previous else {}, snapshot["metrics"], continuous),
                       "newly_observed_records": [record for record in snapshot["records"] if not record["repeated"]],
                       "process_observations": snapshot["processes"],
                       "ring_gaps": snapshot["ring_gaps"], "errors": snapshot["errors"]})
        previous = snapshot
    return result


def compare(before, after):
    before_last = before["snapshots"][-1]["metrics"] if before["snapshots"] else {}
    after_last = after["snapshots"][-1]["metrics"] if after["snapshots"] else {}
    def observations(capture):
        return sorted({item["text"] for snap in capture["snapshots"] for item in snap["processes"]})
    left, right = set(observations(before)), set(observations(after))
    def identities(capture):
        # These are observed identities, not a claim that the process survived
        # until the end of the capture. Include start to distinguish PID reuse.
        return {(item["fields"]["pid"], item["fields"]["start"], item["fields"].get("comm", ""))
                for snap in capture["snapshots"] for item in snap["processes"]
                if "pid" in item["fields"] and "start" in item["fields"]}
    before_ids, after_ids = identities(before), identities(after)
    def render_ids(values):
        return [{"pid": pid, "start": start, "comm": comm} for pid, start, comm in sorted(values)]
    return {"schema_version": 1, "profile": before["profile"],
            "comparison_scope": "independent captures; no cross-file counter deltas or event sequence deduplication",
            "final_metric_changes": metric_changes(before_last, after_last),
            "process_observation_changes": {"only_before": sorted(left - right), "only_after": sorted(right - left)},
            "process_identity_changes": {"only_before": render_ids(before_ids - after_ids),
                                         "only_after": render_ids(after_ids - before_ids)},
            "before": summarize(before), "after": summarize(after)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        profile = load_profile(args.profile)
        before = decode_capture(args.before.read_text(errors="backslashreplace"), profile)
        after = decode_capture(args.after.read_text(errors="backslashreplace"), profile)
        result = compare(before, after)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    json.dump(result, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
