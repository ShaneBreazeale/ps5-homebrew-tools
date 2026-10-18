# SPDX-License-Identifier: GPL-3.0-or-later
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "host"))
from decode_events import decode_capture, load_profile
from compare_captures import compare, summarize


def ring(sequence, *values):
    return "".join(f"log-word[{sequence + i}]=0x{value:016x}\n" for i, value in enumerate(values))


def marker(name):
    return int.from_bytes(name.encode("ascii"), "big")


class LogTests(unittest.TestCase):
    def setUp(self):
        self.profile = load_profile(ROOT / "profiles/events/scope-state-v1.json")

    def decode(self, text):
        return decode_capture(text, self.profile)

    def test_repeated_snapshot_with_sliding_window(self):
        first = ring(10, marker("PPRUMX01"), 123, 1, 4)
        second = ring(14, marker("PPRSCP01"), 2, 0x402, 456, 4)
        capture = self.decode(first + "core handle=10\n" + first + second + "core handle=12\n")
        self.assertEqual(len(capture["snapshots"]), 2)
        records = capture["snapshots"][1]["records"]
        self.assertTrue(records[0]["repeated"])
        self.assertFalse(records[1]["repeated"])
        self.assertEqual(records[1]["fields"]["occupied"], 2)
        self.assertEqual(summarize(capture)[1]["metric_changes"][0]["delta"], 2)

    def test_truncated_fragment_and_unknown_are_preserved(self):
        capture = self.decode(ring(50, 0xabc, marker("PPRSCP01"), 2) + "core handle=1\n")
        records = capture["snapshots"][0]["records"]
        self.assertEqual(records[0]["status"], "unknown")
        self.assertEqual(records[0]["words"], ["0x0000000000000abc"])
        self.assertEqual(records[1]["status"], "truncated")
        self.assertEqual(records[1]["expected_words"], 5)
        self.assertTrue(capture["snapshots"][0]["ring_gaps"])

    def test_gap_does_not_join_payload(self):
        capture = self.decode(ring(1, marker("PPRUMX01"), 99) + ring(5, marker("PPRSCP01"), 1, 2, 3, 4))
        records = capture["snapshots"][0]["records"]
        self.assertEqual([r["status"] for r in records], ["truncated", "decoded"])

    def test_counter_reset_starts_new_epoch_without_delta(self):
        word = ring(10, marker("PPRUMX01"), 123, 1, 4)
        capture = self.decode(word + "core handle=10\n" + word + "core handle=2\n")
        self.assertEqual(capture["snapshots"][1]["epoch"], 1)
        self.assertFalse(capture["snapshots"][1]["records"][0]["repeated"])
        self.assertNotIn("delta", summarize(capture)[1]["metric_changes"][0])

    def test_sequence_regression_and_conflict(self):
        for second in (ring(1, 12), ring(10, 13)):
            with self.subTest(second=second):
                capture = self.decode(ring(10, 12) + "core handle=10\n" + second + "core handle=11\n")
                self.assertEqual(capture["snapshots"][1]["epoch"], 1)

    def test_explicit_reader_session_resets_deduplication(self):
        word = ring(10, marker("PPRUMX01"), 123, 1, 4)
        capture = self.decode("debug-reader: start\n" + word + "core handle=10\n" + "debug-reader: start\n" + word + "core handle=11\n")
        self.assertFalse(capture["snapshots"][1]["records"][0]["repeated"])
        self.assertNotIn("delta", summarize(capture)[1]["metric_changes"][0])

    def test_empty_ring_snapshots_and_gauges(self):
        capture = self.decode("core handle=10\nppr_lifetime outstanding=4\ncore handle=12\nppr_lifetime outstanding=1\n")
        self.assertEqual(len(capture["snapshots"]), 2)
        changes = summarize(capture)[1]["metric_changes"]
        self.assertEqual(changes[0]["delta"], 2)
        self.assertNotIn("delta", changes[1])

    def test_ambiguous_marker_is_not_guessed(self):
        record = self.decode(ring(1, marker("PPREKX01"), 0, 123, 1))["snapshots"][0]["records"][0]
        self.assertEqual(record["status"], "unknown")
        self.assertIn("two payload words", record["reason"])

    def test_profile_prevents_cross_variant_decoding(self):
        profile = load_profile(ROOT / "profiles/events/exec-unmount-v1.json")
        result = decode_capture(ring(1, marker("PPRSCP01"), 1, 2, 3, 4), profile)
        self.assertTrue(all(record["status"] == "unknown" for record in result["snapshots"][0]["records"]))

    def test_read_fields_and_path_endianness(self):
        profile = load_profile(ROOT / "profiles/events/read-entry-v1.json")
        capture = decode_capture(ring(1, marker("PPRRD001"), (4 << 32) | 12, 2, 4096), profile)
        read = capture["snapshots"][0]["records"][0]["read"]
        self.assertEqual(read, {"kind": 4, "name": "preadv", "fd": 12, "count_unit": "iovecs"})
        path = b"/app0/eboot.bin\0\0"
        record = self.decode(ring(1, marker("PPREXV01"), int.from_bytes(path[:8], "little"), int.from_bytes(path[8:], "little")))["snapshots"][0]["records"][0]
        self.assertEqual(record["path"], "/app0/eboot.bin")

    def test_errors_and_original_lines_preserved(self):
        capture = self.decode("log-word[1]=oops\ndebug-reader: shared_area snapshot failed: -1\n")
        snapshot = capture["snapshots"][0]
        self.assertEqual(len(snapshot["errors"]), 2)
        self.assertEqual(snapshot["lines"][0]["text"], "log-word[1]=oops")

    def test_cross_capture_comparison_never_subtracts_counters(self):
        result = compare(self.decode("core handle=10\n"), self.decode("core handle=14\n"))
        self.assertEqual(result["final_metric_changes"], [{"metric": "core.handle", "before": 10, "after": 14}])

    def test_process_identity_includes_start_for_pid_reuse(self):
        before = self.decode("baseline time=1 count=1 self=5\nbase time=1 pid=5 start=1 comm=app one\n")
        after = self.decode("baseline time=2 count=1 self=5\nbase time=2 pid=5 start=2 comm=app two\n")
        changes = compare(before, after)["process_identity_changes"]
        self.assertEqual(changes["only_before"], [{"pid": 5, "start": 1, "comm": "app one"}])
        self.assertEqual(changes["only_after"][0]["start"], 2)

    def test_cli_json_and_profile_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "capture.log"
            capture.write_text("core handle=1\n")
            command = [sys.executable, str(ROOT / "host/decode_events.py"), str(capture)]
            missing = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(missing.returncode, 2)
            result = subprocess.run(command + ["--profile", str(ROOT / "profiles/events/scope-state-v1.json")], capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(result.stdout)["profile"], "scope-state-v1")
            result = subprocess.run([sys.executable, str(ROOT / "host/compare_captures.py"), str(capture), str(capture), "--profile", str(ROOT / "profiles/events/scope-state-v1.json")], capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(result.stdout)["final_metric_changes"], [])


if __name__ == "__main__":
    unittest.main()
