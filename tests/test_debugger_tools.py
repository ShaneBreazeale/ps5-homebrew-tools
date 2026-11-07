"""End-to-end stop capture against real RSP/fake target, plus offline analysis."""
import hashlib
import importlib.util
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "host"))
import debugger_report as capture
import debugger_analyze as analyze


def row(address, data, role="requested", errno=0, requested=None):
    return {"address": address, "requested": len(data) if requested is None else requested,
            "data": data.hex(), "sha256": hashlib.sha256(data).hexdigest() if not errno else None,
            "errno": errno, "role": role}


class ToolsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = str(pathlib.Path(cls.tmp.name) / "fake-rsp")
        subprocess.run(["cc", "-D_GNU_SOURCE", "-std=c11", "-I", str(ROOT / "payloads/process-debugger"),
                        str(ROOT / "payloads/process-debugger/rsp.c"), str(ROOT / "tests/fake_debug_target.c"),
                        "-o", cls.exe], check=True)
        memory = pathlib.Path(cls.tmp.name) / "memory"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(ROOT / "tests/test_target_memory.c"), "-o", str(memory)], check=True)
        subprocess.run([str(memory)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.sock, child = socket.socketpair()
        self.sock.settimeout(3)
        self.proc = subprocess.Popen([self.exe, str(child.fileno())], pass_fds=(child.fileno(),))
        child.close()
        self.session = capture.Inspection(self.request)
        self.request("vAttach;4d")

    def tearDown(self):
        self.sock.close()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill(); self.proc.wait()
        self.assertEqual(self.proc.returncode, 0)

    def request(self, packet):
        data = packet.encode()
        self.sock.sendall(b"$"+data+b"#"+f"{sum(data)&255:02x}".encode())
        self.assertEqual(self.sock.recv(1), b"+")
        self.assertEqual(self.sock.recv(1), b"$")
        data = b""
        while True:
            byte = self.sock.recv(1)
            if byte == b"#": break
            self.assertTrue(byte); data += byte
        checksum = self.sock.recv(1)+self.sock.recv(1)
        self.assertEqual(sum(data)&255, int(checksum,16))
        self.sock.sendall(b"+")
        return data.decode()

    def report(self, **options):
        return capture.capture_report(self.request, expected_pid=77, stack_bytes=64, code_bytes=0,
                                      **options)

    def test_saved_report_preserves_raw_stack_and_heuristic_frames(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "report.json"
            report = capture.save_report(path, self.request, expected_pid=77, stack_bytes=64, code_bytes=0)
            self.assertEqual(json.loads(path.read_text()), report)
            self.assertEqual(report["status"], "complete")
            self.assertEqual(report["consistency"], "same_observed_stop")
            self.assertEqual(report["frame_walk"]["method"], "rbp_chain")
            self.assertTrue(report["frame_walk"]["heuristic"])
            self.assertFalse(report["frame_walk"]["unwind_verified"])
            self.assertEqual(len(report["frame_walk"]["frames"]), 2)
            self.assertEqual(report["frame_walk"]["stop_reason"], "end_of_chain")
            stack = [r for r in report["memory"] if r["role"] == "stack"]
            self.assertEqual(sum(len(bytes.fromhex(r["data"])) for r in stack), 64)
            self.assertEqual(len(report["threads"]), 2)
            self.assertTrue(report["selection_restored"])
            self.assertEqual(capture.fields(self.request("qPS5:state"))["selected"], "385")
            with self.assertRaises(FileExistsError):
                capture.save_report(path, lambda _: self.fail("overwrite must not touch target"), expected_pid=77)
            self.assertFalse(any(t["command"].startswith(("vAttach", "D", "M", "P", "Z")) or
                                 t["command"] in ("c", "s") for t in report["transcript"]))

    def test_readv_keeps_failures_and_later_successes(self):
        self.request("M10,4:aabbccdd")
        result = self.session.readv([(16,4),(128,1),(18,2)])
        self.assertEqual(result[0]["data"], "aabbccdd")
        self.assertTrue(result[1]["errno"]); self.assertEqual(result[1]["data"], "")
        self.assertEqual(result[2]["data"], "ccdd")
        report = self.report(ranges=[(128,4)])
        self.assertEqual(report["status"], "partial")
        self.assertTrue(any(r["errno"] for r in report["memory"]))

    def test_wrong_pid_does_not_read_memory(self):
        report = capture.capture_report(self.request, expected_pid=88)
        self.assertEqual(report["status"], "partial")
        self.assertFalse(report["memory"])
        self.assertFalse(any(t["command"].startswith("qPS5:readv:") for t in report["transcript"]))

    def test_stop_change_and_transport_failure_preserve_evidence(self):
        states = 0
        def changing(command):
            nonlocal states
            if command == "qPS5:state":
                states += 1
                if states == 2: self.request("s")
            return self.request(command)
        report = capture.capture_report(changing, expected_pid=77, stack_bytes=64, code_bytes=0)
        self.assertEqual(report["consistency"], "changed")
        self.assertEqual(report["status"], "partial")
        self.assertTrue(report["memory"])
        reads, disconnected = 0, False
        def disconnecting(command):
            nonlocal reads, disconnected
            self.assertFalse(disconnected, "must not send after transport failure")
            if command.startswith("qPS5:readv:"):
                reads += 1
                if reads == 2:
                    disconnected = True; raise ConnectionError("fixture disconnect")
            return self.request(command)
        report = capture.capture_report(disconnecting, expected_pid=77, stack_bytes=64, code_bytes=0)
        self.assertEqual(report["status"], "partial")
        self.assertTrue(report["memory"])
        self.assertIsNone(report["selection_restored"])

    def test_budget_exhaustion_still_restores_register_selection(self):
        now = [0.0]
        def request(command):
            answer = self.request(command)
            if command == "Hg386": now[0] = 2.0
            return answer
        with mock.patch.object(capture.time, "monotonic", side_effect=lambda: now[0]):
            report = capture.capture_report(request, expected_pid=77, stack_bytes=0, code_bytes=0,
                                             frame_depth=0, seconds=1)
        self.assertEqual(report["status"], "partial")
        self.assertTrue(report["selection_restored"])
        self.assertEqual(capture.fields(self.request("qPS5:state"))["selected"], "385")

    def test_optional_metadata_failure_does_not_lose_stack(self):
        def request(command):
            if command == "qPS5:process" or command.startswith("qPS5:maps:"):
                return "E2D"
            return self.request(command)
        report = capture.capture_report(request, expected_pid=77, stack_bytes=32, code_bytes=0, frame_depth=0)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["consistency"], "same_observed_stop")
        self.assertEqual(len(bytes.fromhex(report["memory"][0]["data"])),32)
        self.assertEqual(report["maps"]["errno"],45)

    def test_changed_optional_map_list_keeps_raw_stack(self):
        def request(command):
            result = self.request(command)
            if command == "qPS5:maps:1":
                values = capture.fields(result)
                values["snapshot"] = "1"
                return ";".join(f"{key}:{value}" for key,value in values.items())
            return result
        report = capture.capture_report(request, expected_pid=77, stack_bytes=32, code_bytes=0, frame_depth=0)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["maps"]["status"], "invalid")
        self.assertTrue(any(r["role"] == "stack" and not r["errno"] for r in report["memory"]))

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "optional capstone decoder not installed")
    def test_saved_code_feeds_both_offline_commands(self):
        code = "488b0509000000e80400000075029090c3"
        self.request(f"M0,{len(code)//2:x}:{code}")
        self.request("P10=0000000000000000")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); report_path = root/"stop.json"
            report = capture.save_report(report_path, self.request, expected_pid=77, stack_bytes=0,
                                         code_bytes=len(code)//2, frame_depth=0)
            self.assertEqual(report["status"], "complete")
            for command, extra in [("search", ["--pattern", "E8 ?? ?? ?? ??"]),
                                   ("xrefs", ["--target", "0x10"])]:
                output = root/(command+".json")
                subprocess.run([sys.executable, str(ROOT/"host/debugger_analyze.py"), command,
                                str(report_path), "--role", "code", "--output", str(output)]+extra, check=True)
                result = json.loads(output.read_text())
                self.assertEqual(result["input_sha256"], hashlib.sha256(report_path.read_bytes()).hexdigest())
                self.assertEqual(result["source_consistency"], "same_observed_stop")
                if command == "search": self.assertEqual(result["matches"][0]["address"], 7)
                else: self.assertEqual(len(result["references"]), 3)

    def test_invalid_plan_cannot_send_oversized_packets(self):
        for name in ["A"*256, "x/y", "x\x00", ""]:
            with self.assertRaises(ValueError):
                capture.capture_report(lambda _: self.fail("invalid plan touched target"), expected_pid=77, modules=[name])
        with self.assertRaises(ValueError):
            capture.Inspection(lambda _: self.fail("oversized packet sent")).ask("x"*4097)

    def test_malformed_bulk_reply_is_rejected(self):
        for reply in ["count:1;0:0,4,00", "count:1;0:e,1,aa", "count:2;0:0,4,00000000", "count:1;0:0,4,gggggggg"]:
            with self.assertRaises(ValueError):
                capture.Inspection(lambda _: reply).readv([(0,4)])


class AnalysisTests(unittest.TestCase):
    def test_wildcards_overlap_nibbles_boundaries_and_holes(self):
        chunks = analyze.merge_segments([(0x1000,b"\x48\x8b"),(0x1002,b"\xaf\x48\x8b\xaf"),(0x1008,b"\xaf")])
        result = analyze.wildcard_search(chunks,"48 8? ?F")
        self.assertEqual([m["address"] for m in result["matches"]], [0x1000,0x1003])
        self.assertEqual(len(analyze.wildcard_search([(0,b"aaa")],"61 61")["matches"]),2)
        self.assertFalse(analyze.wildcard_search([(0,b"aaa")],"??",max_results=1)["complete"])
        self.assertFalse(analyze.wildcard_search([(0,b"aaa")],"A?")["matches"])
        for pattern in ["", "GG", "0", "abc", "?? "*257]:
            with self.assertRaises(ValueError): analyze.compile_pattern(pattern)
        with mock.patch.object(analyze.time,"monotonic",side_effect=[0,2]):
            self.assertEqual(analyze.wildcard_search([(0,b"a")],"??",seconds=1)["stop_reason"],"time_limit")

    def test_report_hashes_conflicts_and_missing_bytes(self):
        report={"schema":1,"kind":"ps5-user-stop","memory":[row(0,b"ab"),row(3,b"bc"),row(2,b"",errno=14,requested=1)]}
        segments=analyze.segments_from_report(report)
        self.assertFalse(analyze.wildcard_search(segments,"62 62")["matches"])
        report["memory"].append(row(1,b"X"))
        with self.assertRaises(ValueError): analyze.segments_from_report(report)
        report["memory"]=[row(0,b"ab")]; report["memory"][0]["data"]="0000"
        with self.assertRaises(ValueError): analyze.segments_from_report(report)

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "optional capstone decoder not installed")
    def test_cross_references_decode_operands_not_raw_immediates(self):
        # RIP-relative load -> 0x1010; direct call/jne -> 0x1010; pointer-slot
        # call -> 0x1026; movabs immediate is deliberately not a reference.
        code=bytes.fromhex("488b0509000000e80400000075029090c3ff150f00000048b81010000000000000")
        result=analyze.cross_references([(0x1000,code)])
        targets=[r["target"] for r in result["references"]]
        self.assertEqual(targets[:3],[0x1010]*3)
        self.assertEqual(result["references"][3]["target_role"],"pointer_slot")
        self.assertEqual(len(result["references"]),4)
        self.assertEqual(len(analyze.cross_references([(0x1000,code)],target=0x1010)["references"]),3)
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["unresolved_indirect"]),1)

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "optional capstone decoder not installed")
    def test_cross_reference_failure_and_instruction_limits(self):
        result=analyze.cross_references([(0x1000,b"\x90\x0f")])
        self.assertFalse(result["complete"])
        self.assertEqual(result["undecoded"],[{"address":0x1001,"length":1}])
        self.assertEqual(analyze.cross_references([(0,b"\x90\x90")],max_instructions=1)["stop_reason"],"instruction_limit")
        # Negative RIP displacement and segment-relative addresses.
        code=bytes.fromhex("488d05f9ffffff64488b0500000000")
        refs=analyze.cross_references([(0x1000,code)])["references"]
        self.assertEqual(refs[0]["target"],0x1000)
        self.assertIsNone(refs[1]["target"])

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "optional capstone decoder not installed")
    def test_cross_reference_batches_keep_instruction_boundaries(self):
        code=b"\x90"*4094+bytes.fromhex("e800000000")
        result=analyze.cross_references([(0x1000,code)])
        self.assertTrue(result["complete"])
        self.assertEqual(result["bytes_decoded"],len(code))
        self.assertEqual(result["references"][0]["address"],0x1ffe)
        self.assertEqual(result["references"][0]["target"],0x2003)

    def test_offline_cli_records_input_hash_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); source=root/"bytes"; output=root/"result.json"
            source.write_bytes(b"\x48\x8b\x01")
            args=[sys.executable,str(ROOT/"host/debugger_analyze.py"),"search",str(source),"--binary","--base","0x1000", "--pattern","48 ?? 01","--output",str(output)]
            subprocess.run(args,check=True)
            self.assertEqual(json.loads(output.read_text())["matches"][0]["address"],0x1000)
            result=subprocess.run(args,capture_output=True)
            self.assertEqual(result.returncode,2)


if __name__ == "__main__":
    unittest.main()
