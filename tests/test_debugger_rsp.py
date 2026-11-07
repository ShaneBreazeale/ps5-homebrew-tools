"""Test RSP with an independent provider, without ptrace or PS5 native headers."""
import pathlib
import socket
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]


class RspBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = str(pathlib.Path(cls.tmp.name) / "fake-rsp")
        subprocess.run(["cc", "-D_GNU_SOURCE", "-std=c11", "-Wall", "-Wextra",
                        "-I", str(ROOT / "payloads/process-debugger"),
                        str(ROOT / "payloads/process-debugger/rsp.c"),
                        str(ROOT / "tests/fake_debug_target.c"), "-o", cls.exe], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def start(self, mode="normal"):
        self.sock, child = socket.socketpair()
        self.sock.settimeout(3)
        self.proc = subprocess.Popen([self.exe, str(child.fileno()), mode], pass_fds=(child.fileno(),))
        child.close()
        self.addCleanup(self.stop)

    def stop(self):
        self.sock.close()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.assertEqual(self.proc.returncode, 0)

    def send(self, packet):
        data = packet.encode()
        self.sock.sendall(b"$" + data + b"#" + f"{sum(data) & 255:02x}".encode())
        self.assertEqual(self.sock.recv(1), b"+")

    def reply(self):
        self.assertEqual(self.sock.recv(1), b"$")
        data = b""
        while True:
            byte = self.sock.recv(1)
            if byte == b"#":
                break
            self.assertTrue(byte)
            data += byte
        checksum = self.sock.recv(1) + self.sock.recv(1)
        self.assertEqual(int(checksum, 16), sum(data) & 255)
        self.sock.sendall(b"+")
        return data

    def request(self, packet):
        self.send(packet)
        return self.reply()

    def test_identity_registers_memory_and_execution(self):
        self.start()
        self.assertEqual(self.request("qAttached"), b"0")
        self.assertTrue(self.request("vAttach;4d").startswith(b"T11thread:385;"))
        self.assertEqual(self.request("qfThreadInfo"), b"m385,386")
        self.assertEqual(self.request("p0"), b"8877665544332211")
        self.assertEqual(self.request("p11"), b"02020000")
        self.assertEqual(self.request("p12"), b"43000000")
        registers = self.request("g")
        self.assertEqual(len(registers), 1120)
        self.assertEqual(registers[328:], b"x" * (1120 - 328))
        self.assertEqual(self.request("G" + registers.decode()), b"OK")
        self.assertEqual(self.request("Hg386"), b"OK")
        self.assertEqual(self.request("P0=0807060504030201"), b"OK")
        self.assertEqual(self.request("p0"), b"0807060504030201")
        self.assertEqual(self.request("M10,3:aabbcc"), b"OK")
        self.assertEqual(self.request("m10,3"), b"AABBCC")
        self.assertTrue(self.request("m80,1").startswith(b"E"))
        self.assertEqual(self.request("Hc386"), b"OK")
        self.assertIn(b"thread:386;", self.request("s"))
        self.assertEqual(self.request("p10"), b"0120000000000000")
        self.assertEqual(self.request("D"), b"OK")
        self.assertEqual(self.request("qAttached"), b"0")
        self.assertEqual(self.request("qPS5:shutdown"), b"OK")

    def test_breakpoint_enum_translation(self):
        self.start()
        self.request("vAttach;4d")
        for kind, reason in [(0, b"swbreak:;"), (1, b"hwbreak:;"),
                             (2, b"watch:40;"), (4, b"awatch:40;")]:
            self.assertEqual(self.request(f"Z{kind},40,1"), b"OK")
            self.assertIn(reason, self.request("vCont;c:385"))
            self.assertEqual(self.request(f"z{kind},40,1"), b"OK")
        self.assertEqual(self.request("Z3,40,1"), b"")

    def test_raw_interrupt_via_controller_callback(self):
        self.start("wait")
        self.request("vAttach;4d")
        self.send("c")
        self.sock.sendall(b"\x03")
        self.assertTrue(self.reply().startswith(b"T11thread:385;"))
        self.assertEqual(self.request("D"), b"OK")

    def test_disconnect_during_execution(self):
        self.start("wait")
        self.request("vAttach;4d")
        self.send("c")
        self.sock.shutdown(socket.SHUT_RDWR)
        self.proc.wait(timeout=3)
        self.assertEqual(self.proc.returncode, 0)

    @staticmethod
    def fields(reply):
        return dict(item.split(b":", 1) for item in reply.split(b";"))

    def test_runtime_capabilities_and_process_metadata(self):
        self.start()
        caps = self.fields(self.request("qPS5:capabilities"))
        self.assertEqual(caps[b"source"], b"unrecorded")
        self.assertEqual(caps[b"implemented"], b"63e")
        self.assertEqual(caps[b"firmware"], b"13600000")
        self.assertEqual(caps[b"hosting"], b"standalone")
        self.assertEqual(caps[b"validation"], b"host")
        self.assertTrue(self.request("qPS5:process").startswith(b"E"))
        self.request("vAttach;4d")
        info = self.fields(self.request("qPS5:process"))
        self.assertEqual(info[b"pid"], b"4d")
        self.assertEqual(bytes.fromhex(info[b"name"].decode()), b"test$#;")
        self.assertEqual(bytes.fromhex(info[b"path"].decode()), b"/app0/test$#.elf")
        self.assertEqual(info[b"fields"], b"7")
        self.assertEqual(info[b"start_usec"], b"2a")

    def test_maps_and_module_addresses(self):
        self.start()
        self.request("vAttach;4d")
        first = self.fields(self.request("qPS5:maps:0"))
        second = self.fields(self.request("qPS5:maps:1"))
        self.assertEqual(first[b"snapshot"], second[b"snapshot"])
        self.assertEqual(first[b"count"], b"2")
        self.assertEqual(first[b"start"], b"400000")
        self.assertEqual(second[b"offset"], b"4000")
        self.assertEqual(bytes.fromhex(first[b"name"].decode()), b"/app0/test$#.elf")
        self.assertTrue(self.request("qPS5:maps:2").startswith(b"E"))
        module = self.fields(self.request("qPS5:module:" + b"test.sprx".hex()))
        self.assertEqual(module[b"base"], b"400000")
        self.assertEqual(module[b"entry"], b"401000")
        for name in ["", "0", "00", "zz"]:
            self.assertTrue(self.request("qPS5:module:" + name).startswith(b"E"))

    def test_read_only_register_bank_chunks(self):
        self.start()
        self.request("vAttach;4d")
        bases = self.fields(self.request("qPS5:regset:fsgs:0,10"))
        self.assertEqual(bases[b"size"], b"10")
        values = bytes.fromhex(bases[b"data"].decode())
        self.assertEqual(int.from_bytes(values[:8], "little"), 0x123456789)
        self.assertEqual(int.from_bytes(values[8:], "little"), 0xABCDEF123)
        state = self.fields(self.request("qPS5:regset:xsave:300,100"))
        self.assertEqual(state[b"size"], b"340")
        self.assertEqual(state[b"features"], b"7")
        self.assertEqual(bytes.fromhex(state[b"data"].decode()), bytes(range(64)))
        for suffix in ["xsave:341,1", "xsave:0,401", "xsave:0,0", "unknown:0,1"]:
            self.assertTrue(self.request("qPS5:regset:" + suffix).startswith(b"E"))
        self.assertEqual(len(self.request("g")), 1120)

    def test_target_description_matches_existing_wire_file(self):
        self.start()
        document = b""
        while True:
            chunk = self.request(f"qXfer:features:read:target.xml:{len(document):x},80")
            self.assertIn(chunk[:1], (b"m",b"l"))
            document += chunk[1:]
            self.assertLess(len(document),10000)
            if chunk.startswith(b"l"): break
        registers = ET.fromstring(document).findall("feature/reg")
        sizes = [int(reg.attrib["bitsize"]) for reg in registers]
        self.assertEqual(sizes[:24], [64]*17+[32]*7)
        self.assertEqual(sum(sizes), 560*8)
        self.assertEqual(registers[16].attrib["name"], "rip")

    def test_multiple_ranges_and_stop_identifiers(self):
        self.start()
        self.assertTrue(self.request("qPS5:readv:0,1").startswith(b"E"))
        self.request("vAttach;4d")
        first = self.fields(self.request("qPS5:state"))
        self.assertEqual(first[b"stop_id"], b"1")
        self.assertEqual(self.request("M10,4:aabbccdd"), b"OK")
        reply = self.fields(self.request("qPS5:readv:10,4;80,1;12,2;800000000000,1"))
        self.assertEqual(reply[b"count"], b"4")
        self.assertEqual(reply[b"0"], b"0,4,AABBCCDD")
        self.assertEqual(reply[b"2"], b"0,2,CCDD")
        self.assertTrue(reply[b"1"].endswith(b",0,"))
        self.assertTrue(reply[b"3"].endswith(b",0,"))
        for suffix in ["", "0,0", "0,401", "0,1;", ";0,1", "0,1;0,400", ";".join(["0,1"]*17)]:
            self.assertTrue(self.request("qPS5:readv:"+suffix).startswith(b"E"))
        self.request("s")
        second = self.fields(self.request("qPS5:state"))
        self.assertEqual(second[b"stop_id"], b"2")
        self.assertEqual(self.request("D"), b"OK")
        self.assertEqual(self.fields(self.request("qPS5:state"))[b"pid"], b"0")

    def test_provider_count_is_bounded_before_encoding(self):
        self.start("oversized")
        self.request("vAttach;4d")
        self.assertTrue(self.request("qfThreadInfo").startswith(b"E"))
        self.assertTrue(self.request("T385").startswith(b"E"))
        self.assertTrue(self.request("qPS5:maps:0").startswith(b"E"))


if __name__ == "__main__":
    unittest.main()
