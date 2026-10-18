"""Exercise the real process backend with a deterministic ptrace test double.

Host tests validate protocol/state logic, not the PS5 kernel ptrace ABI.
"""
import pathlib
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PAYLOAD = ROOT / "payloads/process-debugger"

MOCK = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static struct reg mock_regs[2];
static struct dbreg mock_db[2];
static unsigned char mock_memory[1024];
static int pending, attached, fail_set, sets, stepped[2], suspended[2];
static int mock_ptrace(int request, int id, caddr_t address, int data) {
    int i = id == 102 ? 1 : 0;
    switch(request) {
    case PT_ATTACH:
        if(id != 4242) { errno = ESRCH; return -1; }
        if(attached) { errno = EBUSY; return -1; }
        attached = 1; pending = SIGSTOP; return 0;
    case PT_DETACH: attached = 0; return 0;
    case PT_GETNUMLWPS: return 2;
    case PT_GETLWPLIST: ((lwpid_t*)address)[0] = 101; ((lwpid_t*)address)[1] = 102; return 2;
    case PT_GETDBREGS: *(struct dbreg*)address = mock_db[i]; return 0;
    case PT_SETDBREGS:
        if(++sets == fail_set) { errno = EIO; return -1; }
        mock_db[i] = *(struct dbreg*)address; return 0;
    case PT_LWPINFO: ((struct ptrace_lwpinfo*)address)->pl_lwpid = 101; return 0;
    case PT_GETREGS: *(struct reg*)address = mock_regs[i]; return 0;
    case PT_SETREGS: mock_regs[i] = *(struct reg*)address; return 0;
    case PT_CLEARSTEP: stepped[i] = 0; return 0;
    case PT_SETSTEP: stepped[i] = 1; return 0;
    case PT_SUSPEND: suspended[i] = 1; return 0;
    case PT_RESUME: suspended[i] = 0; return 0;
    case PT_CONTINUE:
        mock_regs[0].r_rip++;
        mock_db[0].dr[6] = 0;
        for(int k = 0; k < 4; k++) if(target.bp[k].used) mock_db[0].dr[6] |= 1ul << k;
        pending = SIGTRAP; return 0;
    case PT_IO: {
        struct ptrace_io_desc* io = (void*)address;
        uintptr_t offset = (uintptr_t)io->piod_offs;
        if(offset > sizeof(mock_memory) || io->piod_len > sizeof(mock_memory)-offset) { errno = EFAULT; return -1; }
        if(io->piod_op == PIOD_READ_D) __builtin_memcpy(io->piod_addr, mock_memory+offset, io->piod_len);
        else __builtin_memcpy(mock_memory+offset, io->piod_addr, io->piod_len);
        return 0;
    }
    default: errno = EINVAL; return -1;
    }
}
static pid_t mock_wait4(pid_t pid, int* status, int flags, struct rusage* usage) {
    if(!pending) return 0;
    *status = (pending << 8) | 0x7f;
    pending = 0;
    return pid;
}
static void setup(void) {
    __builtin_memset(&target, 0, sizeof(target));
    __builtin_memset(mock_regs, 0, sizeof(mock_regs));
    __builtin_memset(mock_db, 0, sizeof(mock_db));
    mock_regs[0].r_rip = mock_regs[1].r_rip = 0x1000;
    mock_regs[0].r_rflags = mock_regs[1].r_rflags = 0x202;
    /* Slot 1 is owned by someone else and must survive all operations. */
    mock_db[0].dr[1] = mock_db[1].dr[1] = 0x9000;
    mock_db[0].dr[7] = mock_db[1].dr[7] = 0x4;
    sets = fail_set = pending = attached = 0;
}
static void unit_tests(void) {
    setup();
    assert(attach_process(4242) == 0);
    assert(target.count == 2 && target.selected == 101);
    assert(breakpoint(1, 1, 0x1000, 1) == 0);
    assert(target.bp[0].used && !target.bp[1].used);
    assert(mock_db[0].dr[0] == 0x1000 && mock_db[1].dr[0] == 0x1000);
    assert(mock_db[0].dr[1] == 0x9000 && (mock_db[0].dr[7] & 4));
    assert(breakpoint(1, 1, 0x1000, 1) == 0); /* idempotent */
    struct dbreg before0 = mock_db[0], before1 = mock_db[1];
    fail_set = sets + 2;
    assert(breakpoint(1, 2, 0x2000, 8) == -EIO);
    assert(!target.bp[2].used && !target.poisoned);
    assert(__builtin_memcmp(&before0, &mock_db[0], sizeof(before0)) == 0);
    assert(__builtin_memcmp(&before1, &mock_db[1], sizeof(before1)) == 0);
    fail_set = 0;
    assert(breakpoint(1, 2, 0x2000, 8) == 0);
    assert(breakpoint(1, 4, 0x3000, 4) == 0);
    assert(breakpoint(1, 1, 0x4000, 1) == -ENOSPC);
    assert(breakpoint(1, 2, 0x2001, 8) == -EINVAL);
    assert(breakpoint(1, 3, 0x2000, 8) == 1);
    assert(resume_process(1, 101, 0) == 0);
    assert(!stepped[0] && !suspended[1]);
    assert(detach_process() == 0 && !attached);
    for(int i = 0; i < 2; i++) {
        assert(mock_db[i].dr[0] == 0 && mock_db[i].dr[2] == 0 && mock_db[i].dr[3] == 0);
        assert(mock_db[i].dr[1] == 0x9000 && mock_db[i].dr[7] == 4);
    }
    assert(!hwbreak_valid(1, 0x1000, 2));
    assert(!hwbreak_valid(2, 1ull << 47, 8));
    assert(hwbreak_control(&(struct hwbreak){0x1000, 2, 8, 1}, 0) == 0x90001);
    puts("backend state/rollback assertions passed");
}
int main(int argc, char** argv) {
    if(argc == 1) { unit_tests(); return 0; }
    setup();
    gdb_socket = atoi(argv[1]);
    serve();
    if(target.pid) assert(detach_process() == 0);
    return 0;
}
'''


class ProcessTests(unittest.TestCase):
    def send(self, payload):
        data = payload.encode()
        self.sock.sendall(b"$" + data + b"#" + f"{sum(data) & 255:02x}".encode())
        self.assertEqual(self.sock.recv(1), b"+")

    def reply(self):
        self.assertEqual(self.sock.recv(1), b"$")
        data = b""
        while True:
            c = self.sock.recv(1)
            if c == b"#": break
            self.assertTrue(c)
            data += c
        checksum = self.sock.recv(1) + self.sock.recv(1)
        self.assertEqual(int(checksum, 16), sum(data) & 255)
        self.sock.sendall(b"+")
        return data

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        folder = pathlib.Path(cls.tmp.name)
        # Use the repository's actual FreeBSD reg/ptrace declarations with host
        # system types. Only OS calls are mocked, not the backend implementation.
        reg = (ROOT / "tests/debugger-abi/machine/reg.h").read_text()
        ptrace = (ROOT / "tests/debugger-abi/sys/ptrace.h").read_text()
        ptrace = ptrace.split("#ifdef _KERNEL", 1)[0] + "\n#endif\n"
        ptrace = "\n".join(line for line in ptrace.splitlines() if not line.startswith("#include"))
        fake = "#define MAXCOMLEN 19\ntypedef int lwpid_t;\n" + reg + "\n" + ptrace
        # Old FreeBSD siginfo uses a tag unavailable on macOS; the mock only
        # accesses pl_lwpid, while production uses the full repository header.
        fake = fake.replace("struct __siginfo pl_siginfo", "siginfo_t pl_siginfo")
        (folder / "ptrace.h").write_text(fake)
        process = (PAYLOAD / "main.c").read_text()
        process = process.replace('#include "../../vendor/prosper0gdb/rsp_transport.h"', '#include "rsp_transport.h"')
        process = process.replace('#include "../../vendor/prosper0gdb/trap_state.h"', '#include "trap_state.h"')
        process = process.replace("#include <sys/ptrace.h>", '#include "ptrace.h"')
        # Forward declare the doubles after native wait headers, then redirect
        # just the implementation calls to them.
        process = process.replace('#include "hwbreak.h"', '''#include "hwbreak.h"
static int mock_ptrace(int, int, caddr_t, int);
static pid_t mock_wait4(pid_t, int*, int, struct rusage*);''')
        process = process.replace("ptrace(request, id, address, data)", "mock_ptrace(request, id, address, data)")
        process = process.replace("wait4(", "mock_wait4(").replace("mock_mock_wait4(", "mock_wait4(")
        process = process.replace("sys_exit", "_exit")
        src = folder / "process.c"
        src.write_text("#define PROCESS_DEBUGGER_TEST\n" + process + MOCK)
        cls.exe = str(folder / "process")
        subprocess.run(["cc", "-D_GNU_SOURCE", "-w", "-I", str(PAYLOAD), "-I", str(ROOT / "vendor/prosper0gdb"), str(src), "-o", cls.exe], check=True)
        subprocess.run([cls.exe], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.sock, child = socket.socketpair()
        self.sock.settimeout(3)
        self.proc = subprocess.Popen([self.exe, str(child.fileno())], pass_fds=(child.fileno(),))
        child.close()

    def tearDown(self):
        self.sock.close()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.assertEqual(self.proc.returncode, 0)

    def request(self, packet):
        self.send(packet)
        return self.reply()

    def attach(self):
        self.assertTrue(self.request("vAttach;1092").startswith(b"T"))

    def test_attach_threads_detach(self):
        self.attach()
        self.assertEqual(self.request("qAttached"), b"1")
        self.assertEqual(self.request("qfThreadInfo"), b"m65,66")
        self.assertEqual(self.request("Hg66"), b"OK")
        self.assertEqual(self.request("qC"), b"QC66")
        self.assertEqual(self.request("Hgffff"), b"E03")
        self.assertEqual(self.request("D"), b"OK")
        self.assertEqual(self.request("qAttached"), b"0")

    def test_register_roundtrip(self):
        self.attach()
        self.assertEqual(self.request("P0=8877665544332211"), b"OK")
        self.assertEqual(self.request("p0"), b"8877665544332211")
        registers = self.request("g")
        self.assertEqual(len(registers), 1120)
        self.assertEqual(self.request("G" + registers.decode()), b"OK")
        self.assertTrue(self.request("P0=xx").startswith(b"E"))

    def test_memory_roundtrip_and_fault(self):
        self.attach()
        data = bytes(range(32)).hex()
        self.assertEqual(self.request("M10,20:" + data), b"OK")
        self.assertEqual(self.request("m10,20"), data.encode().upper())
        self.assertTrue(self.request("mffffffffffff,1").startswith(b"E"))
        self.assertTrue(self.request("M0,1:zz").startswith(b"E"))

    def test_hwbreak_and_watch_stop_reasons(self):
        self.attach()
        self.assertEqual(self.request("Z1,1000,1"), b"OK")
        self.assertIn(b"hwbreak:;", self.request("c"))
        self.assertEqual(self.request("z1,1000,1"), b"OK")
        self.assertEqual(self.request("Z2,100,8"), b"OK")
        self.assertIn(b"watch:100;", self.request("vCont;c"))
        self.assertEqual(self.request("z2,100,8"), b"OK")
        self.assertEqual(self.request("Z4,100,8"), b"OK")
        self.assertIn(b"awatch:100;", self.request("c"))
        self.assertEqual(self.request("Z3,100,8"), b"")
        self.assertTrue(self.request("Z2,101,8").startswith(b"E"))

    def test_step_selected_thread(self):
        self.attach()
        self.assertEqual(self.request("vCont?"), b"vCont;c;s")
        self.assertTrue(self.request("vCont;s:65").startswith(b"T05"))
        self.assertEqual(self.request("p10"), b"0110000000000000")
        self.assertTrue(self.request("vCont;s:ffff").startswith(b"E"))
        self.assertTrue(self.request("vCont;c;s").startswith(b"E"))

    def test_invalid_attach_and_repeated_attach(self):
        self.assertTrue(self.request("vAttach;1").startswith(b"E"))
        self.assertTrue(self.request("vAttach;123").startswith(b"E"))
        self.attach()
        self.assertTrue(self.request("vAttach;1092").startswith(b"E"))

    def test_xml_chunking(self):
        self.assertIn(b"hwbreak+", self.request("qSupported:swbreak+"))
        self.assertTrue(self.request("qXfer:features:read:target.xml:0,10").startswith(b"m"))
        self.assertTrue(self.request("qXfer:features:read:target.xml:ffffffff,10").startswith(b"E"))


if __name__ == "__main__":
    unittest.main()
