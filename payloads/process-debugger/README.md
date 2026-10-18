# Process debugger

An all-stop GDB remote server for attaching to one process by PID. Built with
the same Payload SDK, LLVM 18 requirement, reproducible flags, and startup code
as the other homebrew-tools payloads. The default listener is TCP port 1234.

## Build and launch

From the repository root with `PS5_PAYLOAD_SDK` and `LLVM_CONFIG` configured:

```sh
make process-debugger
python3 host/send_payload.py out/process-debugger.elf --host "$PS5_HOST" \
  --log captures/process-debugger-001.log --idle-timeout 60
```

The sender's idle timeout leaves a running server alive. Do not resend merely
because its log connection timed out. `make all` and `make bundle` also include
the debugger; no separate research checkout or runtime is needed.

Use a GDB build supporting x86-64:

```gdb
set architecture i386:x86-64
file /path/to/matching/unstripped/target.elf
target extended-remote CONSOLE_ADDRESS:1234
attach TARGET_PID
info threads
info registers
x/10i $pc
stepi
hbreak *TARGET_ADDRESS
continue
detach
```

Supply the target's relocated symbol addresses for ASLR. The server does not
currently discover module mappings or load shared-library symbols. The ELF
above is the target's ELF, not the debugger payload. These GDB commands describe
the supported protocol; a stock GDB client has not yet been tested live.

## Implemented behavior and limits

- `vAttach`, detach, thread enumeration/selection, GP register access, memory
  access, single-step, continue, Ctrl-C, and target exit replies.
- `Z1`/`z1` hardware execution breakpoints. Free slots only: existing debug
  allocations are preserved. All current LWPs are updated transactionally;
  saved registers are restored on detach, including disconnect cleanup.
- `Z2` and `Z4` write/access watchpoint handlers and DR7 encoding. **Disabled
  on retail 13.60 in the default build because data watchpoints did not fire in
  live validation.** The experimental kernel fallback can be compiled with
  `CPPFLAGS=-DPROCESS_DEBUGGER_KERNEL_DBREGS`; it is not console-validated.
- Four hardware slots total, shared with existing debug-register owners.
  `Z3` read-only watchpoints and `Z0` software breakpoints are unsupported.
- One process, at most 256 threads. New threads receive breakpoint state at the
  next observed stop; creation while running is not yet intercepted. Only one
  vCont action is supported. FP/vector registers and signal-delivery resume
  commands are not implemented.
- System applications can impose additional PS5 AppContext restrictions;
  arbitrary system/game attachment has not been validated. PID 1 and the
  server itself are rejected.

The server follows the SDK's `test_privileges` sample: temporarily set the
caller authid/capabilities, issue raw ptrace, then restore credentials. It does
not use the SDK libc ptrace stub, which returned 1 without attaching during
console testing. Failed restoration blocks further use and is retried during
connection cleanup. Attach and cleanup waits are bounded; failed detach keeps
the server alive so exiting cannot implicitly kill a tracee.

The experimental PCB fallback is gated to PS5 Pro 13.60. It verifies proc/thread
ownership, TID and PCB pointers, and requires exactly one six-register save
area matching ptrace readback before writing. Its latest ELF was sent but did
not report startup before the console stopped responding; no successful live
fallback run is claimed. The cause of the loss of connectivity is unknown.

## Validation

```sh
make check
python3 host/validate_debugger.py --host "$PS5_HOST" \
  --elf out/process-debugger.elf --report captures/debugger-validation-001.json
```

The console validator creates its own disposable child. It tests attach,
register/memory read-write-restore, stepping, breakpoints, detach/resume, and
reconnect. `qPS5:test-hardware` borrows inherited slots only for this child;
original state is retained for restoration. Arbitrary targets cannot use that
command. Reports are created exclusively and retain commands/replies and the
payload hash, including failed runs.

Current evidence: SDK/LLVM 18.1.8 builds on gpubox; host protocol/state tests
pass. Live PS5 Pro 13.60 tests passed attachment, GP register and memory
read/write/restore, instruction stepping, and a hardware execution breakpoint.
The full validator has **not passed**: data watchpoints, disconnect cleanup,
and the experimental kernel path remain unvalidated. See
[debugger validation](../../docs/DEBUGGER_VALIDATION.md).

Custom diagnostic packets: `qPS5:dbregs`, `qPS5:spawn-test`,
`qPS5:test-hardware`, `qPS5:finish-test`, and `qPS5:shutdown` (requires no attached
process or test child). `vKill;PID` explicitly terminates the attached target.

Protocol: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html
