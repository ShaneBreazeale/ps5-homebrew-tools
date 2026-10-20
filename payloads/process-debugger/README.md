# Process debugger

Single-process **usermode** GDB remote server for PS5 homebrew. Built through
the normal Payload SDK / LLVM 18 targets, with a default TCP listener at 1234.
It is not a kernel debugger and cannot trap kernel offset `0xcfc12`.

## Guides

| Guide | Contents |
| --- | --- |
| [CLI runbook](../../docs/DEBUGGER.md) | Build on gpubox, deploy once, log, attach, inspect, step, software/hardware breakpoints, detach |
| [LLM / CLI / GDB-MI contract](../../docs/DEBUGGER_AGENTS.md) | Session facts, bounded automation, MI state handling, evidence handoff |
| [Packet reference](../../docs/DEBUGGER_PROTOCOL.md) | Actual RSP subset, GP layout, identifiers, custom packets, limits and errors |
| [Recovery and kernel scope](../../docs/DEBUGGER_RECOVERY.md) | Offline console, kstuff slot ownership, Chain Test constraints, retired PCB fallback |
| [Validation record](../../docs/DEBUGGER_VALIDATION.md) | Exact historical builds, failed runs, successful child-only checks and remaining work |
| [Context7 guide](../../docs/CONTEXT7.md) | Confirmed library ID, retrieval prompts, indexing rules |

## Current status

Historical PS5 Pro 13.60 tests passed child-process attachment, GP register and
memory read/write/restore, instruction stepping, and a hardware execution trap
using slots leased only in our own disposable child. Software breakpoints (`Z0`,
`INT3`) are implemented and host-tested so a kstuff session can still break
without a free debug-register slot. They are not console-tested. The full
console validator has never passed. A stock GDB/MI client, arbitrary
system/game attachment, multithread execution and complete disconnect/resume
cleanup remain unvalidated.

Data watchpoints Z2/Z4 did not fire in the earlier 13.60 tests and remain
explicitly disabled there. **They are not fixed.** The source now checks address/
DR7 readback and rollback after ptrace updates; those checks detect dropped state
but do not prove a trap. Occupied DR slots are preserved and produce ENOSPC.
There is no automatic kstuff-slot takeover.

The direct PCB debug-register writer has been removed. The old
`PROCESS_DEBUGGER_KERNEL_DBREGS` flag now causes a compile error. Do not deploy
the historical run-007 fallback into a kstuff session. The latest operator
report is that the console is offline; see the dated recovery note before
planning any live action.

## Build and local checks

```sh
# Set PS5_PAYLOAD_SDK and LLVM_CONFIG to the supported LLVM 18 SDK build first.
make process-debugger
make check
make checksums
```

The result is `out/process-debugger.elf`. `make all` and `make bundle` include
it. The workspace's usual build host is gpubox; exact recorded paths are in the
validation guide. Do not substitute the research runtime or LLVM 23 build.

## Client setup

After a separately authorized, ready server deployment, start `gdb -nx -q` from
the repository root and source the local compatibility settings:

```gdb
source docs/debugger/compat.gdb
```

This profile makes no connection. Follow the CLI guide to set fresh logs,
connect with `target extended-remote`, and attach the current numeric PID.
Do not pass title IDs, historical PIDs, raw kernel offsets or kernel addresses.
Default port 1234 is distinct from the loader's default port 9021.

## Console validation command

```sh
# Live, state-changing test of the server's own disposable child; not a probe.
python3 host/validate_debugger.py --host "$PS5_HOST"   --elf out/process-debugger.elf --report captures/debugger-validation-NEW.json
```

Use this only in an authorized current session, without another GDB client.
The report is created exclusively and preserves replies/hash. The full suite
currently fails on the known-disabled retail 13.60 data-watchpoint path; that
expected failure is not justification to enable a PCB writer or resend a payload.
No live execution is needed to validate a documentation change.
