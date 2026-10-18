# Process debugger validation — 2026-10-18

The process server is integrated into the ordinary homebrew-tools SDK build.
It is partially console-tested, not a fully validated arbitrary-process debugger.

## Historical final build

- Build host: gpubox, isolated directory `/tmp/ps5-homebrew-debugger-final`.
- SDK: `/home/shane/stage0-build/ci-sdk/opt/ps5-payload-sdk`.
- LLVM: 18.1.8 from `/home/shane/stage0-build/llvm/bin/llvm-config`.
- Runtime dependency: `LD_LIBRARY_PATH=/home/shane/stage0-build/libdeps/lib/x86_64-linux-gnu`.
- Standard `make all checksums`: passed. The existing resident snapshot source
  emits one unused-function warning; the debugger builds without warnings.
- `make check`: all 42 Python tests and the C paging checks passed on gpubox.
  Local macOS host tests also passed. The research shared-stub suite passed
  its eight protocol tests.
- Final default artifact: `out/process-debugger.elf`, SHA-256
  `d80da62f7ddc90cf89651ca8651043384617563175d02fedb8ac8c35c149fb05`.
  This final artifact was **not deployed** after the console became unreachable.
- Default port: 1234. Retail 13.60 data watchpoints are disabled by default.
  The experimental `PROCESS_DEBUGGER_KERNEL_DBREGS` flag was not used for this
  final build. No LLVM version gate was bypassed.

Reproduce from the repository root on gpubox:

```sh
PS5_PAYLOAD_SDK=/home/shane/stage0-build/ci-sdk/opt/ps5-payload-sdk \
LLVM_CONFIG=/home/shane/stage0-build/llvm/bin/llvm-config \
LD_LIBRARY_PATH=/home/shane/stage0-build/libdeps/lib/x86_64-linux-gnu \
make all checksums check
```

The original gpubox checkout at `/home/shane/ps5-homebrew-tools` was not edited.
The isolated final source/build and captured logs remain on gpubox.

## Console evidence

Console: the existing PS5 Pro 13.60 research console, address 192.168.87.247.
These tests used only disposable children created by the debugger. No system
application or game was selected as a debug target. The console model/firmware
labels come from the established workspace record; these runs did not capture
a new independent hardware-identification manifest.

Raw evidence is retained locally under `captures/debugger-20261018/` (ignored
by Git), including all seven JSON transcripts, payload logs, and gpubox hashes.
The remote originals are `/tmp/process-debugger-validation-20261018-00N.json`
and `/tmp/process-debugger-console-20261018-00N.log` on gpubox.

| Run / port | Result |
| --- | --- |
| 001 / 1234 | Server startup and protocol negotiation passed; libc ptrace returned a non-success value without attaching; wait timed out. |
| 002 / 1235 | Added diagnostics and bounded waits; confirmed attach did not complete. |
| 003 / 1236 | SDK raw syscall plus temporary credentials: PID attachment, thread enumeration, GP registers, register/memory write-read-restore, and instruction stepping passed. All debug slots were already occupied, so hardware insertion correctly returned no space. |
| 004 / 1237 | Test-child-only slot lease allowed execution-breakpoint insertion and a SIGTRAP at the breakpoint; DR6 did not identify the hit. |
| 005 / 1238 | Confirmed hardware execution trap RIP matched the requested address while DR6 retained stale BS status. |
| 006 / 1239 | Conservative execution-trap classification produced `hwbreak:;`. Data watchpoint insertion succeeded but no data-watchpoint stop arrived. Full validation failed. An instrumentation bug printed the poll line repeatedly; the final source fixes that. |
| 007 / 1240 | Experimental checked PCB fallback compiled and was sent. No startup log was received. The console subsequently did not respond to network checks. No successful fallback execution is claimed. |

Run 006 proves hardware **execution** breakpoints on the disposable child.
It does not prove data watchpoints. The default build returns an explicit
unsupported error for 13.60 data watchpoints instead of accepting a breakpoint
that has failed to fire in testing. x86 read-only watchpoints remain unsupported.

The temporary slot lease is restricted to the server's own test child; arbitrary
targets cannot clear other owners' allocations with that command. Original
register state is retained for restoration. The raw transcript can be reviewed
for exactly which commands completed; no full validator run passed.

## Remaining work and console state

- Confirm the console's physical state and restore its reachable homebrew
  environment before further deployment. The reason it stopped responding is
  unknown. It is not established that the PCB fallback executed.
- Confirm cleanup of temporary validation servers and children. Several server
  versions were left resident while debugging ports 1234–1240; cleanup after
  loss of connectivity could not be verified. A console restart, if performed
  by the operator, ends these volatile processes.
- Investigate data traps and credential restoration using a bounded, separately
  authorized test. The historical direct-PCB fallback is retired from current
  source, its build macro is rejected, and it must not be sent into kstuff.
  See [recovery and kernel scope](DEBUGGER_RECOVERY.md).
- Finish data watchpoints, detach/resume, disconnect cleanup, and signal delivery
  tests. Some detach commands returned OK; full post-detach execution and
  reconnect validation did not complete.
- Test a real GDB client, multiple threads and thread creation, module/symbol
  discovery, and arbitrary system/game attachment subject to PS5 AppContext
  rules. The existing tests establish attachment to our child, not every PID.

## Source hardening and documentation follow-up

The current working changes retire the direct-PCB writer and reject the old
build macro. Ptrace debug-register writes and rollback now require address/DR7
slot-field readback. Regression checks cover reported-success sanitization,
rollback, and all-four-slots-owned refusal. These are host checks, not a fix or
live proof of data watchpoints. The 13.60 disable remains.

The original `d80da62f...` record above is historical (209,304 bytes), not the
identity of a newly built hardened payload. No follow-up console deployment is
part of the docs/hardening work. Current operation instructions are in the
[CLI runbook](DEBUGGER.md), [agent contract](DEBUGGER_AGENTS.md), and
[protocol reference](DEBUGGER_PROTOCOL.md).

### Hardened build (not deployed)

The readback/ownership hardening source was built in a new isolated directory
on gpubox: `/tmp/ps5-debugger-hardening-aRhzik`, using the same staged SDK and
LLVM 18.1.8, through `make process-debugger check`. The debugger compiled without
warnings and all **43** Python host tests plus the C paging checks passed.
The legacy-flag rejection and sanitized-register rollback checks are included.

Artifact: 210,272 bytes, SHA-256
`3121031f6acd83fbc3e40c64e020f7cadfbaa38d0a603cd91c5644319cdab817`.
This build has not been sent to the console. The older 209,304-byte
`d80da62f...` artifact and run-007 evidence remain historical. No new live
watchpoint, kernel breakpoint or cleanup claim follows from this build.
