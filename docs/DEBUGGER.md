# Process debugger: CLI runbook

This is a **usermode, single-process, all-stop** GDB remote server. Use it to
inspect a known live homebrew process, read GP registers/memory, and step
instructions. It is not a kernel debugger, launcher, crash-dump server, or
complete replacement for gdbserver.

Read [the dated recovery note](DEBUGGER_RECOVERY.md) before a new console run.
[Validation](DEBUGGER_VALIDATION.md) records what actually passed; the
[agent guide](DEBUGGER_AGENTS.md) and [packet reference](DEBUGGER_PROTOCOL.md)
provide automation details. This runbook describes intended client workflows;
a stock GDB client has not yet passed live integration testing with this stub.

## Capability and evidence

| Operation | Current implementation | Console evidence |
| --- | --- | --- |
| Attach by numeric PID | One PID; rejects PID 1 and itself; stops process | Disposable child only |
| Enumerate/select LWPs | At most 256 threads | Child enumeration; multithread control unvalidated |
| GP registers / small memory reads and writes | Available while stopped; user addresses only | Read/write/restore passed on the child |
| Instruction step | Single selected LWP; other enumerated LWPs suspended during step | Single-thread child passed |
| Continue | Resumes process; waits for next stop | Execution breakpoint reached on child |
| Hardware execution breakpoints | Free DR0–DR3 slots shared across current LWPs | Child-only slot lease used to prove an execution trap |
| Software breakpoints (`Z0`) | Plant `INT3` in the process; at most 64; no debug-register slots | Host-tested (insert, shadow, hit, step-over, occupied DRs). Not console-tested |
| Z2/Z4 data watchpoints | Rejected on retail 13.60 | Insertions in an earlier build did not fire |
| Read-only watchpoints | Unsupported | No claim |
| Detach / disconnect restoration | Explicit detach and cleanup paths exist | Some detach replies OK; full execution/reconnect test incomplete |
| Kernel breakpoint at `0xcfc12` | Not supported | Requires a separate kernel backend |

The current source verifies debug-register address/control readback after every
write and rollback. This catches rejected/sanitized state. It does **not** prove
that a data watchpoint will trap. Direct PCB writes have been removed and the
old `PROCESS_DEBUGGER_KERNEL_DBREGS` build flag causes a compile error.

## 1. Establish the session

Record the current console address, firmware/model, resident state (including
kstuff), loader availability, authorized process identity/PID, and debugging
objective. Determine whether inspection, stepping, writes and continued
execution are within the existing task authorization. Use a current PID; a title
ID, historical PID or dead process is not an attachment target.

The last recorded console state is offline after run 007, not a standing claim
that the console is ready. Do not send a payload based solely on an old address,
a successful ping, or a historical Relapse GET. A ping can establish reachability
but does not establish a working jailbroken loader session.

The server binds all IPv4 interfaces on its configured port, with no
application authentication or TLS. Use a controlled network reachable only by
the debugging participants. The debugger allows memory/register writes and
explicit target termination; its port is not an HTTP health endpoint.

## 2. Build with the homebrew-tools spec

Use the public Payload SDK and LLVM 18. Follow [building](BUILDING.md) to set
`PS5_PAYLOAD_SDK` and `LLVM_CONFIG`, or use the reference container.

```sh
make process-debugger
make check
make checksums
```

The artifact is `out/process-debugger.elf`. Keep its SHA-256, source commit and
dirty diff, compiler/SDK identity, and flags with the session. Changing flags or
SDK/compiler paths does not invalidate Make's timestamp cache: remove the
specific generated ELF first or use a fresh build directory.

In this workspace the normal build host is **gpubox**. Its recorded SDK/LLVM
locations and build command are in [the validation record](DEBUGGER_VALIDATION.md#historical-final-build).
Use an isolated source/build directory when the existing gpubox checkout has
unrelated work. This repository uses the SDK startup/runtime; a research-runtime
ELF compiled with Mac LLVM 23 is not a substitute.

To change the listener, rebuild explicitly, for example:

```sh
# A new port is a configuration choice, not automatic timeout recovery.
rm -f out/process-debugger.elf
make process-debugger CPPFLAGS=-DPROCESS_DEBUG_PORT=1234
```

Default port: **1234**, fixed at build time. The server does not scan for a
spare port. Binding failure returns 2 and does not print the ready marker.
The original prosper0gdb research listener has different behavior; its port
scanning does not apply to this payload.

## 3. Deploy once and preserve evidence

Create a fresh session directory, then set `PS5_HOST` to the current confirmed
console address. The following command contacts the loader and executes code;
it belongs only in an authorized, ready console session.

```sh
mkdir -p captures
SESSION="$(mktemp -d "$PWD/captures/debugger-XXXXXX")"
export SESSION
# Set PS5_HOST explicitly before this step.
python3 host/send_payload.py out/process-debugger.elf   --host "$PS5_HOST" --port 9021 --idle-timeout 60   --log "$SESSION/loader.log"
```

Ports have different purposes:

| Port | Purpose |
| --- | --- |
| 9021 by sender default | Loader receives one ELF and streams payload output |
| 1234 by debugger default | GDB Remote Serial Protocol (RSP) session |

Wait for `process-debugger: ready pid=... port=... (ptrace backend)` in the
loader log. The sender creates `loader.log.json` beside the raw log. Sender exit
status describes transport, not console success. Its idle timeout can leave the
server running; never resend merely because output became quiet. If an older
server owns the port, do not start another version on a series of new ports.
Establish ownership and cleanup first.

## 4. Connect one GDB client

Use a GDB build with x86-64 support on a host that can reach the console. Obtain
its version and start without local init files:

```sh
gdb --version
gdb -nx -q
```

From the repository root, source the checked-in local compatibility settings:

```gdb
source docs/debugger/compat.gdb
```

This profile only configures the client. It does not connect, attach or resume.
It selects x86-64/all-stop, bounded connection waits, small memory packets,
legacy resume packets, and a zero hardware-watchpoint limit. Disabling vCont
avoids GDB emitting a multi-action resume list that this server cannot parse.
The four-slot client limit is an upper bound, not a grant of four free slots.

Replace the placeholder values below. Log paths must be new per session;
these are GDB commands, so shell variables such as `$PS5_HOST` are not expanded.

```gdb
set logging file /ABSOLUTE/SESSION/gdb.log
set logging overwrite off
set logging enabled on
set remotelogbase hex
set remotelogfile /ABSOLUTE/SESSION/rsp.log
file /ABSOLUTE/PATH/TO/MATCHING_TARGET.elf
target extended-remote CONSOLE_ADDRESS:1234
attach PID_DECIMAL
```

The local symbol file belongs to the **target application**, not to
`process-debugger.elf`. If symbols are unavailable, omit `file` and inspect
runtime addresses. `target extended-remote` connects to an existing server;
`attach` stops an existing process. `run`, `start` and remote `load` are not
supported launching workflows here.

If GDB rejects a compatibility setting, record the version and its error and
check the upstream manual; do not silently remove the limit or assume the
server gained a capability. Both the CLI profile and GDB/MI examples still
need a stock-client console validation run.

## 5. Inspect before changing execution

```gdb
info threads
info registers
p/x $pc
x/8i $pc
x/8gx $rsp
maintenance packet qPS5:dbregs
```

`maintenance packet` keeps diagnostics on the same connection. `monitor` is
not a substitute: this server does not implement qRcmd. Do not open a second
RSP client or run the console validator beside GDB. The server accepts one
client and one attached process at a time.

`thread N` selects GDB's client thread ID, which is not necessarily the remote
LWP ID printed in a raw stop packet. Register and memory inspection requires a
stopped target. Reads are limited to 1,024 bytes per memory packet; the profile
uses smaller packets. Unavailable FP/vector registers are not zero values.

A backtrace (`bt 8`) may help if matching relocated symbols and unwind data are
available. Failed unwinding is not proof of a kernel hang or the absence of a
caller. Avoid evaluating target function calls through `print` or `call`.

## 6. Step and use breakpoints

For one authorized instruction step:

```gdb
stepi
p/x $pc
x/8i $pc
```

Bound the number of steps and capture each stop. `next`, `nexti`, `finish`,
`until`, source-level `step`, and inferior function calls plant temporary
software breakpoints. Those `Z0` packets are implemented; the combined GDB
workflows are not console-tested. Scheduler-locking settings do not establish a
new server guarantee: `continue` resumes the process, not just the selected thread.

On a kstuff session, use a software breakpoint. It plants `INT3` and does not
need a debug-register slot:

```gdb
break *0xVERIFIED_RUNTIME_USER_ADDRESS
info breakpoints
continue
```

Inspect the RSP log for `Z0` / `OK` and a later stop containing `swbreak:;`.
GDB's `break` is the kstuff-compatible path. `hbreak` still needs a free DR.

Use a verified **runtime user address** for a hardware breakpoint when slots
are free:

```gdb
hbreak *0xVERIFIED_RUNTIME_USER_ADDRESS
info breakpoints
continue
```

GDB can defer insertion until resume. A breakpoint listed in `info breakpoints`
is only a client request; inspect the RSP log for the Z1 reply and the subsequent
stop. Stop execution with Ctrl-C if the agreed stop condition is not reached;
wait for a stop reply before issuing inspection or detach commands.

If all four DR slots are occupied, `Z1` returns ENOSPC. Use `break` / `Z0`
instead. In run 003 the slots were already occupied by kstuff-related state.
Do not clear those registers, borrow kernel slots, restart kstuff, or enable a
PCB-writing flag. The `qPS5:test-hardware` lease is restricted to the server's
own disposable child and cannot repair slot exhaustion in a real application.

Remove only breakpoints created by this session, using their GDB numbers:

```gdb
delete BREAKPOINT_NUMBER
```

## 7. Symbols and ASLR

The server does not provide module mappings, library enumeration, executable
paths or automatic ASLR relocation. Establish the runtime module identity and
load bias from independent current-session evidence. A file offset, ELF virtual
address and runtime address are different quantities.

For a PIE ELF with one verified load bias, GDB can relocate local symbols with
`symbol-file -o LOAD_BIAS /path/to/target.elf`. This is a local symbol operation;
it does not change the target's mappings. For modules requiring separate section
addresses, use the upstream `add-symbol-file` documentation. Do not guess a
slide from an old capture, subtract arbitrary bases, or reuse a kernel dump's
base for a user process. Check disassembly at a known runtime instruction before
trusting symbol-based breakpoints.

`0xcfc12` in the Chain Test investigation is a **kernel offset**, not a valid
way to locate this server's usermode breakpoint target. See
[recovery and kernel scope](DEBUGGER_RECOVERY.md#kernel-offset-0xcfc12).

## 8. Detach and close

When stopped, remove session-created breakpoints, issue `detach`, record its
reply, then quit GDB. The detach implementation restores saved debug registers
and releases debugger-owned stepping/suspensions. These are implementation
paths; the complete resume/reconnect cleanup sequence has not passed live tests.

A lost connection triggers server-side cleanup attempts. If detach fails, the
server retries rather than exiting while still attached. A new connection may
queue while cleanup is pending; successful TCP connect does not prove the
server is ready to service a new client. Do not force-kill the server as automatic
recovery: exiting a tracer can affect its tracee. Report unknown cleanup state.

`maintenance packet qPS5:shutdown` returns OK only when no target or disposable
child remains. It ends the server, not the application. Use it only when server
shutdown is in the existing task scope. `kill` / `vKill` terminates the target
and is not equivalent to detach.

## Batch capture and automation

Use the [agent guide](DEBUGGER_AGENTS.md#batch-inspection) for a bounded batch
inspection file and a GDB/MI request sequence. Do not automate repeated attach,
resume, reconnect or payload deployment loops. GDB can abort a batch file on an
error before its trailing detach executes; preserve that exit status and
establish the actual session state before another action.

## Troubleshooting

| Observation | Interpretation and next action |
| --- | --- |
| No ready marker | Loader/runtime status unknown or bind/startup failed; preserve log; do not resend automatically |
| Connection refused on 1234 | No GDB listener at the debugger port; confirm the process-debugger payload is running. For loader port 9021, classify ping vs send with [black-session classes](TROUBLESHOOTING.md#black-session-classes) |
| TCP connects but commands stall | Another client or cleanup may own the server; stop duplicate clients and establish ownership |
| Attach returns ESRCH | PID missing, dead, inaccessible, or not visible under current platform rules; do not substitute a title ID |
| Attach EACCES/EPERM | SDK kernel/credential access or target policy unavailable; do not patch a system process to make it work |
| Attach wait times out | A ptrace attempt may already have changed ownership; record failure and cleanup status |
| ENOSPC / E1C on Z1 | No common free hardware slot across current LWPs; inspect dbregs and preserve other owners |
| EIO / E05 on a register update | Write/readback or rollback failed; no trap success is established; stop and collect evidence |
| Z2/Z4 unsupported on 13.60 | Known capability restriction; increasing timeouts will not enable watchpoints |
| Generic T05 stop | SIGTRAP with no proven breakpoint identity; stale DR6 was observed; do not label a watchpoint hit without evidence |
| GDB sends vCont with multiple actions | Apply the profile before connecting; record packet trace; server supports only a single action |
| Chain Test black screen, PPSA90001 gone | No live title process to attach; this is not fixed by attaching NPXS40087 or a kernel offset |

## Validation and references

`make check` runs host tests without console access. The full
`host/validate_debugger.py` suite mutates its disposable child and checks data
watchpoints; it is expected to fail at the disabled 13.60 data-watchpoint check.
It is not a passive probe and should not be run alongside GDB. Read the
[validation guide](DEBUGGER_VALIDATION.md) before any new authorized live test.

Upstream command references: [connecting](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Connecting.html),
[remote configuration](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Configuration.html),
[logging](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Logging-Output.html),
[symbol files](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Files.html).
Repository source and recorded console evidence determine which features
actually apply here.
