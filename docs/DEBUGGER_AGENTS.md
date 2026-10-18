# CLI debugging with an LLM agent

Use this document as the task contract for an agent controlling this repository's
process debugger. The [CLI runbook](DEBUGGER.md) covers human operation; the
[protocol subset](DEBUGGER_PROTOCOL.md) determines what automation may assume.
Read [the recovery note](DEBUGGER_RECOVERY.md) and [validation history](DEBUGGER_VALIDATION.md)
first. These instructions do not supply missing authorization or make a dead
console/process reachable.

## Session facts and authorization

Before connecting, assemble these facts from current evidence and the user's
existing instructions. Ask only for facts/authorization that are actually missing;
continue useful offline work while waiting.

| Fact | Example shape, not a default |
| --- | --- |
| Objective and target scope | Inspect a specific live homebrew PID for a bounded launch diagnosis |
| Console and connectivity | Current host, firmware/model, reachable authorized loader/session |
| Resident state | kstuff version/profile or explicit absence; DR ownership unknown until inspected |
| Debugger identity | Source commit, dirty diff, SDK/LLVM, flags, SHA-256, listener port |
| Target identity | Numeric PID, process name/start/lifetime, title if relevant, current existence |
| Symbols and addresses | Matching unstripped ELF/hash and verified runtime load bias |
| Allowed actions | Inspection, a step budget, specific writes/breakpoints/resumes if authorized |
| Stop conditions | Maximum steps/time/hits, expected event, errors requiring handoff |
| Evidence destination | A fresh local session directory; loader and RSP logs |

A title ID is not a PID. `PPSA90001` was already gone at the observed Chain Test
black screen. `NPXS40087` attachment is unvalidated. The same failure cannot be
investigated by assuming either a dead process or a different system title is
an interchangeable target. Kernel offset `0xcfc12` requires a kernel tracing
backend, not this server. The separate [kernel offset inspection backend](KERNEL_DEBUGGER.md)
resolves the saved image and probes gated bytes; it does not yet install traps.

## State machine

Track state explicitly instead of interpreting every successful command as a
successful diagnosis:

```text
unknown -> ready server -> one connected client -> attached/stopped
attached/stopped -> inspecting -> attached/stopped
attached/stopped -> one resume pending -> stopped OR exited OR unknown
attached/stopped -> detach acknowledged -> resumed (needs observation)
any transport/cleanup failure -> unknown -> collect evidence / operator handoff
```

A TCP connection, `^connected`, qSupported response, client-side breakpoint
record, `PT_SETDBREGS` success and a matching register readback are different
pieces of evidence. None alone proves a breakpoint hit. A historical run does
not validate a newly built ELF. Do not call attach/inspection "read-only": it
stops the process and uses SDK credential/debug-state operations even if the
subsequent GDB commands only read values.

## Default execution policy

Use existing task authorization without repetitive confirmation. Operate only
within its identified target, mutations and execution budget. Begin with small
inspections; keep steps/resumes individually observable. When a requirement
needs kernel tracing, data watchpoints on 13.60, or a free slot that does not
exist, report the missing capability rather than escalating to a PCB writer,
clearing another owner's DR state, changing kstuff, or attaching another title.

The console is recorded offline after run 007. No deployment follows from this
documentation task. Re-establish the actual console/session state before a new
live run. Stop resends/reconnect loops on an unknown state; builds and host tests
can continue independently.

## CLI setup and logging

Launch `gdb -nx -q` and `source docs/debugger/compat.gdb` before connection.
The profile makes no target connection. Use the [runbook's logging settings](DEBUGGER.md#4-connect-one-gdb-client)
with new session-local paths, then connect to the current server and attach the
authorized PID. Do not feed GDB command text to a shell: `$pc` and `$rsp` belong
to GDB, and shell expansion would change them.

Once stopped, a useful bounded inspection is:

```gdb
info threads
info registers
x/8i $pc
x/8gx $rsp
maintenance packet qPS5:dbregs
```

If stepping is authorized, do one `stepi`, wait for its stop, record RIP and
nearby instructions, then decide whether the budget allows another step.
Never replace this with an unlimited `while`/auto-continue script. A selected
GDB thread does not isolate `continue` to that thread.

Use `hbreak` for a verified runtime user address, never `break` or an assumed
software-breakpoint fallback. GDB may defer the actual Z1 insertion until
resume. Keep breakpoint numbers owned by this session and remove only those.
The default profile sets the hardware-watchpoint limit to zero; do not issue
`watch` and rely on GDB's software-watchpoint fallback. Z2/Z4 are disabled on
retail 13.60, and a raw maintenance packet cannot enable them.

Do not use `run`, `start`, `load`, `call`, `print function()`, reverse execution,
`next`, `finish`, or signal-delivery resume as established workflows. The current
stub lacks the complete features those operations can need.

## Batch inspection

For a short inspection that never resumes after attachment, prepare a NEW
session file, replace every placeholder, and review it before invoking GDB:

```gdb
# SESSION/inspect.gdb -- example, not a prevalidated live script
source docs/debugger/compat.gdb
set logging file /ABSOLUTE/SESSION/gdb.log
set logging overwrite off
set logging enabled on
set remotelogbase hex
set remotelogfile /ABSOLUTE/SESSION/rsp.log
file /ABSOLUTE/PATH/TO/MATCHING_TARGET.elf
target extended-remote CONSOLE_ADDRESS:1234
attach PID_DECIMAL
info threads
info registers
x/8i $pc
x/8gx $rsp
maintenance packet qPS5:dbregs
detach
quit
```

Run from the repository root, preserving stdout, stderr and exit status:

```sh
# SESSION must already name a new directory and inspect.gdb must be reviewed.
gdb -nx -q --batch -x "$SESSION/inspect.gdb"   >"$SESSION/batch.stdout" 2>"$SESSION/batch.stderr"
```

Batch success is not proof the detached application continued correctly. Batch
failure may skip the trailing detach; an external shell `timeout` can terminate
GDB before cleanup. Do not force `set confirm off`, auto-kill a target, or
launch a fresh debugger on the assumption that exit cleaned everything up.
Record the last completed operation and establish the stopped/running/unknown
state. Prefer an interactive controller for workflows needing controlled
interrupt and cleanup handling.

## GDB/MI for structured controllers

GDB/MI can give an LLM harness structured responses. Start a persistent process
with `gdb -nx -q --interpreter=mi2`, maintain one client connection and parse the
MI grammar instead of screen-scraping prompts. This is a proposed client
integration; no MI-based live PS5 session has yet been validated.

Illustrative requests below contain placeholders and are sent to GDB stdin,
not to a shell. Send each request only after its predecessor's appropriate
result/state has been handled:

```text
1-gdb-set pagination off
2-gdb-set architecture i386:x86-64
3-gdb-set non-stop off
4-gdb-set remotetimeout 10
5-gdb-set tcp auto-retry off
6-gdb-set remote verbose-resume-packet off
7-gdb-set remote hardware-watchpoint-limit 0
8-gdb-set remote memory-read-packet-size 256
9-gdb-set mi-async on
10-target-select extended-remote CONSOLE_ADDRESS:1234
11-target-attach PID_DECIMAL
12-thread-info
13-data-list-register-names
14-data-list-register-values x 0 1 2 3 4 5 6 7 16 17
15-data-read-memory-bytes "$rsp" 64
16-interpreter-exec console "maintenance packet qPS5:dbregs"
```

Apply the remaining local profile settings through `-gdb-set` or source the
profile through `-interpreter-exec console` before connecting. Select threads
using MI's IDs from `-thread-info`, not the raw LWP IDs. Query register names
before assuming a client's register numbering; the wire map is documented in
the packet reference. Do not assert a stopped target merely because attach
produced a result record; consume and correlate the stop notification too.

For an authorized instruction step:

```text
17-exec-step-instruction
```

A `17^running` result (or a running notification) starts the execution phase.
Wait for the corresponding `*stopped` or exit notification before the next
inspection. A command token correlates its result record; asynchronous `*` and
`=` notifications need state-based correlation and are not guaranteed to carry
that token. MI console/log/target stream records use quoted escaped strings;
parse them rather than treating `~`, `&`, or `@` records as command results.

For an authorized hardware breakpoint, use `-break-insert -h` with the verified
runtime location. For an authorized continue use `-exec-continue`, and wait for
a stop/exit under the agreed time budget. `-exec-interrupt` requests interruption
when asynchronous operation is supported; its acknowledgement is not a stop.
On this server the resulting wire interruption uses Ctrl-C and the stop can
be SIGSTOP rather than SIGINT. Never send a second RSP request while a resume
reply is pending. The controller talks MI to GDB; it does not also own the RSP
socket directly.

When stopped and cleanup is authorized, remove session-created breakpoints,
then send `-target-detach`, capture its result and application-state evidence,
and use `-gdb-exit`. Treat `^error` as an operation failure; do not endlessly
retry. For custom `maintenance packet` commands, parse the remote reply inside
MI output even when the outer result is `^done`.

## Evidence and handoff format

A useful handoff includes:

```text
Objective / authorized target and actions:
Source commit + dirty diff / SDK / compiler / build flags:
Debugger ELF SHA-256 / listener port:
Console model / firmware / resident state / readiness evidence + timestamp:
Target identity / PID / GDB thread / wire LWP / target ELF / ASLR evidence:
Commands issued and last confirmed operation:
Observed stop reason / RIP / registers / breakpoint insertion reply:
Timeouts, errors, and remaining execution budget:
Cleanup replies / target running-stopped-exited-unknown / server state:
Artifact paths and open hypotheses:
```

Separate observations from hypotheses. "T05 at verified execution address"
and "data watchpoint did not fire in the test budget" are observations.
"The PCB fallback caused the console hang" is not established: run 007 had no
startup log. Never describe a generic trap as proof of a data-watchpoint hit.

## Context7 retrieval

Resolve this repository by its full name and task before querying it. Confirm
the returned ID and branch/version instead of inventing an ID. Query the current
capability, recovery and agent guides together when planning live CLI work.
If the repository is not indexed, read these local Markdown files directly.
Use the separately resolved GNU GDB docs for CLI/MI syntax and the public Payload
SDK docs/source for SDK APIs. Do not infer server capabilities from generic GDB
or gdbserver documentation. See [Context7 setup and prompts](CONTEXT7.md).

Upstream references: [MI interface](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI.html),
[MI execution](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Program-Execution.html),
[MI target manipulation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Target-Manipulation.html).
