# Process debugger: protocol reference

This reference describes `payloads/process-debugger/main.c` and the imported
packet transport, not the full GDB remote protocol. Use [the CLI runbook](DEBUGGER.md)
for operations and [the agent contract](DEBUGGER_AGENTS.md) for automation.
Implemented packets are not evidence of successful console validation.

## Transport, identifiers and limits

- One TCP client, one attached usermode process, all-stop behavior.
- ASCII RSP framing: `$PAYLOAD#CHECKSUM`, checksum is the byte sum modulo 256
  encoded as two hex digits. Normal `+` acknowledgements are required in both
  directions. The server does not implement no-ack negotiation.
- No binary `X` memory writes, escape/RLE protocol extensions, compression, or
  binary file transfer. Invalid checksum, EOF, embedded NUL/non-ASCII commands
  or an overlong input packet close the session; do not rely on retransmission.
- `PacketSize=1000` is hexadecimal: at most 4,096 payload characters accepted.
  Memory `m`/`M` transfers have a separate **1,024-byte** limit (hex `400`).
- Addresses/lengths/PIDs/TIDs/register numbers in packets are hexadecimal.
  GDB CLI `attach` takes the numeric PID in its CLI syntax; it performs encoding.
  Wire TIDs are LWP IDs, not GDB's displayed thread numbers or PS5 title IDs.
- Integer parsing accepts at most 16 hex digits. Attach PID must be greater
  than 1, at most `0x7fffffff`, and different from the debugger server PID.
- Target memory and breakpoint addresses are user addresses below `1 << 47`.
  Kernel memory is not exposed by `m`/`M`; kernel breakpoints are unsupported.
- Thread count is capped at 256. Registers/debug state are obtained while the
  process is stopped. New threads are discovered at subsequent stops, not at
  every thread creation event while running.

## Connection and process packets

| Packet | Reply / behavior | Limit |
| --- | --- | --- |
| `qSupported:...` | `PacketSize=1000;qXfer:features:read+;vContSupported+;hwbreak+` | Features advertise implementation, not validated runtime support |
| `!` | `OK` | Extended mode acknowledgement; does not implement launch |
| `vMustReplyEmpty` | Empty packet | Negotiation |
| `qAttached` | `1` with a target PID; otherwise `0` | Does not independently prove a successful stopped attach |
| `vAttach;PID` | Stop reply or `Exx` | Attach may have partially succeeded before an error |
| `?` | Current stop/exit reply | With no target can return `W00`; that alone does not prove a known process exited |
| `D` / `D;PID` | `OK` after restoring/debug-detaching; or `Exx` | Tagged PID must match target; resumes via PT_DETACH |
| `vKill;PID` | `OK` after killing/waiting, or `Exx` | Destructive; only current stopped target; not detach |
| `qXfer:features:read:target.xml:OFFSET,LENGTH` | `m...` / `l...` XML chunks | Minimal x86-64 / FreeBSD target declaration |

`vRun`, fork/exec following, multiprocess IDs (`pPID.TID`), non-stop mode,
`qXfer:exec-file`, library/memory maps, qRcmd/`monitor`, TLS address resolution,
remote file I/O and remote executable loading are not implemented. Unsupported
queries generally receive an empty packet while attached; the generic target
state gate can instead return ESRCH before attachment.

## Threads and register packets

| Packet | Meaning |
| --- | --- |
| `qfThreadInfo` | One `mTID,TID,...` response after refreshing current LWPs |
| `qsThreadInfo` | `l` (no more thread entries) |
| `qC` | `QC` followed by selected LWP ID |
| `HgTID` | Select register-inspection LWP; `0`/`-1` select stopping LWP |
| `HcTID` | Store preferred resume/step LWP; `0`/`-1` clear preference |
| `TTID` | Verify a listed LWP, reply `OK` or error |
| `g` | 560-byte register layout encoded as 1,120 characters; only first 164 bytes available |
| `pNUMBER` | One GP/core register, or empty for an unsupported register |
| `PNUMBER=VALUE` | Write one available core register, little-endian bytes |
| `G...` | Write full core layout; remaining unavailable fields must retain `x` placeholders |

Core register layout:

| Wire register numbers (hex) | Order | Width each |
| --- | --- | --- |
| `0`–`f` | rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8–r15 | 8 bytes |
| `10` | rip | 8 bytes |
| `11`–`17` | eflags, cs, ss, ds, es, fs, gs | 4 bytes |

For example `p10` reads RIP; `p11` reads EFLAGS. Register bytes are hex-encoded
in little-endian order, not a text-formatted numeric value. Unavailable FP/vector
registers are `x` placeholders, not zeroes. The server does not supply FS/GS base
registers, FP register access or a complete extended-register target XML.

Selecting a thread does not turn a process continue into thread-isolated
execution. `Hc` and the optional vCont TID select/validate context; a normal
continue resumes the process. Instruction step uses the selected/preferred LWP
and temporarily suspends the other currently enumerated LWPs. This multithread
path is host-tested only.

## Memory and resume

| Packet | Behavior |
| --- | --- |
| `mADDRESS,LENGTH` | Read at most 1,024 user bytes; returns hex or error |
| `MADDRESS,LENGTH:HEX` | Write exact hex bytes while stopped; `OK` or error |
| `c` / `cADDRESS` | Continue; optional address updates selected LWP RIP |
| `s` / `sADDRESS` | Single instruction step; optional address updates RIP |
| `vCont?` | `vCont;c;s` |
| `vCont;c` / `vCont;s` | One continue/step action |
| `vCont;c:TID` / `vCont;s:TID` | One action with a validated hex LWP ID; `-1` accepted |
| Raw byte `0x03` while running | Request SIGSTOP, then report the stop |

Only a **single** vCont action is parsed. `vCont;s:TID;c` and similar lists
return an error. Use the CLI compatibility profile to request legacy c/s from
GDB. `C`, `S`, signal-bearing vCont, reverse execution, range step and remote
function calls are unsupported. Resuming normally suppresses the pending signal
by passing zero to PT_CONTINUE; an agent must not silently discard an unexpected
application signal by repeatedly continuing.

Resume receives a transport acknowledgement; its semantic reply arrives when
the target stops/exits. There is no immediate `OK` for c/s. Do not send another
request on that connection while a resume reply is pending. A controller timeout
is not evidence that the process stopped or that the breakpoint was ineffective.

## Hardware breakpoints

| Packet type | Meaning | Current status |
| --- | --- | --- |
| `Z0` / `z0` | Software breakpoint | Unsupported (empty reply) |
| `Z1` / `z1` | Execution breakpoint | Kind/length must be 1; a common free slot is required |
| `Z2` / `z2` | Write watchpoint | Disabled on retail 13.60; earlier insertions failed to fire |
| `Z3` / `z3` | Read-only watchpoint | Unsupported (empty reply) |
| `Z4` / `z4` | Read/write watchpoint | Disabled on retail 13.60; earlier insertions failed to fire |

Syntax: `ZTYPE,ADDRESS,KIND` and matching lowercase removal. Data-watchpoint
encoding supports 1/2/4/8-byte naturally aligned ranges; that encoding is
host-tested and does not establish actual console support. Other firmware is
unvalidated. Repeated identical insertion/removal is idempotent.

Allocation preserves each current LWP's original DR state and chooses a slot
unused across **all** enumerated LWPs. It never automatically evicts kstuff.
Four occupied slots means ENOSPC even if the client permits four breakpoints.
Application and rollback writes are read back: DR0–DR3 addresses and DR7 slot
fields must match. Reserved bits and stale DR6 status are excluded from this
comparison. Failure produces EIO; unsuccessful rollback poisons resume and
breakpoint operations. Readback success alone cannot establish a trap.

No direct PCB register writer remains. The retired build macro is a compile
error, not a hidden method of enabling 13.60 watchpoints.

## Stop replies

- `Tss` includes `thread:TID;` for a stopped target.
- Proven hardware execution events can include `hwbreak:;`.
- Data-watchpoint formatting exists for `watch:ADDRESS;` and `awatch:ADDRESS;`,
  but no successful retail 13.60 data-watchpoint test is claimed.
- `Wxx` denotes the recorded normal exit code; `Xss` denotes recorded signal
  termination. Correlate replies with the actual attached PID and operation.

PS5 DR6 values were stale in live tests. The server supplements them with
conservative trap-context checks; a generic T05 is not proof that a particular
watchpoint fired. Do not translate a raw FreeBSD signal/errno using a Linux
host's numeric tables without checking the target ABI.

## Custom diagnostic packets

Use `maintenance packet PACKET` in an already connected GDB session. Replies
appear in CLI output; GDB/MI `^done` for the maintenance command does not mean
the remote packet returned OK. Check the actual response.

| Packet | Preconditions | Reply / effect |
| --- | --- | --- |
| `qPS5:dbregs` | Attached and stopped | `dr0:HEX;dr1:HEX;dr2:HEX;dr3:HEX;dr6:HEX;dr7:HEX` for selected LWP |
| `qPS5:spawn-test` | No target and no existing owned child | Creates a disposable child; `pid:HEX;pc:HEX;watch:HEX;done:HEX` |
| `qPS5:test-hardware` | Attached to this server's own single-thread child; no active session breakpoints | Temporarily borrows inherited slots while retaining original restoration state; cannot be used on an arbitrary app |
| `qPS5:finish-test` | Owned child detached | Kills/reaps only that child; OK or error |
| `qPS5:shutdown` | No attached target and no owned child | OK, then server closes and exits |

The child persists after a client disconnect in current source, so that a
reconnecting validation client can inspect cleanup. It still needs explicit
finish/reaping. An old server version may behave differently; identify its hash.
None of these packets is a general command shell or kernel breakpoint interface.

## Errors and state

Error packets are `E` plus two hexadecimal digits of the target/native errno.
Common PS5/FreeBSD cases include:

| Reply | Meaning in this implementation |
| --- | --- |
| E01 | EPERM; rejected operation/child-only lease/target policy |
| E03 | ESRCH; absent target/LWP or invalid attachment state |
| E05 | EIO; ptrace/readback/rollback or credential restoration problem |
| E07 | E2BIG; thread count exceeded cap |
| E0D | EACCES; SDK credential access unavailable |
| E0E | EFAULT; memory operation failed/short transfer |
| E10 | EBUSY; existing target/child or invalid lifecycle operation |
| E16 | EINVAL; malformed packet/address/unsupported resume form |
| E1C | ENOSPC; no common free hardware slot |
| E2D | ENOTSUP; known-disabled data watchpoint path on retail 13.60 |
| E3C | ETIMEDOUT; bounded attach/cleanup wait expired |

Some errors follow partial attachment or mutation. Keep the session state
unknown until detach/restoration or a fresh observation establishes it. Do not
blindly replay commands or restart the server on EIO/timeout.

## Source and external reference

Implementation: [main.c](../payloads/process-debugger/main.c),
[DR7 encoding](../payloads/process-debugger/hwbreak.h),
[transport](../vendor/prosper0gdb/rsp_transport.h), and
[host backend tests](../tests/test_process_debugger.py).
External protocol: [GNU GDB RSP packets](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html)
and [stop replies](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Stop-Reply-Packets.html).
