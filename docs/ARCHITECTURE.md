# Architecture

The repository has three executable parts: console payloads, computer-side
utilities, and a standalone payload template. Resident experiments are preserved
as research records and text archives.

```mermaid
flowchart LR
    Source[Payload C source] --> Build[Public PS5 Payload SDK]
    Build --> ELF[ELF in out/]
    ELF --> Sender[Host sender]
    Sender --> Loader[Console ELF loader]
    Loader --> Payload[Diagnostic payload]
    Payload --> Stream[Loader output stream]
    Stream --> Capture[Raw host capture]
    Capture --> V2[V2 thread summarizer]
    V2 --> JSON[JSON summary]
```

The summarizer accepts only v2 thread captures. Other captures remain text for
inspection using their tool documentation.

## Source layout

| Directory | Responsibility |
| --- | --- |
| `payloads/` | Independently compiled console tools and their guides |
| `host/` | Sending, session classification (ICMP only), raw capture, and offline interpretation |
| `common/`, `lib/`, `examples/` | Fixed evidence wire encoding, durable usermode checkpoint client and benign integration example |
| `mk/` | Shared root-build rules using the external SDK |
| `vendor/` | Imported reader ABI declarations, ioctl definitions and GDB packet transport |
| `residents/` | Historical profiles/archives and portable readiness, capture and execution integration cores |
| `templates/` | A small SDK project that can be copied independently |
| `tests/` | Host transport/analysis checks, debugger protocol and ptrace-state mocks |
| `docs/` | Setup, architecture, compatibility, and provenance |
| `out/`, `captures/` | Generated binaries and local observations, ignored by Git |

## Diagnostic boundaries

Shellshot, procwatch, and thread-probe-v1 query process information through
sysctl. V2 additionally reads bounded kernel memory after its firmware/model
gate and live layout check. Reader3 asks an existing instrumented kstuff resident
for a shared-area snapshot.

Reader3 does not install that resident. The root build does not build or run
resident variants. Their archived scripts depend on unrecovered baseline source
and are intentionally outside the executable build.

## Logging formats

Process and thread tools print their own line-oriented records. Reader3 prints
the resident's counters, message ring, and numeric word ring. Its ABI is declared
in [shared_area.h](../vendor/kstuff/uelf/shared_area.h); event meanings are tied
to the producing [resident profile](../residents/README.md).

The [durable evidence path](DURABLE_CHECKPOINTS.md) adds an explicit versioned
binary record for new app checkpoints and resident trace/panic observations.
Its host journal persists records before checkpoint ACKs. It does not reinterpret
legacy reader markers. Keep raw output, per-build site schemas and exact source/
ELF identities. The resident polled exporter still needs a live panic hook and
an independent physical driver; normal scheduling/networking is unavailable
as a dependency during kernel failure.

## Kernel offset inspection path

The separate [kernel offset backend](KERNEL_DEBUGGER.md) resolves explicit
anchors against a hash-checked raw capture on the host. Its one-shot SDK payload
uses live SDK bases, an explicitly linked [readiness provider](KERNEL_READINESS.md)
and the page walker to inspect one seven-byte kernel instruction. A known
historical resume-cookie fallback requires an explicit build option and cannot
rescue malformed, stale or changing handshake evidence. It emits a JSON observation, performs no kernel
writes and installs no trap. A saved observation can relocate a host report but
cannot establish present readiness, full running-image identity or DR ownership.
The separate [SMP coordinator](KERNEL_EXECUTION.md) now models concurrent
stop/step/restore barriers and a polled command mailbox. Its actual resident
rendezvous, architecture stepping, physical transport and restoration adapter
remain unimplemented; native simulation and an SDK object check do not supply
live execution control.

## Process-debugger control path

The process debugger is a long-lived control server with a second TCP channel:
loader transport deploys the ELF and streams stdout; a single GDB client owns
the independent RSP connection. Host send/idle status is separate from debugger
attachment and target execution state. The listener owns connection lifetime;
the RSP adapter owns packets and register encoding; the ptrace provider owns
inspection, execution, breakpoint state and restoration behind a
[typed target API](DEBUGGER_BACKEND.md). Read-only discovery uses bounded
sysctl queries and SDK dynlib helpers; optional register banks use ptrace getters.
Controller interrupts arrive through a callback rather than backend
socket reads. The adapter reuses the research stub's packet codec; it does not
enter prosper0gdb's ring-0 context or install kernel traps.

SDK helpers temporarily change caller credentials around raw ptrace/signal
syscalls and restore them afterward. Debug registers are allocated only from
unowned slots, written/read back with ptrace, and restored on detach. Failure
paths retain ownership and retry cleanup rather than exiting a tracer blindly.
Direct PCB writes are retired; data watchpoints on retail 13.60 remain disabled.

See [CLI operation](DEBUGGER.md), [wire protocol](DEBUGGER_PROTOCOL.md), and
[agent state handling](DEBUGGER_AGENTS.md). The architecture does not establish
stock-GDB or arbitrary system-process compatibility; consult validation evidence.
