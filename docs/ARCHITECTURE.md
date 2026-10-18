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
| `host/` | Sending, raw capture, and offline interpretation |
| `mk/` | Shared root-build rules using the external SDK |
| `vendor/` | Imported reader ABI declarations, ioctl definitions and GDB packet transport |
| `residents/` | Historical profiles, marker meanings, and archived patch scripts |
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

There is no general logging library or universal event decoder in this initial
collection. Keep raw output and source identities so future decoders can
interpret the original format accurately.

## Kernel offset inspection path

The separate [kernel offset backend](KERNEL_DEBUGGER.md) resolves explicit
anchors against a hash-checked raw capture on the host. Its one-shot SDK payload
uses live SDK bases, the existing resume profile and page walker to inspect one
seven-byte kernel instruction. It emits a JSON observation, performs no kernel
writes and installs no trap. A saved observation can relocate a host report but
cannot establish present readiness, full running-image identity or DR ownership.
Execution control remains a separate unfinished adapter.

## Process-debugger control path

The process debugger is a long-lived control server with a second TCP channel:
loader transport deploys the ELF and streams stdout; a single GDB client owns
the independent RSP connection. Host send/idle status is separate from debugger
attachment and target execution state. The payload has its own ptrace dispatcher
and reuses the research stub's packet codec; it does not enter prosper0gdb's
ring-0 context or install kernel traps.

SDK helpers temporarily change caller credentials around raw ptrace/signal
syscalls and restore them afterward. Debug registers are allocated only from
unowned slots, written/read back with ptrace, and restored on detach. Failure
paths retain ownership and retry cleanup rather than exiting a tracer blindly.
Direct PCB writes are retired; data watchpoints on retail 13.60 remain disabled.

See [CLI operation](DEBUGGER.md), [wire protocol](DEBUGGER_PROTOCOL.md), and
[agent state handling](DEBUGGER_AGENTS.md). The architecture does not establish
stock-GDB or arbitrary system-process compatibility; consult validation evidence.
