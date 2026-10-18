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
| `vendor/` | Imported reader ABI declarations and ioctl definitions |
| `residents/` | Historical profiles, marker meanings, and archived patch scripts |
| `templates/` | A small SDK project that can be copied independently |
| `tests/` | Host sender behavior checks with mocked connections |
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
