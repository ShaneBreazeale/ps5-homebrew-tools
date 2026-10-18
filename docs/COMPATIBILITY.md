# Compatibility and interpretation

## Research baseline

The imported diagnostic implementations were used on a PS5 Pro running firmware
13.60. This records the historical observation, not a claim that new builds
match historical binaries or support other consoles and firmware versions.

| Component | Boundary |
| --- | --- |
| reader3 | A resident implementing `KEKCALL_SHARED_AREA_SNAPSHOT` with this exact snapshot layout |
| procwatch / shellshot | Firmware-specific raw `kinfo_proc` offsets, including PID 72, name 447, and thread count 596 |
| thread-probe-v1 | Raw selector probing; unsupported selectors can return ENOENT |
| thread-probe-v2 | Explicitly requires firmware `(fw & 0xffff0000) == 0x13600000` and SoC `0x840fd0`; bounded kernel reads and a live self-check of list links, thread owner, and TID |
| thread summarizer | A completed three-pass v2 capture with 1,096-byte process records and 0x480-byte thread records |
| minimal payload | New SDK starter; compiled locally, not console-tested |

## Reading the output

- The sender's exit status reports host-side transport, not the payload's return
  value. A connection can close normally after a payload printed an error.
- V2 can finish its sysctl capture with `kernel_layout_validated=0`; kernel
  thread reads are skipped and the v2 summarizer rejects that capture.
- Procwatch polls every 50 ms. A process can start and exit between polls, so
  absence from its log does not prove no execution occurred. It matches entries
  by PID; very rapid PID reuse is another limitation.
- The app-info layout used in these collectors differs from observed firmware
  behavior. Treat reported title fields as candidates. The v2 summarizer labels
  reconstructed titles accordingly.
- The v2 collector caps each process at 256 threads. Historical ShellCore
  captures reached that cap. Some kernel fields remain candidates despite the
  owner/TID/list checks.
- Kernel snapshots do not stop other threads. A record is an observation, not
  a stable crash dump or proof of the instruction blocking a thread.
- Reader3 prints each snapshot's available ring window. Repeated words across
  snapshots do not establish repeated events. A 16-word ring can overwrite
  earlier context, and a missing event needs a check that its logging path was
  armed.
- Zero counters for disabled instrumentation do not establish that the
  corresponding operation never happened.

## Sending into a research session

The sender makes no empty loader probes and performs no automatic retries.
Connection loss or an idle timeout can leave execution state unknown. Preserve
the capture and establish session state before deciding on another send.

Resident experiments change the session's kernel state. The historical workflow
used a fresh exploit/loader session for each resident and did not resend or
replace kstuff inside that live session. Reader and sysctl diagnostic payloads
are separate from resident installation.
