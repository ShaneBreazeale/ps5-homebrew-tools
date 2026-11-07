# Compatibility and interpretation

## Research baseline

The imported diagnostic implementations were used on a PS5 Pro running firmware
13.60. This records the historical observation, not a claim that new builds
match historical binaries or support other consoles and firmware versions.

| Component | Boundary |
| --- | --- |
| Kernel offset backend | PS5 Pro 13.60; versioned readiness provider or explicitly enabled historical cookie/profile fallback, plus readable audited page; seven-byte exec-join inspection only, no traps or console validation. See [kernel backend](KERNEL_DEBUGGER.md). |
| Process debugger | Usermode PID attach; child-only partial console evidence on Pro 13.60; free DR slots required; Z2/Z4 disabled on retail 13.60; no kernel breakpoints or direct PCB fallback. See [the debugger guide](DEBUGGER.md). |
| Resident snapshot | A resident implementing `KEKCALL_SHARED_AREA_SNAPSHOT` with this exact snapshot layout |
| Process watch / process snapshot | Firmware-specific raw `kinfo_proc` offsets, including PID 72, name 447, and thread count 596 |
| thread-probe-v1 | Raw selector probing; unsupported selectors can return ENOENT |
| thread-probe-v2 | Explicitly requires firmware `(fw & 0xffff0000) == 0x13600000` and SoC `0x840fd0`; bounded kernel reads and a live self-check of list links, thread owner, and TID |
| thread-probe-v3 | Same firmware and SoC gate as v2. Read-only walk of one title, repeated until the process is absent. Pair with `host/stream_logger.py`. Defaults are `PPSA90001`, 2000 ms, 300 passes |
| follower-live | Requires a resident that implements this snapshot ABI (`KSTUFF_OBS=1`). Prints new ring words and the first sight of each tracked ioctl command. It does not install kstuff. A quiet `nmount` counter on 13.60 is expected; group `0x32` is the pfs mount transport when the resident records it |
| thread summarizer | A completed three-pass v2 capture with 1,096-byte process records and 0x480-byte thread records |
| kernel capture | PS5 Pro 13.60 with the exact resume instrumentation and validated page map in its named profile |
| capture exporter/receiver | Matching FPK1-END1 tools and a completed collector manifest; no console runtime test yet |
| native app starter | Builds with the locally installed Payload SDK; console installation and runtime behavior remain untested |
| minimal payload | New SDK starter; compiled locally, not console-tested |

## Reading the output

- The sender's exit status reports host-side transport, not the payload's return
  value. A connection can close normally after a payload printed an error.
- V2 can finish its sysctl capture with `kernel_layout_validated=0`; kernel
  thread reads are skipped and the v2 summarizer rejects that capture.
- Process watch polls every 50 ms. A process can start and exit between polls, so
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
- Resident snapshot prints each snapshot's available ring window. Repeated words across
  snapshots do not establish repeated events. A 16-word ring can overwrite
  earlier context, and a missing event needs a check that its logging path was
  armed.
- Zero counters for disabled instrumentation do not establish that the
  corresponding operation never happened.
- On firmware 13.60 a PPR package mount is a pfs SM ioctl (group `0x32`),
  not `nmount`. A zero `nmount` counter during a title launch is the
  expected reading. The ioctl-com table lists only commands the resident
  recorded.

## Sending into a research session

The sender makes no empty loader probes and performs no automatic retries.
`session_health.py` pings only; it never connects to the loader port. Loader
refused or open state comes from a send that already ran, or from an operator
`--loader-result`. Connection loss or an idle timeout can leave execution state
unknown. Preserve the capture and classify ping vs loader before deciding on
another send. See [black-session classes](TROUBLESHOOTING.md#black-session-classes).

Resident experiments change the session's kernel state. The historical workflow
used a fresh exploit/loader session for each resident and did not resend or
replace kstuff inside that live session. Reader and sysctl diagnostic payloads
are separate from resident installation.
