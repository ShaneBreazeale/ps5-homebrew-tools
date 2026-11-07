# Reusing capture windows without rebooting

This proposal follows the operator's interrupt/dump/reboot workflow. Review of
the workspace operator records on 2026-10-20 identifies the historical workflow
below. Those records do not establish current console readiness or show that
ring fullness causes the reboot requirement.

## What the operator records establish

Workspace-only sources outside this repository are `../OPERATING.txt` and
`../research/fpkg-capture/2026-10-17-STAGE2-LAUNCH.md`, supplemented by
`../research/fpkg-capture/2026-10-19-PROGRESS.md`. Paths here are relative to the
repository root. The October 19 progress note is later than OPERATING.txt's
October 18 observations; its pickup instructions are historical, not a current
deployment authorization.

Interpret the older causal wording with the
[Chain Test validity correction](KERNEL_PATCH_EXPERIMENTS.md#chain-test-validity--2026-10-21-correction).
No successful launch of the exact repackaged specimen was found on any firmware.
The recorded failures do not isolate package validity from firmware compatibility
or establish a plaintext-wide cause.

The recorded cycle installs one instrumented kstuff ELF after a fresh Relapse,
launches Chain Test once, then uses reader3 to export resident logs when the
loader survives. The observer logs and resumes through emulation or selected
call skips. This is not evidence of an interactive all-CPU stop waiting for a
resume command.

- The October 18 xr15 observation records full `r15=0`, `rax=0` and a frame-slot
  pointer at `exec+0xcfc12`. A later process snapshot records no lasting
  PPSA90001, SceShellUI in `SSTOP`, and the resident and loader still alive.
- October 19 xff0 records an observer hit and a successful reader3 export while
  the title remains black. Its ELF SHA-256 is
  `365078c1a1927fb4d798cd4a676aeee6f79966679975608906b4606f9d34d829`.
- The x88 trial instead lost loader service while ICMP still responded and no
  ring was obtained. This alone does not prove a kernel panic or isolate the
  copy operation as the root cause.

The records require a fresh session before replacing resident instrumentation.
Clearing logs cannot repair the title/ShellUI state, undo skipped operations or
make a second resident installation safe. Reboots serve as clean experiment
boundaries; no demonstrated buffer-reset remedy appears in these records.

The next design to evaluate is one pinned resident with bounded, separately
identified observation windows and reviewed resident-owned configuration.
First establish repeated read-only snapshots/bookmarks without changing traps
or launching the failed title again. Repeated app launches require independent
evidence that the previous title/ShellUI state recovered; loader survival is
insufficient. Runtime observer reconfiguration and application recovery remain
unimplemented and unvalidated.

## Separate capture storage from execution recovery

| Observed condition | Appropriate mechanism | What clearing a ring cannot establish |
| --- | --- | --- |
| Kernel progressing, old events remain visible | Start a new host-side capture window using sequence bookmarks | A new resident session or a repaired application |
| Bounded capture ring full | Disarm logging, quiesce callbacks, export and retire consumed records | CPU release or restored instrumentation |
| Recoverable deliberate kernel stop | Verified resident-owned restoration, all-CPU release and independent progress observation | Successful return from the exception handler |
| Missing CPU, failed restoration, unknown cleanup | Preserve evidence and resolve the recorded execution state | Permission to resume or reinitialize the controller |
| Confirmed panic/fatal path | Preserve panic evidence and investigate the cause | A usable pre-panic kernel state |

The checked kstuff-lite `47da23b70685651a475d20247a3c4f2cac433eb4`
`uelf/log.c` uses an overwriting word ring and a wrapping message ring. It does
not halt the kernel when these rings fill. The repository's separate
`residents/capture/capture.h` preserves a full ring, counts dropped hits and
returns `ENOBUFS`; the resident still owns emulation/chaining/resume when logging
refuses an event. Neither behavior is itself a crash-recovery mechanism.
The [Linux tracing ring design](https://docs.kernel.org/trace/ring-buffer-design.html)
is a reference for overwrite versus producer/consumer behavior, not a PS5 API
or runtime compatibility claim.

The reader in `payloads/resident-snapshot/main.c` currently starts local word and
message cursors at zero on each of its three passes. Repeated printed events can
therefore be the same available window, not a ring that needs kernel-side
clearing. Changing reader cursors changes the view; it need not change resident
memory. That reader's legacy snapshot ABI must match the actual producer.

## Proposed capture-window lifecycle

1. Give each trial a separate host capture-window ID and retain the pinned
   resident/session identity, trap ownership and current execution state.
2. Enable bounded observation through a resident-owned handler. A trace-only
   handler records and returns through the resident's established emulation and
   resume path. It must handle full/budget/busy logging results without getting
   stuck in the observer. This does not prevent an underlying fatal operation.
3. Stop accepting new capture events at the window boundary. Prove in-flight
   producers/exporters quiescent. Disabling a logging flag alone is insufficient.
4. Export events, counters and loss information, preserve them on the host, then
   acknowledge consumption. A live implementation needs staging or peek/ack so
   failed host persistence does not discard the only copy. Existing `kc_drain`
   removes one record immediately and supplies no durable host acknowledgment.
5. If execution was parked, restore only resident-owned instrumentation, verify
   all scoped CPUs and complete release. Independently observe return/progress
   and quiesce the adapter before retiring the stop. A coordinator's COMPLETE
   state records acknowledgments, not successful IRET or application progress.
6. Start a new bounded capture window using the same healthy resident. Keep a
   new window ID even when the owner generation is unchanged: fresh `kc_begin`
   resets per-CPU sequences and counters. Preserve prior counters before that
   call. Draining/rearming an existing capture does not replenish its hit budget.

This is a proposed adapter/host protocol. It installs no live reset, resume or
panic-recovery command. A stopped kernel also needs a transport that remains
usable while its CPUs are parked; a scheduled usermode TCP worker does not
supply that property. Those adapters remain unfinished in this repository.

A two-bank capture store could reduce pauses: quiesce and seal one bank, switch
to an available bank, export the sealed bank, then recycle it only after the
host acknowledgment. Bank state, capture-window identity, producer quiescence,
loss policy and backpressure must be explicit. That is buffer-lifetime
management; execution restoration remains a separate requirement.

## Inspect the dump path's own waits

The same pinned kstuff source contains waiting loops in message logging and
snapshot helpers. `snapshot_msg_log` waits while `write_lock` is set;
`snapshot_word_log_entry` retries until it observes a stable entry;
`snapshot_ioctl_com_table` acquires its table's spinlock. A paused writer or
lock owner may prevent a reader's progress. This is a candidate mechanism to
investigate, not a finding that these routines caused the operator's crash.

A future reviewed snapshot adapter should use bounded attempts and explicit
busy/incomplete results, preserve partial-evidence validity per section, and
avoid waiting for a parked producer. Never force-clear a lock, global sequence,
trap register or panic flag to make a read finish. Clearing those fields does
not establish that the owner stopped using them. Existing snapshot/producer
consistency must be reviewed together for the exact build.

For a future live implementation, match the actual reader3 and producing
resident ELF/source identities, review their snapshot ABI, and establish fresh
UI/ICMP/loader/target progress observations. Historical xff0 is an artifact
reference, not the identity of a currently running resident. This investigation
makes no new console connection.

## Host experiment and limits

The existing [execution test driver](../tests/test_kernel_execution.c) now joins
the actual capture and execution cores in three additional host scenarios:

- `reuse`: 100 consecutive windows with 16 simulated CPUs and 25,600 drained
  events. The coordinator is initialized once; capture windows use the public
  disarm/drain/begin APIs. All-CPU restoration precedes release, retirement
  precedes another stop, and the simulated ownership snapshot remains unchanged.
- `drain-failed-restore`: draining every event leaves a failed restoration held,
  with no release authorization and no controller retirement.
- `drain-missing-cpu`: draining every event cannot supply a missing CPU arrival;
  timeout remains failed with the missing-CPU mask preserved.

Run without an SDK or console:

```sh
python3 -m unittest discover -s tests -p test_kernel_execution.py -v
make check
```

The simulated adapter asserts quiescence and successful restoration/release.
It supplies no real CPU rendezvous, physical transport, durable host ACK or
hardware progress evidence. The tests demonstrate protocol reuse and the
separation of storage from execution state; they do not show that the current
console can resume or that clearing logs avoids a panic.

### Verification record

Local `make check` passed all **168** Python tests and C paging checks. The
11 execution tests passed locally and on gpubox (Linux x86-64, GCC 13.3.0).
All three new scenarios also passed AddressSanitizer/UndefinedBehaviorSanitizer
on both hosts. Gpubox used `/tmp/ps5-capture-reuse-fFSion`; source pins,
commands and logs are saved under `captures/kernel-capture-reuse-jiv49fmk/`.
The first isolated gpubox test bundle omitted `host/analysis_common.py` and
failed at import; that log is retained. Adding the existing helper completed
the bundle, and all tests then passed without a production-code change.
No payload or kernel adapter was changed, and no console was contacted.
