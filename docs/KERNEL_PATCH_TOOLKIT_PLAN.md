# Kernel patch toolkit proposal

Recorded 2026-10-20. This is the staged design and implementation tracker, not
a deployment runbook. It grants no new live-target authorization. The first
implementation is documented in the [toolkit guide](KERNEL_PATCH_TOOLKIT.md).

## Implementation status — 2026-10-20

| Stage | Current evidence | Still required |
| --- | --- | --- |
| 1: offline manifest and simulation | Implemented in `host/kernel_patch.py`, the portable `residents/patch/patch.h` core, host simulator and native/CLI tests; includes exact-policy generation, apply/exercise/revert, readback, restoration, journal failure and replay handling | Preserve this boundary when adding a live backend |
| 2: resident interface and read-only integration | [Implemented pinned source overlay and authenticated bridge](KERNEL_PATCH_STAGE2.md) for kstuff-lite `47da23b`; shared inspection state, bootstrap readbacks, SDK client and saved-log validator; bridge/actual dispatch/bootstrap SDK-compiled and host-tested; inspection readiness ABI unchanged | SDK installer startup integration/link, real syscall/page-lifetime/coexistence validation and a fresh identified console session for live stage 2 and stage 3 validation (stage 3 source work has since proceeded; the session remains a prerequisite for it) |
| 3: owned test data | [Owned-cell resident adapter, journal, authenticated exercise/recovery clients and saved evidence](KERNEL_PATCH_STAGE3.md) implemented; host-tested and SDK compile-checked | SDK installer startup integration/link, stage 2 hardware checks, exact live build/session and console write/readback/restore evidence |
| 4: selected kernel data | Core accepts independently registered exact data policies; host tests cover the capability path | Individually reviewed real fields and their lifetime/locking/mutation semantics, then live validation |
| 5: kernel code and execution | Existing execution coordinator remains separate; patch core explicitly refuses code mutation | Hardware rendezvous/transport, instruction and incoming-flow review, architecture synchronization, restoration and live validation |

Complete resident image linking and actual installer source compilation are now
implemented through the [private build runbook](KERNEL_PATCH_BUILD.md). The
[research design](KERNEL_PATCH_RESEARCH.md) separates tooling controls from the
unproven Chain Test hypothesis. The SDK installer entry/bootstrap integration
and final installer link remain unfinished.

The full plan remains unfinished. Host tests and SDK compilation do not prove
any live kernel modification capability.

## Goal

Build tools for small, reviewable and reversible kernel modifications, with
explicit image/session identity, expected-byte checks, bounded operations and
preserved evidence. Separate offline planning, kernel writes and execution
control so each can be tested independently.

The public [Payload SDK kernel interface](https://github.com/ps5-payload-dev/sdk/blob/master/include/ps5/kernel.h)
exposes `kernel_copyout` for kernel reads and `kernel_copyin` for kernel writes.
Those interfaces do not establish page writability, atomicity, safe code
replacement or restoration in the current firmware/resident session.

## Proposed components

| Component | Responsibility | Existing foundation / missing work |
| --- | --- | --- |
| Offline patch planner | Record firmware/model, matching dump hash, explicit address anchor, expected bytes, replacement bytes and undo bytes; reject overlaps and invalid ranges | [Toolkit planner](KERNEL_PATCH_TOOLKIT.md) now implements the manifest and generator; instruction-shape audits do not prove semantics |
| Live verifier | Pin resident build/session/generation, obtain current kernel bases, verify mappings and compare original bytes immediately before mutation | Reuse concepts from [kernel inspection](KERNEL_DEBUGGER.md) and [readiness](KERNEL_READINESS.md); the existing inspection capability grants no write permission |
| Bounded writer | Apply one planned change, verify readback, preserve the preimage and result, and attempt and verify restoration after failure | Portable transaction core and host simulation implemented; live backend still required |
| Cooperative resident adapter | Provide explicit ownership, synchronization, bounded transport and write capability for the selected operation | Stage 2 inspection and stage 3 owned-cell source adapters implemented; selected real-data and execution adapters still required |
| Trace and execution interface | Observe effects; eventually coordinate kernel stop, step, restoration and release | [Capture](KERNEL_CAPTURE_CORE.md) and [execution](KERNEL_EXECUTION.md) cores exist; live hardware adapters remain unfinished |

## Implementation sequence

1. **Offline manifest and simulated transaction engine.** Define a versioned
   manifest and saved result format. Exercise successful writes, original-byte
   mismatch, partial writes, readback mismatch, failed restoration and stale
   session identity with a simulated backend. A manifest is a plan, not proof
   that the live operation is supported.
2. **Resident interface and read-only integration.** Pin the exact resident
   build, establish fresh session identity and expose separately defined write
   capabilities. Keep the existing inspection readiness ABI unchanged; it
   accepts inspection capability only. Verify transport and live checks before
   enabling mutation.
3. **First live milestone: resident-owned test data.** Change one dedicated test
   variable, verify it, restore it and verify restoration. The adapter must own
   and synchronize that variable. Record exact payload/resident hashes, target
   identity, commands, before/after bytes and cleanup evidence.
4. **Selected kernel data changes.** Add only individually reviewed operations
   with known field lifetime, locking, alignment and mutation semantics. A
   generic memory copy does not supply those guarantees.
5. **Kernel code changes and execution control.** Require coordinated CPU
   quiescence, reviewed instruction boundaries and incoming control flow,
   architecture-correct instruction-stream synchronization, verified restoration
   and usable transport while CPUs are parked. Define refusal and failure
   handling before implementing the live operation.

## Constraints and validation boundary

- Prefer cooperation with a pinned kstuff resident in a dedicated fork. Preserve
  existing DR ownership. Do not revive the retired direct-PCB fallback, steal
  slots or alter IDT/TSS to work around missing capabilities.
- Resolve addresses from explicit anchors and current-session bases. Historical
  KASLR addresses and matching bytes at one site do not identify a whole running
  kernel. The process debugger remains usermode-only.
- Recheck expected bytes under the synchronization that protects the write;
  an earlier inspection cannot eliminate a concurrent-change race.
- Treat rollback as an operation that can fail. Preserve an explicit unknown
  or failed-restoration state and block further mutations; do not report
  transactional atomicity merely because write/readback checks exist.
- Preserve results before acknowledging completion where the transport permits.
  Do not blindly replay a timed-out mutation or automatically reboot, reconnect
  or resend a payload as recovery.
- Use the standard Payload SDK / LLVM 18 build and host checks. Build success,
  simulation and transfer success are distinct from validation of an exact ELF
  on a console. Establish current readiness and permitted mutations before any
  live test; follow the [recovery constraints](DEBUGGER_RECOVERY.md).

The offline transaction toolkit, stage 2 inspection integration and stage 3
owned-cell adapter are implemented and build-checked. Stage 3 source development
has proceeded locally; enabling its live milestone still requires a linked SDK installer,
stage 2 read-only hardware validation and a fresh console session.
Selected real-data and code adapters remain unfinished; no console-validated
modification path is supplied yet.
