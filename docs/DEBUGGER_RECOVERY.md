# Debugger recovery and kernel scope

This is a dated investigation note and a guide to the next decision, not a
claim of current console readiness. Read it with [validation evidence](DEBUGGER_VALIDATION.md).
A successful new build does not change the last observed runtime state.

## Operator report — 2026-10-18

The operator reports that `192.168.87.247` no longer answers ping, and that the
last Relapse GET remains at **12:08:11**. These match the recorded post-run-007
state. No new console deployment is authorized merely by a documentation or
host-build task. Establish the actual console state with the operator before
another live session; do not reboot, rerun the exploit, replace kstuff, or send
another debugger as an automatic recovery action.

The prior Chain Test black-screen observation has these constraints:

- `PPSA90001` was already gone; attaching its historical PID cannot capture the
  event that already terminated it.
- `NPXS40087` attachment is unvalidated and is not a substitute for kernel tracing.
- The existing debugger targets a usermode process and cannot trap kernel offset
  `0xcfc12`.
- In run 003, all four hardware DR slots were already occupied by kstuff-related
  state. More GDB breakpoints cannot create additional hardware capacity.

These are session-specific facts, not permanent properties of every console,
firmware, process or future run. A new session needs new identity and timing
observations.

## What failed, and what is still unknown

Earlier Z2/Z4 insertions returned success but did not produce data-watchpoint
stops. They remain disabled in the retail 13.60 production path. A host test of
DR7 encoding or a matching register readback cannot close that runtime gap.

Run 007 compiled `PROCESS_DEBUGGER_KERNEL_DBREGS`, containing a direct PCB
save-area writer. The ELF was sent, no startup marker was received, and the
console later stopped answering. The available evidence does not establish
whether that writer executed or what caused the loss of connectivity. **Do not
send that historical fallback into a kstuff session.**

The subsequent final ELF with SHA-256
`d80da62f7ddc90cf89651ca8651043384617563175d02fedb8ac8c35c149fb05`
was built with LLVM 18.1.8 and was not deployed after the loss of connectivity.
The operator identifies it as 209,304 bytes. Treat the hash and size as historical
artifact identity, not a guarantee for a newly rebuilt source tree.

## Current source changes after the failed runs

- Direct PCB debug-register writing and the save-area scanner have been removed
  from the process payload. Defining the retired macro is a compile error.
- Ptrace debug-register setters are followed by address/DR7 slot-field readback.
  A mismatch causes EIO and rollback; unsuccessful rollback poisons further
  resume/breakpoint operations.
- Host regression checks cover a setter that reports success but drops access/
  length bits, transaction rollback, and an all-four-slots-owned ENOSPC case.
- Occupied hardware slots are preserved. The disposable child's explicit lease
  remains confined to that owned child; it cannot clear a real app's kstuff state.
- Data traps are still **not fixed or console-validated**. The root cause remains
  open. These changes close false-success and unsafe-fallback paths, not the
  missing hardware capability.

These source changes have no implied live result. Record a new compiler build,
ELF hash and a separately authorized console test before drawing new conclusions.

## Kernel offset 0xcfc12

A usermode GDB attach is the wrong execution scope. Even if the offset is
converted to a runtime kernel VA, this process server rejects kernel breakpoint
addresses. Sending `hbreak *0xcfc12` would refer to a low user virtual address,
not to the intended kernel instruction.

Kernel offset inspection is now implemented separately; see the
[kernel backend guide](KERNEL_DEBUGGER.md). The matching saved dump confirms
`exec+0xcfc12 = text+0x38fc12 = data-0x9303ee`. No kernel execution-control
adapter has been implemented or deployed. Before designing a trap:

1. Establish whether `0xcfc12` is an image-relative VA, a file offset, or relative
   to some other anchor. Verify the source image/hash and the runtime kernel base
   for the same firmware/session. Do not reuse an old KASLR base.
2. Identify the actual instruction and relevant code path from the matching dump
   and disassembly. The plain offset is not proof of a breakpoint boundary.
3. Establish trap/debug-register ownership and the interaction with resident
   kstuff. Do not repurpose occupied slots or change IDT/TSS inside that session.
4. Define the smallest observation, trigger window and failure/cleanup procedure.
   Kernel/SMP stop, trap-frame handling, transport while stopped and restoration
   need their own validation; none comes from this process stub.
5. Validate the backend in a separately established, appropriate research session
   with known firmware/model and reversible state handling before pursuing the
   Chain Test event. Do not send a guessed kernel trap to the offline console.

This repository currently offers neither a verified kernel trap command nor an
automated kernel tracer for that offset. The research prosper0gdb code is not a
drop-in kernel mode for `process-debugger.elf` and must not be invoked alongside
kstuff based on a CLI example alone.

## Next useful work while the console is offline

Continue host tests, standard gpubox SDK builds, packet/client compatibility
review, analysis of matching saved dumps, and evidence/documentation repair.
For the watchpoint bug, prepare a future disposable-target test that records:

- target/tracer identity, firmware/resident profile, exact ELF and clean session;
- DR ownership before allocation; actual readback after insertion and before
  resume; signal/trap metadata and verified instruction/memory activity;
- whether a single write/access watchpoint fires, plus detach/restoration evidence;
- a bounded stop condition and no automatic fallback to kernel writes.

Do not claim the live data-watchpoint or kernel-trap problem is solved until
that evidence exists. The [agent handoff template](DEBUGGER_AGENTS.md#evidence-and-handoff-format)
keeps future LLMs from repeating the failed path.
