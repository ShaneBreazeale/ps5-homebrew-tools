# Debugger target operations

The process debugger separates inspection and execution from GDB RSP. The
[public target API](../payloads/process-debugger/target.h) has no socket, packet,
ptrace or GDB register-layout dependencies. This is an internal C interface,
not a stable binary ABI or a new network protocol.

| Component | Responsibility |
| --- | --- |
| [target.h](../payloads/process-debugger/target.h) | Numeric identity/scope, maps, threads, memory, named x86-64 core registers, stop events, breakpoints and execution operations |
| [ptrace_backend.c](../payloads/process-debugger/ptrace_backend.c) | Usermode ptrace implementation, credentials, ownership, breakpoint transactions, stop classification, stepping and restoration |
| [inspection.c](../payloads/process-debugger/inspection.c) | Read-only sysctl metadata/maps and SDK module address lookup |
| [rsp.c](../payloads/process-debugger/rsp.c) | RSP commands, framing, errors, thread/register encoding, signal-number translation and socket interrupt polling |
| [main.c](../payloads/process-debugger/main.c) | Listener, connection lifetime and disconnect/shutdown cleanup |

The listener obtains `process_debug_target()` and passes it to `rsp_serve()`.
The adapter calls only `target_ops`; it cannot inspect ptrace's private target
state. The provider returns named architecture values and native stop signals;
the adapter converts these to the existing GDB register file and stop replies.
Unavailable FP/vector registers still use the existing `x` encoding. Register
writes preserve native fields absent from the core-register snapshot.

## Contract and ownership

Calls are serialized by one controller. The ptrace factory supplies a singleton
for one attached usermode PID, not independent instances or concurrent clients.
Identity reports the numeric attached PID and usermode scope; PID zero means no
attachment. It does not establish executable identity, title ID or lifetime
beyond the existing attachment. The kernel scope enum reserves vocabulary for a
future provider and grants no kernel capabilities.

Every provider implements the operation table, returning negative native errno
on failure. Unsupported operations return `-ENOTSUP`; an unsupported breakpoint
kind returns `-ENOSYS`, which RSP maps to the existing empty reply. This keeps
unsupported read-only watchpoints distinct from known-disabled retail 13.60
data watchpoints (`-ENOTSUP`). Successful list results must fit the caller's
capacity; insufficient capacity returns `-ENOSPC`. Memory transfers remain
bounded to 1,024 bytes and the ptrace provider rejects kernel addresses.

The maps operation now queries KERN_PROC_VMMAP on the researched 13.60
firmware and validates SDK-format variable-length records, user ranges, ordering,
permissions and terminated names. It returns errors for absent selectors or
incompatible layouts without a kernel walker. Process metadata uses the existing
1,096-byte Sony process-record profile, with optional path/app fields identified
by flags. SDK dynlib helpers resolve an explicit module basename. These new
paths are host-tested and not console-validated. No automatic GDB memory-map
or library qXfer feature is advertised. The new methods remain independent of
[their custom packet encoding](DEBUGGER_PROTOCOL.md#read-only-discovery-packets).

Register and resume thread choices remain provider state. Selecting zero picks
the current stop thread for register operations or clears the preferred resume
thread. Resume takes an action, optional thread, native signal and controller
callback; zero thread uses the provider's existing preferred/selected context.
Continue still resumes the process, while step temporarily suspends other LWPs.
A successful resume returns zero at a stop or one on exit/termination. After any
error the controller must inspect identity and state: the target may have
resumed, stopped, exited or retained partial ownership.

During execution, the provider synchronously polls `target_wait` without knowing
the transport. The callback returns zero for no input, one to request interruption,
or negative errno for a controller failure; it must not reenter target operations.
RSP consumes raw Ctrl-C and detects disconnect in this callback. The provider
issues the stop request and classifies the resulting native event. Disconnect
can return while the target is running; listener cleanup still calls detach,
which stops and restores the target before releasing ownership.

Owned-child diagnostics remain backend operations with their existing guards.
An optional child setup hook closes controller resources after fork, so the
provider does not need frontend descriptor knowledge. Hardware slot leasing
remains exclusive to the provider's own disposable child. All four DR slots may
already belong to kstuff; ENOSPC never authorizes clearing them. Software
breakpoint shadows, rollback/poison handling, firmware watchpoint restrictions,
credential restoration and the retired PCB-writer compile guard remain in the
provider. A frontend cannot bypass these policies by choosing a different packet.

## Verification and limits

`make check` includes the existing ptrace fault/ownership regressions, direct
operation-table tests linked without RSP, and RSP tests linked against an
independent fake target without ptrace or PS5 ABI headers. Tests cover register
translation, memory, thread selection, breakpoint kinds, stepping, controller
interrupt/disconnect and bounded list encoding. `make process-debugger` compiles
the four production translation units through the standard SDK/LLVM 18 target.

These are host tests and build checks. The split adds no live kernel adapter,
multi-controller support or console validation. Runtime availability of discovery
and the read-only FS/GS/XSAVE register banks remains unvalidated. It does not fix
data watchpoints or establish SMP-safe kernel stop/step/restore. The separate
[SMP coordinator](KERNEL_EXECUTION.md) remains a simulated/compile-checked core
with no live resident execution adapter. See the [validation record](DEBUGGER_VALIDATION.md)
for historical console evidence and [protocol reference](DEBUGGER_PROTOCOL.md)
for the legacy GDB subset and new discovery extensions.

All process-memory mutation paths use the same preimage/write/readback/rollback
transaction. Planting commits the captured original byte only after verified
completion. Removal and detach clear ownership entries only after verified
restoration. Unverifiable rollback poisons execution and blocks detach; a failed
but verified rollback can be retried while retaining ownership. These checks do
not make shared mappings atomic against writers outside the stopped process.

`read_memory_ranges` validates up to 16 slices and 1,024 total bytes before
reading, retaining native per-range errors and clearing failed output slices.
The provider publishes a nonzero stop serial that increments at each native
stop. [Stop reports and analysis](DEBUGGER_REPORTS.md) use these methods through
RSP without mixing packet logic into the provider.
