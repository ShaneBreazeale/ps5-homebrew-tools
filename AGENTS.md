# Agent instructions for PS5 Homebrew Tools

## Read first

For debugger work read, in order:

1. `docs/DEBUGGER_RECOVERY.md` — dated operator session facts and the kernel/user distinction.
2. `docs/DEBUGGER_VALIDATION.md` — historical evidence, failures, exact tested hashes.
3. `docs/DEBUGGER.md` — build, CLI workflow, cleanup, troubleshooting.
4. `docs/DEBUGGER_AGENTS.md` — automation contract, CLI and GDB/MI examples.
5. `docs/DEBUGGER_PROTOCOL.md` — actual packet subset and limits.
6. For kernel work, `docs/KERNEL_DEBUGGER.md` — explicit anchors, inspection phase and unfinished execution adapter.

Current source and current-session observations take precedence over stale indexed
snippets. Distinguish implemented behavior, host tests, historical console tests,
and validation of the exact current ELF. A compiled or uploaded ELF is not a
validated debugger. The full console validator has never passed.

## Scope and session state

- This payload attaches to ONE USERMODE PID. It cannot trap a kernel address or
  the kernel offset `0xcfc12`. Do not substitute a system-process attach for a
  missing kernel debugger. `PPSA90001` and `NPXS40087` are title identifiers,
  not PIDs; attachment to NPXS40087 is unvalidated.
- The operator reported 192.168.87.247 offline after run 007; the last observed
  Relapse GET was 12:08:11 on 2026-10-18. Treat these as dated observations, not
  a permanent host default or proof of readiness. Do not deploy until readiness
  is newly established in the authorized session.
- Do not deploy the retired kernel-dbregs fallback into a kstuff session.
  `PROCESS_DEBUGGER_KERNEL_DBREGS` is now rejected at compile time. Do not remove
  that guard, write thread PCBs, or alter IDT/TSS to work around watchpoint failure.
- Respect the user's existing authorization and target scope; do not ask again
  for actions already authorized. If a required target/session fact is missing,
  ask for that fact while continuing independent local work. Never turn this
  file into a routine approval requirement for reading, building, or host tests.

## CLI debugging

- Establish host, port, authorized numeric PID, process identity/lifetime,
  firmware/model, resident state, exact payload hash, target ELF/symbol identity,
  permitted mutations/resumes and stop conditions before using a live target.
- One RSP client at a time. Do not run the validator or a second probe beside GDB.
  Never probe the ELF loader with an empty connection or resend on idle timeout.
  Classify a black or frozen session with `host/session_health.py` (ICMP only)
  or the `session_health` sidecar from a failed send. Do not send another ELF
  into `elfldr_dead`, `kernel_unreachable`, or `loader_silent`.
- Start with the compatibility profile in `docs/debugger/compat.gdb`. It disables
  multi-action vCont and automatic reconnect. Current stock-GDB integration is
  not console-validated; use the protocol log to diagnose incompatibility.
- Prefer small GP-register/memory inspections and bounded instruction steps.
  `continue` resumes the process, not just a selected thread. `break` / `Z0`
  software breakpoints are implemented (`INT3`, no DR slots) and host-tested.
  They are not console-tested. `next`, `finish`, `run`, target function calls
  and signal-delivery resume remain unvalidated workflows.
- All four DR slots may belong to kstuff. Use `Z0` software breakpoints in that
  case. An ENOSPC result on `Z1` means stop and report unavailable hardware
  capacity. Never clear another owner's slots or use the disposable child's
  slot lease on a real application. Data watchpoints remain disabled on retail
  13.60; a readback match does not prove a watchpoint fires.
- Detach explicitly, record the reply, preserve logs and report any unknown
  cleanup state. Do not kill/reboot a target or server as an automatic recovery.
  Debugger disconnect can leave state uncertain; cleanup is not fully validated.

## Build and maintenance

Use the standard Payload SDK / LLVM 18 build. In this workspace, gpubox is the
usual build host; the staged SDK and LLVM 18.1.8 locations are recorded in the
validation guide. Do not bypass the LLVM gate with the Mac's LLVM 23 toolchain.
`make check` uses no SDK or console. Compile code changes through the ordinary
`make process-debugger` target. Kernel offset inspection uses
`make kernel-offset`; it does not install a trap or inherit process-debugger
validation. Documentation-only changes need link/command
checks, not console execution. Keep new runbooks linked from docs/README.md
and update context7.json rules when behavior or important constraints change.

Use Context7 for current external CLI/SDK documentation: resolve the library ID
first, then query the selected ID with the actual question. Never invent this
repository's Context7 ID or claim an indexing refresh occurred just because a
configuration file changed. Do not submit private captures, credentials or
session transcripts to Context7. Keep raw captures, binaries and SDKs out of Git.
