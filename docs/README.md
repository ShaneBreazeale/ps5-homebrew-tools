# Documentation

Use [Getting started](GETTING_STARTED.md) for the first build and capture.
Commands in the guides run from the repository root unless stated otherwise.

## Run the tools

| Guide | Use it to |
| --- | --- |
| [Build reference](BUILDING.md) | Configure the SDK and select Make targets |
| [Kernel readiness and fallback](KERNEL_READINESS.md) | Integrate versioned readiness with a restricted legacy-cookie fallback |
| [Kernel offset backend](KERNEL_DEBUGGER.md) | Resolve explicit anchors and inspect a gated kernel instruction; no traps yet |
| [Kernel patch toolkit](KERNEL_PATCH_TOOLKIT.md) | Plan patches, generate policies and simulate verified transactions; console validation pending |
| [Kernel patch experiments](KERNEL_PATCH_EXPERIMENTS.md) | Run the transfer-fault campaign and define baseline/treatment hypotheses |
| [Kernel patch research](KERNEL_PATCH_RESEARCH.md) | Review the homebrew stability study, control experiments and evidence limits |
| [Private resident builds](KERNEL_PATCH_BUILD.md) | Pin complete dependencies, link resident images and compile the actual installer source |
| [Kernel patch stage 2](KERNEL_PATCH_STAGE2.md) | Prepare the pinned private resident overlay, build the authenticated read-only client and verify saved observations |
| [Kernel patch stage 3](KERNEL_PATCH_STAGE3.md) | Run the authenticated owned-cell write/readback/restore exercise, resident journal and read-only recovery; live validation pending |
| [Process debugger CLI](DEBUGGER.md) | Build, log, attach by PID, inspect, step and detach |
| [Host utilities](../host/README.md) | Send once, stream until the connection dies, classify a failed session, and summarize v2 captures |
| [Process snapshot](../payloads/process-snapshot/README.md) | Take one filtered process snapshot |
| [Process watch](../payloads/process-watch/README.md) | Watch process changes during an app launch |
| [Resident snapshot](../payloads/resident-snapshot/README.md) | Read matching resident counters and event rings |
| [Thread probe v1](../payloads/thread-probe-v1/README.md) | Inspect raw sysctl records and selector availability |
| [Thread probe v2](../payloads/thread-probe-v2/README.md) | Capture selected processes' kernel thread records |
| [Thread probe v3](../payloads/thread-probe-v3/README.md) | Walk one title's kernel threads until the process leaves |
| [Follower-live](../payloads/follower-live/README.md) | Stream new resident ring words and first-seen ioctl commands |
| [Kernel capture and export](CAPTURE_TOOLS.md) | Collect and transfer a matching kernel-text capture |
| [Log tools](LOG_TOOLS.md) | Decode and compare resident captures |
| [Analysis tools](ANALYSIS_TOOLS.md) | Validate offsets and audit patches offline |
| [Native app](NATIVE_APP.md) | Build the controller/logging starter app |
| [Troubleshooting](TROUBLESHOOTING.md) | Interpret setup failures and incomplete output |

## Understand and extend the repository

- [Architecture](ARCHITECTURE.md): component boundaries and capture flow.
- [Kernel patch toolkit proposal](KERNEL_PATCH_TOOLKIT_PLAN.md): implementation tracker for offline manifests, verified writes and unfinished live resident integration.
- [Context7 guide](CONTEXT7.md): index and use the maintained tool docs.
- [Compatibility](COMPATIBILITY.md): supported baseline and interpretation limits.
- [Minimal native app](../templates/minimal-app/README.md): start a controller-based app.
- [Minimal payload](../templates/minimal-payload/README.md): start a new ELF tool.
- [Resident experiments](../residents/README.md): historical profiles and event fields.
- [Contributing](../CONTRIBUTING.md): add tools and record verification.
- [Provenance](PROVENANCE.md) and [import manifest](imports.json): source identities.
- [Initial validation](VALIDATION.md): what was actually built and tested.
- [Third-party notices](../THIRD_PARTY_NOTICES.md): imported code and license notices.

## Debugger and LLM references

- [Payload entry point](../payloads/process-debugger/README.md): current capability summary.
- [CLI runbook](DEBUGGER.md): operational workflow and troubleshooting.
- [Agent / GDB-MI guide](DEBUGGER_AGENTS.md): automation, evidence and cleanup state.
- [Protocol reference](DEBUGGER_PROTOCOL.md): exact implemented packet subset.
- [Recovery / kernel scope](DEBUGGER_RECOVERY.md): dated session facts and failed paths.
- [Validation](DEBUGGER_VALIDATION.md): gpubox builds and partial console evidence.
- [Root agent instructions](../AGENTS.md): repository-specific rules for coding agents.
- [GDB compatibility profile](debugger/compat.gdb): local settings; makes no connection.
