# Kernel offset inspection backend

Build: `make kernel-offset` → `out/kernel-offset.elf`, using the standard Payload
SDK / LLVM 18 runtime. This one-shot payload implements the inspection phase of
a separate kernel backend. It does not attach to a process, install a trap,
consume DR slots, step, resume, or write kernel state.

Read the [kernel backend guide](../../docs/KERNEL_DEBUGGER.md) for the exact
anchor mapping, offline planner, readiness requirements, output and limits.
The [recovery note](../../docs/DEBUGGER_RECOVERY.md) still applies: no deployment
has occurred after the recorded console outage.

The default profile supports only PS5 Pro retail 13.60 and the seven-byte exec
join instruction at `text+0x38fc12` (`data-0x9303ee`). The normal build requires
a linked versioned readiness provider. An explicit
legacy build can instead check the matching resume cookie and hook state zero.
Both require a valid pmap, readable audited page and consistent post-read state.
See [readiness modes](../../docs/KERNEL_READINESS.md) for exact build flags and
provider/producer integration. Other states produce an explicit refusal record; protected pages are not read or bypassed.
A matching instruction is a point-in-time byte observation, not a trap hit.

Output is one `KOFFSET_JSON={...}` line. Return 0 means the seven bytes matched;
return 1 means unsupported/unverified/error/mismatch. The sender's return code
is separate. Keep its complete raw log and sidecar. No files or listener are
created on the console. Metadata and at most seven target instruction bytes are
read. This payload has not been console-tested.
