# Kernel patch stage 2 client

Build with `make kernel-patch-stage2` using the standard Payload SDK / LLVM 18.
The default emits an explicit provider-unavailable result and issues no resident
query. A matching private prepared overlay enables the authenticated read-only
provider; configured ELFs contain its credential and are excluded from `all` and
`bundle`.

See the [stage 2 integration guide](../../docs/KERNEL_PATCH_STAGE2.md) for source
pins, private configuration, build checks, JSON evidence and the live validation
boundary. No build target installs a resident or sends a payload.
