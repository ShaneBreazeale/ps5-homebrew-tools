# Owned-cell exercise and recovery clients

Optional standard SDK clients for the [stage 3 resident integration](../../docs/KERNEL_PATCH_STAGE3.md).
`make kernel-patch-stage3` builds the single fixed write/readback/restore exercise;
`make kernel-patch-stage3-query` builds the separate read-only recovery client.
Both are provider-free by default. Configure explicitly using a newly prepared
stage 3 overlay's `KERNEL_PATCH_STAGE3_CONFIG` directory. Configured ELFs contain
a bearer credential and must remain private; neither is included in public bundles.

The console milestone is unvalidated. Build and host-test evidence is documented
separately from deployment, hardware transport and actual restoration evidence.
