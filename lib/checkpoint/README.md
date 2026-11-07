# Durable checkpoint library

Link `checkpoint.c` into a usermode app or payload and include `checkpoint.h`.
It sends before/after observations and waits for host persistence before each
enabled call succeeds. Read the [runbook](../../docs/DURABLE_CHECKPOINTS.md)
for initialization, identities, runtime groups, error handling and limits.

[The benign example](../../examples/checkpoint-demo/main.c) is host-tested and
SDK-compiled. It is not a kernel tracer. Never call the blocking checkpoint
library from a resident trap or panic handler; use the separate preallocated
[resident evidence core](../../residents/evidence/evidence.h).
