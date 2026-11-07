# Cooperative kernel event capture core

[capture.h](../residents/capture/capture.h) extends the kernel work with a
portable event-capture core for a future cooperative resident adapter. It is
host-tested integration code, separate from the kernel-text dump collector and
the kernel-offset byte inspector. It is not linked into an installed resident,
and no payload command currently arms a kernel trap.

## Four-slot bound and ownership

The core accepts at most four capture sites, using the existing execution-trap
slots DR0–DR3. This is an upper bound on shared hardware capacity, not four
additional slots. Capturing all GP registers at one site consumes one site;
the four-slot constraint does not limit how many GP register values an event
can contain. No time multiplexing, slot eviction or software breakpoint fallback
is provided.

The adapter supplies a synchronized `kc_snapshot` with its pinned resident build
ID, live session ID, generation, actual CPU scope, and each CPU's DR0–DR3/DR7
state. `granted_mask` explicitly permits observation of an **already resident-owned
execution trap**. It must come from that resident's registration/ownership
mechanism. An occupied or disabled register is not a grant, and the inspection
readiness ABI does not provide these permissions.
The adapter must independently validate the build against its pinned
configuration before `kc_begin`; the core cannot authenticate supplied snapshots.

`kc_bind` requires the same granted slot and kernel address on every CPU in the
scope. Missing grants or differing assignments return `ENOSPC`; a repeat binding
is idempotent. With all four slots occupied and none granted, zero capture sites
are available. With the resident's explicit cooperation, an existing trap can
be observed without consuming another hardware slot. This core never programs
DRs or clears another owner's state. Data watchpoints remain outside its scope.

## Adapter lifecycle

1. Allocate and zero-initialize a `kc_capture` outside exception context. Its
   fixed per-CPU storage is too large for a kernel trap stack. Call `kc_begin`
   with the verified snapshot and a hit budget of 1–4096 **per CPU**.
2. Bind the approved sites with `kc_bind`. Call `kc_arm` with a new synchronized
   snapshot after the adapter has established the actual trap/ownership state.
   Arming enables this core's logging only.
3. At an execution event already proven by the resident, pass the slot, CPU,
   current snapshot and complete `kc_registers` to `kc_record`. Matching RIP is
   required; DR6 alone cannot establish provenance. A snapshot is trusted adapter
   input, not a query made by the core. The resident still owns exception chaining,
   instruction emulation and resume, including when logging refuses an event.
4. Call `kc_disarm`, then have the adapter quiesce all in-flight callbacks before
   draining, inspecting counters or changing configuration. Drain each CPU with
   `kc_drain`, preserving the owner snapshot alongside the events. Disarming
   logging does not remove a hardware breakpoint or prove resident cleanup.
5. Begin another capture only after draining all buffered events. A revoked
   capture additionally requires a new session or a newer generation. The
   adapter must establish the new identity; changing a number to bypass refusal
   is not valid ownership evidence.

Every operation requires caller serialization and stable snapshot/register
storage. This core supplies no locking, CPU rendezvous or reentrancy handling.
An integrating resident must exclude concurrent/nested access without waiting
inside a trap; rejected events at that boundary need separate adapter counters.
Do not wire these functions into an SMP exception path until that contract is
implemented and reviewed. Capture configuration and draining belong outside
exception context. No allocation, formatting or network operation occurs in
`kc_record`.

The separate [SMP execution coordinator](KERNEL_EXECUTION.md) now supplies
nonblocking stop/step/restore coordination and a mailbox for adapter integration.
It does not automatically serialize this capture core or supply live trap entry.

## Events, bounds and refusal

Schema-1 events retain CPU, slot, generation, per-CPU sequence, all 16 GP
registers, RIP and RFLAGS. Full-width R15 and RAX are preserved. An optional
adapter-supplied, bounded, fault-contained read samples eight bytes at
`[rbp-0x68]` only when the complete range is a canonical kernel address. Failure
or an absent reader leaves `frame_value_valid=0` and the value zero; it does not
erase the register event. A plain unsafe kernel dereference is not a suitable
reader.

Each CPU has 16 buffered events. A full ring preserves existing events, counts
the dropped hit and returns `ENOBUFS` without reading frame memory. Every valid
in-scope hit, including overflow, spends the per-CPU budget. Once exhausted,
further hits return `EAGAIN` without recording or reading memory. Draining and
rearming do not renew that budget. There is no cross-CPU time ordering, coherent
snapshot, or target stop implied by an event.

Changes to build/session/generation, CPU scope, or a bound slot's address,
grant or DR7 fields revoke logging with `ESTALE`. Returning the old snapshot
cannot rearm that capture. Already buffered evidence remains drainable. Unbound
slots are preserved and never restored from an old snapshot. Invalid indices,
nonkernel sites and unsupported watchpoint grants are rejected. The core
neither converts errors into trap success nor attempts invasive recovery.

## Verification boundary

Run from the repository root without an SDK or console:

```sh
python3 -m unittest discover -s tests -p test_kernel_capture.py -v
make check
```

The native test executes the actual C core, covering four-site registration,
all-slots-owned refusal, partial/differing CPU grants, full-width register
events, failed frame reads, bounded rings/budgets, and sticky revocation. These
checks do not validate a resident registration API, real trap frames, safe
kernel reads, concurrency, instruction emulation, transport or cleanup.

No live adapter, new resident build, console deployment or live capture
validation is supplied by this change. The existing
[kernel execution-adapter requirements](KERNEL_DEBUGGER.md#execution-control-adapter-still-required)
and [recovery constraints](DEBUGGER_RECOVERY.md) still apply. The retired PCB
writer, IDT/TSS modifications and slot stealing remain prohibited.

Host-verified on 2026-10-19, with no console contact: all 74 Python host tests and the C paging checks passed
locally and on gpubox; the capture test also passed AddressSanitizer and
UndefinedBehaviorSanitizer locally. The standard `make kernel-offset
process-debugger check` build passed on gpubox with the staged SDK and LLVM
18.1.8 in `/tmp/ps5-kernel-capture-core-1zwmil`. Those SDK payloads do not link
this resident component; the new core's execution evidence is the native host
test. Neither payload was deployed.
