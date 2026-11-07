# Kernel patch toolkit

The toolkit implements an offline manifest planner, policy generator, request
codec, host simulator and portable resident transaction core. These are the
first implementation steps of the [toolkit plan](KERNEL_PATCH_TOOLKIT_PLAN.md).
The stage 3 source adapter supplies a bounded owned-cell write transport; SDK installer
integration/link, installation and console validation remain pending. Complete
resident linking and actual installer source compilation are covered by the
[private build runbook](KERNEL_PATCH_BUILD.md). Kernel code
mutation is explicitly refused by the core.

The [stage 2 guide](KERNEL_PATCH_STAGE2.md) documents the implemented private
resident source overlay, authenticated read-only SDK client and saved-log
validator. SDK installer integration/link and live console verification remain
outstanding; the generic interfaces below do not install an adapter automatically.

## Offline workflow

Build the simulator without an SDK or console:

```sh
make kernel-patch-host
```

The example uses synthetic bytes and illustrative identity values. It is not a
console profile. Create a fresh evidence directory and generate the synthetic
image locally; no raw kernel image is checked into Git:

```sh
PATCH_SESSION="$(mktemp -d /tmp/kernel-patch-demo-XXXXXX)"
export PATCH_SESSION
python3 - <<'PY'
import os
from pathlib import Path
(Path(os.environ['PATCH_SESSION']) / 'synthetic.bin').write_bytes(b'original' + bytes(24))
PY
python3 host/kernel_patch.py plan \
  --manifest examples/kernel-patch/manifest.json \
  --dump "$PATCH_SESSION/synthetic.bin" --output "$PATCH_SESSION/plan.json"
python3 host/kernel_patch.py simulate \
  --manifest examples/kernel-patch/manifest.json \
  --dump "$PATCH_SESSION/synthetic.bin" \
  --identity examples/kernel-patch/identity.json --patch test-variable \
  --operation exercise --output "$PATCH_SESSION/exercise.json"
```

`exercise` verifies the original bytes, writes the replacement, verifies it,
restores the actual preimage and verifies restoration, under one adapter lease.
Its successful result has `status: ok` and `state: restored`. In this example
all reads and writes access only a private host byte array. The simulated
journal is in memory; it does not prove durable evidence storage on a console.

Inject a failed restoration and preserve its result:

```sh
python3 host/kernel_patch.py simulate \
  --manifest examples/kernel-patch/manifest.json \
  --dump "$PATCH_SESSION/synthetic.bin" \
  --identity examples/kernel-patch/identity.json --patch test-variable \
  --operation apply --fault restore-failure \
  --output "$PATCH_SESSION/failed-restoration.json"
```

This command returns 1 with a saved `restore` / `unknown` result. Other faults
cover partial writes, an error after all bytes were written, readback mismatch,
short/failed reads, changed resident identity, permission refusal, acquisition,
release and journal failures. Use `simulate --help` for the choices. A simulated
fault does not reproduce a firmware failure or validate hardware behavior.

Generate reviewed build input and a separate offline request:

```sh
python3 host/kernel_patch.py policy \
  --manifest examples/kernel-patch/manifest.json \
  --dump "$PATCH_SESSION/synthetic.bin" --output "$PATCH_SESSION/reviewed-policy.h"
python3 host/kernel_patch.py encode \
  --manifest examples/kernel-patch/manifest.json \
  --dump "$PATCH_SESSION/synthetic.bin" \
  --identity examples/kernel-patch/identity.json --patch test-variable \
  --sequence 1 --operation verify --output "$PATCH_SESSION/request.bin"
```

Generating a policy does not approve it. An integrator reviews it, the recorded
firmware/SoC and its semantics, then compiles it into the pinned resident build
with the repository root on the include path. Never construct a live resident's
policy table from an incoming client request. The simulator mirrors a request
only to exercise synthetic host memory.

`encode` submits nothing. A saved identity is a dated input, not proof of
present readiness or a write grant. `decode --result result.bin --output
result.json` interprets a saved 248-byte result. All output paths use exclusive
creation, flush and fsync; an existing record is never replaced. A storage
failure can leave an incomplete output file, which must not be treated as a
completed record. Exit 0 means the offline command succeeded (or the simulated
operation returned `ok`), 1 means a saved simulated operation failed, and 2
means invalid input, an existing output, or a tool/storage error.

## Manifest schema 1

[The example manifest](../examples/kernel-patch/manifest.json) documents the
required fields. Unknown and duplicate JSON keys are refused. Inputs are capped
at 1 MiB of JSON and 64 MiB per image.

- `id`, exact raw `firmware` and `soc` identify the reviewed profile. No firmware
  wildcard or historical runtime base is inferred.
- `image` contains the capture `sha256`, `size` and explicit `anchors`. Anchors
  are named `text`, `data` or `resident`; each value is the signed byte offset of
  that anchor relative to the first captured byte. An anchor may be outside the
  captured region. It is not a wrapped-ELF file offset.
- There are 1–16 patches. Each has a unique `id`, `kind` (`test_data`, `data`, or
  `code`), declared `anchor`, signed 64-bit `offset`, power-of-two `alignment`
  from 1–64, and a nonempty `review` note. That note is retained evidence, not
  automatic certification of semantics. `test_data` requires `resident`.
- `expected`, `replacement` and `undo` are equally sized, lowercase hex strings
  describing 1–64 bytes. Replacement must change bytes. Undo must equal expected
  bytes; the transaction core additionally captures the actual live preimage.
- Every expected range must fit and match the hash-checked capture. Overlaps,
  including aliases through different anchors, are refused. Runtime binding
  also rejects noncanonical addresses, arithmetic overflow, misalignment and
  ranges crossing a 4 KiB boundary. All declared anchors must retain the capture
  layout when bound to a saved identity. No disassembler or semantic proof is implied.

The plan records a SHA-256 of canonicalized manifest JSON and the raw image
hash. Its `live_capability_verified` and `whole_kernel_identity_verified` fields
remain false. The generated C table preserves exact bytes, anchors, offsets,
alignment, image hash and reviewed firmware/SoC constants. The adapter must
check those constants when initializing the service; the core cannot infer the
firmware associated with an arbitrary table supplied by an integrator.

## Resident integration contract

[patch.h](../residents/patch/patch.h) defines a separate ABI; the inspection
[readiness interface](KERNEL_READINESS.md) remains unchanged and grants no writes.
It provides no syscall number, loader, hooks or physical transport. Do not route
these requests through a guessed kstuff command.

Initialize `kp_engine` outside exception context while quiescent, using a pinned
identity, independently configured policies and all seven adapter callbacks.
Initialize the storage before its first use; initialization inputs and outputs
must not alias the engine. Keep engine/request/result storage resident-owned,
stable, separate and suitably aligned. Never hand a mutable user pointer to the
core. Copy and validate the exact wire size at the bridge boundary.

The 104-byte `kp_identity` pins ABI/size, firmware, SoC, capabilities, generation,
canonical runtime text/data/resident bases, a fresh nonzero 128-bit session and
32-byte resident build identity. Capability bits are inspect=1, owned test data=2
and selected data=4. Unknown capabilities are refused. This is trusted adapter
input, not cryptographic attestation. The bridge must authenticate the operator
and pin the resident build independently of the reply. Reinitialization is not
recovery from a timeout or a way to clear poison; establish actual recovery,
quiescence and a fresh real resident session first.

Callbacks must use resident-safe code, fault-contained access and bounded work.
The core cannot preempt a hung callback or turn userland libc into kernel-safe
code. It takes one nonblocking lock-free CAS on its service gate, with no spinning
or allocation. The gate protects service state, not the target:

| Callback | Required behavior |
| --- | --- |
| `acquire` | On success, hold the real target lease and return a synchronized identity. On failure, leave no acquired lease or target changes. The lease must exclude competing writers, lifetime changes and mapping changes for the operation. |
| `snapshot` | Return the actual current identity under the same lease. Build, session, generation, bases or capability changes revoke the engine; reverting metadata cannot rearm it. |
| `mapping` | Verify range ownership, actual page access, operation kind and mutation permission under the lease. For selected data policies, enforce reviewed field lifetime, locks, alignment, memory type and semantics. Do not manufacture writability or clear protections. |
| `read` | Perform a fault-contained bounded read and report exact transferred bytes. Errors and short reads invalidate the entire reported byte range. |
| `write` | Perform only the reviewed mutation and report exact transfer. Any attempted write is treated as potentially dirty, including an error or reported zero transfer. No PCB, debug-register, IDT/TSS or protection workaround is supplied. |
| `save` | Preserve the request, full result and stage before returning success, with the durability promised by the bridge. PREPARE includes the captured preimage before any write; OUTCOME records verified commit/restoration or uncertainty; COMPLETE records lease completion. Include source/build, exact payload ELF, subject/session and command evidence in the surrounding session record. A flag for a successful save is set after that callback returns. |
| `finish` | Finish the service lease once. When quarantine is requested, retain protection of the uncertain target state and refuse further mutations. Returning success is not permission to resume an unrestored target. Define platform intervention for failed cleanup; no automatic reboot is supplied. |

No adapter is installed by these headers. A future live integration must provide
and validate the synchronization, journal, authorization and transport above.
The host backend supplies only simulated acknowledgements for those obligations.

## Read-only resident identity and lost-command recovery

[probe.h](../residents/patch/probe.h) implements a read-only query on the same
service gate as mutations. Its 64-byte request carries ABI/size, query operation,
zero reserved bits, a nonzero 128-bit challenge and an independently pinned
32-byte resident build identity. Its fixed 720-byte reply includes the echoed
challenge, pinned identity, sequence, applied-policy mask, poison state and the
last cached 320-byte request with its 248-byte result. No physical bridge or
resident installer is supplied by this interface.

`kp_probe` acquires the real adapter lease, checks actual identity and takes a
second synchronized identity snapshot before finishing the lease. Only complete
success sets `KP_PROBE_CHECKED`. These callbacks perform no core memory read,
write, journal save or command execution, and probing consumes no sequence.
Gate contention returns `KP_BUSY` with the output untouched. A build mismatch
returns refusal without exposing cached bytes or calling the adapter. A changed
identity or failed lease finish revokes the engine. Returning old metadata cannot
rearm it. An already poisoned engine returns cached diagnostics without trying
to reacquire the quarantined target.

`identity` without `KP_PROBE_CHECKED` is the recorded pin, not live readiness.
The last result remains the original command's evidence: a later probe can report
poison while retaining a previously successful cached command. That does not
prove the target's current bytes or clean execution. The bridge must authenticate
the operator and preserve the engine's session/lifetime; a public build hash and
an echoed challenge are not authentication against a malicious resident.

Create a fresh query offline using the independently known resident build hash:

```sh
python3 host/kernel_patch.py probe-request   --build "$RESIDENT_BUILD_SHA256" --output "$PATCH_SESSION/probe-request.bin"
```

This creates a new random challenge and submits nothing. After the reviewed
bridge returns one saved reply, validate it against that exact request:

```sh
python3 host/kernel_patch.py probe-decode   --request "$PATCH_SESSION/probe-request.bin"   --reply "$PATCH_SESSION/probe-reply.bin" --output "$PATCH_SESSION/probe.json"
```

Decoding checks the challenge, pinned build, identity layout, flags, poison state
and cached command/result consistency, including sequences, addresses and
verified bytes. It preserves request/reply hashes and labels saved observations
with `present_readiness_verified: false`; a saved record is not presently fresh.
A valid refusal/poison reply is saved with exit 1. Malformed or mismatched replies
return 2, leaving the input records untouched. Existing outputs are refused.
These commands neither retransmit a lost mutation nor open a console connection.

## Transactions, replay and failure handling

Requests are fixed 320-byte native little-endian records, with ABI/size,
operation, kind, sequence, pinned generation/session/build, reviewed image hash,
anchor/length/signed offset and three zero-padded 64-byte byte arrays. The image
hash selects a reviewed policy; it does not attest the whole running kernel.
The host codec serializes every field explicitly.

Operations are `verify`=1, `apply`=2, `exercise`=3 and `revert`=4. Verify acquires
the lease and checks the original bytes without writing. Apply performs one
reviewed change. Exercise is confined to owned test data and restores it before
completing. Revert uses the same policy to change its verified replacement back
to its original bytes, only after a verified apply in this engine/session.
Failed revert attempts restore the actual preimage (the applied bytes), rather
than blindly writing the manifest's original bytes as rollback.

Policies cannot overlap after runtime relocation either. A per-policy applied
mask tracks verified applies/reverts within the engine lifetime. A fresh engine
cannot infer ownership of an already patched site. Revert success has state
`committed`, meaning the requested inverse change committed; `restored` describes
restoration of a transaction's preimage after a fault or successful exercise.

The first sequence is 1 and subsequent new commands must be contiguous. Exact
replay of the last request returns its cached reply without any callback or
write. Changed same-sequence commands, skipped/older sequences and wrap are
refused. A syntactically valid in-sequence refusal consumes its sequence; invalid
requests and sequence errors do not. The bridge must preserve engine lifetime
and outstanding requests across connection loss. No timeout permits replay as
a fresh command or resetting the engine.

The core rechecks expected bytes while holding the target lease, preserves the
preimage before writing, verifies exact readback and checks identity again.
Write failures and verification failures attempt one bounded restoration under
that lease, followed by exact readback and another identity check. A changed
identity prevents restoration into an unknown lifetime. Failed restoration
poisons the engine and leaves state `unknown`. It cannot promise atomicity or
undo side effects caused by temporarily changed data.

A failed OUTCOME save after a verified apply attempts restoration while the lease
is still held and saves that outcome once more. COMPLETE-save failure happens
after lease finish; it poisons the engine without making a new unprotected write.
The result can therefore say `committed` with a journal error: bytes were verified,
but successful completion was not acknowledged. `engine_poisoned` explicitly
marks the blocked service. Preserve the first evidence and establish actual state
before recovery; do not treat an error as proof that no change happened.

Results are 248-byte records with ABI/size, status, state, flags, length, sequence,
resolved address, four adapter/journal/cleanup errors and preimage/observed/final
byte arrays. Byte validity flags distinguish absent reads from real zero bytes.
The simulator JSON includes manifest/image/request/engine hashes, supplied
identity, operation and fault, and explicitly labels the observation simulated.
It supplies no live payload hash or console evidence.

## Verification and unfinished stages

```sh
python3 -m unittest discover -s tests -p test_kernel_patch.py -v
make check
make kernel-patch-check process-debugger kernel-offset
```

The last command uses the standard Payload SDK / LLVM 18 gate. The patch target
emits only `out/kernel-patch-core-check.o`, compiled freestanding with no red zone
and general registers only. It is not an ELF, installer or proof of kernel entry.

Tests execute the actual C core and C/Python wire path. They cover identity and
policy refusal, aliases, bounds, verified apply/exercise/revert, partial and
failed writes, short/failed reads, restoration, sticky poisoning, persistence
failure, exact replay and service contention. Host simulation cannot validate
kernel locks, real page access, resident coexistence or physical transport.

Remaining plan stages require the selected resident overlay's full build and live
validation, reviewed write/hardware adapters and current console readiness. Kernel
code changes additionally require the real SMP rendezvous, instruction-boundary
and incoming-flow review, architecture-correct instruction-stream synchronization,
verified restoration and transport usable while CPUs are parked. Protocol logic
for an SMP stop is not a substitute for those hardware operations. Code mutation
remains refused until that integration exists.

### Build evidence — 2026-10-20

Local `make check` passed all 139 Python tests and the C paging checks. The native
patch test, including 16-thread replay contention, also passed AddressSanitizer
and UndefinedBehaviorSanitizer.

Built in isolated gpubox directory `/tmp/ps5-kernel-patch-final-HKu8XH` with the
staged public Payload SDK and LLVM **18.1.8**, using `make kernel-patch-check
process-debugger kernel-offset check`. SDK compilation passed without warnings;
139 Python tests ran successfully, with four optional Capstone decoder tests
skipped on that host, and the C paging checks passed. The host RSP fixture emitted
its existing unused `pipe_r`/`pipe_w` warnings. All patch tests ran on both hosts.

| Artifact | SHA-256 |
| --- | --- |
| Compile-only `kernel-patch-core-check.o` | `c923e69e3b56da6ed1c51b21e0d5d0c5a1877dfdfcd276bdde843add8e283b20` |
| Existing `kernel-offset.elf` | `a93b9211876d3d29539cecc4f21f8a992c20b5a9db094bc7c44acfb0ab9a7b17` |
| Existing `process-debugger.elf` | `c663cd2f3cf73eb06059b63c91123b04f9e706d782aadc36cba9b9a0e8b9d001` |

Ignored local evidence under `captures/kernel-patch-20261020-*/` retains build
and test logs, source hashes, exact commands and artifact hashes. Patch implementation
inputs at that point were checked against those source hashes. No ELF was sent
to a console; these builds do not validate kernel writes, the missing adapter or
any newly selected live target.

### Read-only query follow-up — 2026-10-20

The query implementation, C/Python codecs and cached-command consistency checks
passed all **142** local Python tests and the C paging checks. Native transaction
and query tests also passed AddressSanitizer and UndefinedBehaviorSanitizer.
The SDK fixture now emits the read-only query as well as the writer core.

On gpubox, isolated directory `/tmp/ps5-patch-query-HrlQCd`, the standard staged
SDK / LLVM **18.1.8** command `make kernel-patch-check process-debugger kernel-offset
check` passed. All 142 Python tests ran successfully (four optional Capstone tests
skipped on gpubox), plus the C paging checks. Query tests ran on both hosts.
SDK targets compiled without warnings; existing host RSP unused-variable warnings
remain. This is separate evidence from the earlier 139-test build above.

| Artifact | SHA-256 |
| --- | --- |
| Query/core compile-only object | `33f24f26d87ce79a36ff66de656bc3773e851d4fdcc54f2af9bee61b8c8a669f` |
| `process-debugger.elf` | `16bdd6b0ce4ac271ea88e06d6ad88674c70efc86fc05ba61f3f390b18d908f6c` |
| `kernel-offset.elf` | `a93b9211876d3d29539cecc4f21f8a992c20b5a9db094bc7c44acfb0ab9a7b17` |

Ignored `captures/kernel-patch-query-20261020-*/` preserves source/artifact hashes,
commands and local/remote test logs. Implementation inputs were checked against
the remote source hashes. No target ELF was deployed. This historical build predates the separately
implemented [stage 2 bridge](KERNEL_PATCH_STAGE2.md) and
[stage 3 owned-cell adapter](KERNEL_PATCH_STAGE3.md). Live identity and hardware
checks remain required before a console write.

## Stage 3 owned-cell adapter

The [stage 3 integration](KERNEL_PATCH_STAGE3.md) connects the transaction core to
one dedicated resident-owned eight-byte cell, with an authenticated exercise,
resident journal and read-only cached-result recovery. The source and SDK builds
are checked; complete resident links now pass as recorded in the
[build evidence](KERNEL_PATCH_BUILD.md#build-evidence--2026-10-20). SDK installer
integration/link and console validation remain pending.
