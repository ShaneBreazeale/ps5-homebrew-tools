# Durable checkpoints and resident panic evidence

The first usable layer is an app-side checkpoint library and host receiver.
An enabled checkpoint returns success only after the receiver appends its record
and successfully calls `fsync`. The resident layer adds preallocated trace and
panic records with a bounded polled exporter. It does **not** install a resident,
hook panic entry, or implement a PS5 UART/device driver. No new console run has
validated either layer.

## Experiment identity comes before probe interpretation

The operator reports the successive experiments
`xapp → xoff → x580 → xrw → xmap → xor4 → xtest → xjoin → xr15 → probes → xvm → xv12 → xraw → xprc → xjp → xtmap → xtor4 → xeax`.
These are timed resident/payload variants and probes, not stages executed by
one app. Only some older variants have recovered source here; see the
[resident catalogue](../residents/README.md). This list does not establish the
hash, implementation, or outcome of the current `xeax` build.

Keep each experiment's exact ELF hash, source/build identity, firmware/model,
resident generation, hypothesis, expected subject process/PID/lifetime, and
versioned probe schema. In particular, distinguish the observer thread/process
from the title or ShellUI process whose `proc`, appinfo or vmspace is sampled.
Legacy markers such as `PPREKX01`, `PPREXV01`, `PPRWRF01` and `PPRMAP01` do not
automatically acquire meanings in this protocol. Assign reviewed numeric site
IDs and record their argument meanings for the exact producing build. The
same old marker may have different layouts or ambiguous success/failure shapes.

For exec/map experiments, separate observations of the original value, intended
store, store result/readback, and a later join/ASLR observation. A before event
does not prove the store executed. A successful store/readback does not prove
the value survived process creation or reached the expected subject. Preserve
full-width pointers, R15 and RAX; a bit or low 32-bit match alone is insufficient.

## Durable app checkpoints

[checkpoint.h](../lib/checkpoint/checkpoint.h) and
[checkpoint.c](../lib/checkpoint/checkpoint.c) are an ordinary usermode C library.
Link the C file into the app or payload. Initialize a fresh client, choose a
64-bit group mask at runtime, connect once to an explicit host IPv4 literal,
and publish checkpoints around the suspect operation:

```c
/* client was initialized and connected successfully; caller serializes it. */
uint64_t args[4] = {request_id, request_size, 0, 0};
int error = cp_emit(&client, 0, observer_tid, SITE_SUBMIT, PE_BEFORE, args);
if (error) return error; /* do not execute the suspect operation after failure */
int result = suspect_operation();
args[2] = (uint64_t)(int64_t)result;
error = cp_emit(&client, 0, observer_tid, SITE_SUBMIT, PE_AFTER, args);
if (error) return error;
```

Each enabled call sends one fixed-size record and waits for its exact
session/sequence acknowledgement. Connect plus its hello share one deadline;
each checkpoint has one deadline covering send and ACK, bounded to 1–60000 ms.
Failures close the socket and remain sticky. There is no reconnect or replay.
One caller uses a client at a time; provide app-side serialization if needed.
The client tags its own PID at initialization. The receiver refuses a PID
change within that connection; a fresh session still needs process-lifetime
evidence rather than assuming a reused PID identifies the same app.
Disabled groups return success without sending, so record the chosen mask in
the run metadata. Changing a group mask between experiments needs no rebuild;
changing site placement does.

Call `cp_end` to record the application's explicit end and close the connection.
`cp_close` alone sends no completion claim. A stored record whose ACK was lost
still survives on the host; the app must treat that call as failed. A host log
therefore does not establish that the app received the ACK or ran the next call.

These functions may block and depend on normal scheduling/networking. Never
invoke them from a kernel trap, resident callback or panic handler. They can
record the app's boundary before entering a syscall that subsequently fails in
the kernel, but cannot recover a kernel stack after networking dies.

## Receiver and local example

Run from the repository root. These example commands target **loopback only**
and do not send an ELF to a console. Choose a fresh session for every run:

```sh
SESSION=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
BUILD_ID=$(python3 -c 'import hashlib; from pathlib import Path; print(hashlib.sha256(Path("examples/checkpoint-demo/main.c").read_bytes()).hexdigest())')
mkdir -p out captures
cc -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
  examples/checkpoint-demo/main.c lib/checkpoint/checkpoint.c \
  -o out/checkpoint-demo
```

On a Linux host the example binary is ELF64. Start the receiver in one terminal
and run the example in another, using the same `SESSION` and `BUILD_ID`:

```sh
python3 host/checkpoints.py listen --bind 127.0.0.1 --port 10071 \
  --session "$SESSION" --build-id "$BUILD_ID" --experiment demo-001 \
  --artifact out/checkpoint-demo --output captures/demo-001.jsonl
```

```sh
out/checkpoint-demo 127.0.0.1 10071 "$SESSION" "$BUILD_ID" 1
python3 host/checkpoints.py summary captures/demo-001.jsonl
```

For a macOS loopback run, `--artifact` must point at a corresponding SDK-built
ELF, and the metadata should identify that the executed client is the host-built
Mach-O simulation. The native unit tests run this exchange on both macOS and
Linux without labelling a Mach-O file as an ELF.

For a console run, first establish the actual authorized session and target.
Select the host's LAN interface with `--bind`, not the console address. This is
a separate evidence service, not RSP or the ELF loader. It accepts exactly one
connection and never contacts the console or deploys an artifact. Default bind
is loopback. Session/build checks identify records; they are not authentication.
Use a controlled network. No automatic second client is added to GDB.

`--artifact` is required by `listen`; it hashes up to 128 MiB and requires an
ELF64 little-endian header. It is never sent. `--build-id` is a separately chosen
32-byte source/build fingerprint supplied to the library; it is not necessarily
the final ELF hash. This avoids requiring a binary to embed its own hash. Match
the fingerprint with the recorded artifact through the build manifest.

`--metadata LOCAL.json` accepts an object up to 64 KiB. For example:

```json
{
  "firmware": "record actual firmware",
  "model": "record actual model",
  "hypothesis": "record the store/join hypothesis",
  "expected_subject": {"pid": null, "title_id": null, "role": "record title or ShellUI"},
  "resident_generation": null,
  "groups": "0x1",
  "probe_schema": "local-reviewed-v1",
  "sites": {
    "100": {"name": "demo_math", "arguments": ["input", "result", "unused", "unused"]}
  }
}
```

The example site 100 is the benign demo operation, not a kernel hook. Fill in
actual identities and site schemas before interpreting a real experiment.
Do not collect unrelated private data in this metadata.

The receiver reserves a new mode-0600 JSONL file, syncs its manifest and parent
directory, then starts listening. Every event retains raw bytes, CRC, decoded
fields and host receipt time. Append/write/fsync failure prevents acknowledgement;
the failed journal is not reused. Files and existing symlinks are never
overwritten. Durability is the host OS/filesystem's `fsync` contract, subject to
the storage hardware honouring it; console RAM is not durable storage.

The defaults are 100000 records, a 30-second accept/receive/ACK timeout and a
3600-second connection deadline. `--max-records` permits 1–1000000 records;
timeout/deadline options permit positive finite values up to 86400 seconds.
Total duration starts after acceptance. EOF and timeouts preserve evidence and
report transport termination, never a kernel-crash diagnosis. Exit 0 requires
an application-end record; transport/protocol termination returns 1 and setup
errors return 2. A complete final record can remain without an ACK or footer.

`summary` is offline. It rechecks raw bytes, decoded fields, identity, sequence
and footer hashes, reports unpaired before checkpoints, and retains per-CPU
resident domains separately. It reads at most 256 MiB/1000000 events, limits a
line to 128 KiB, and shows at most the last 128 pending calls. A torn final JSON
line is explicitly marked. Larger journals remain raw evidence and require a
deliberately partitioned investigation. A pending call identifies an interval;
asynchronous work, another thread or earlier corruption can still be causal.
ShellUI dying, a black display or network EOF alone does not establish a kernel
panic.

## Resident traces and panic storage

[residents/evidence/evidence.h](../residents/evidence/evidence.h) is a separate
freestanding integration core. Allocate its storage outside exception context,
wire it and its code, verify actual resident/build/session/CPU scope, then call
`re_init` while all participants are quiescent. Configuration stays immutable
during recording. This core does not provide resident ownership verification.

`re_trace` records four raw 64-bit values with a site, phase, observer thread,
CPU and adapter timestamp. `re_trace_context` optionally also copies all 18
GP/control observation words, in order RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP,
R8–R15, RIP, RFLAGS. These are caller-supplied observations, not getters or a
native trap-frame ABI. Existing cooperative trap owners can feed observations
after their own provenance/ownership checks. This introduces no additional DR
slots and never programs DRs, PCBs, IDT or TSS.
`re_trace_context` and `re_panic` also accept an explicit subject PID: the
process being sampled, which may differ from the observer thread's process.
Zero means unknown. The simpler `re_trace` wrapper leaves the subject unknown;
use the context form (with a null register pointer if appropriate) when probing
title versus ShellUI structures.

Each of up to 16 CPUs has 32 fixed records, a bounded hit budget of 1–65535,
and a single-attempt producer gate. Nested producers return busy instead of
waiting. A full ring preserves prior events and counts loss. Rejected attempts
are a modulo-2^32 diagnostic counter; successful/full accepted attempts consume
the finite hit budget and produce visible sequence gaps. Nested gate rejection
does not allocate a sequence. Expired-budget rejections are signalled by the
return value, not added to the dropped counter. Adapter code must retain those
statuses/counters; never silently label a truncated run complete.

`re_panic` has a **separate first-writer slot per CPU**, independent of the trace
producer gate. It can save caller-supplied code/fault arguments and optional
registers even when that CPU interrupted a trace write. No pointer dereference,
stack unwind, formatted panic string, CPU rendezvous or network call occurs.
An interrupted/incomplete panic-slot write is not exported. The adapter must
establish whether an event really came from kernel panic entry; a supplied
record is evidence of that adapter assertion, not independent verification.
Not all CPUs are guaranteed to reach panic entry, so missing CPUs are expected.

## Export when normal scheduling is unavailable

`re_export_init` prepares an exporter in trace mode (0) or panic-only mode (1).
`re_export_poll` makes at most one nonblocking `re_try_write` callback per call,
with at most 288 bytes. It handles partial transfers and backpressure, with a
finite total poll budget of 1–65536 and a monotonic adapter deadline. Timeout,
backwards time, budget exhaustion or device failure becomes sticky. There is no
automatic reset/replay into a partially failed byte stream. Accepted bytes mean
device acceptance, not host receipt or persistence.

Exactly one exporter of each mode may consume a store. The normal trace exporter
does not touch panic slots. A **preinitialized panic-only exporter and independent
physical channel** can still export the ready panic records if the normal
exporter/device was interrupted with its gate held. Do not use the same device
lock/channel from both contexts, allocate the panic exporter in panic context,
or infer that reentrancy is safe. Do not start another exporter of the same mode
until the adapter has quiesced the old one and established a new output stream.

The callback must be a reviewed polled device/shared-memory bridge that remains
usable with interrupts and ordinary scheduling unavailable. It must return
promptly and preserve byte ordering. The core cannot rescue a callback that
hangs, a CPU that never executes, a dead device, or a powered-off console. The
adapter supplies a safe clock and bounds the entire call sequence. Normal TCP,
stdio, socket syscalls, sleeping locks and userland workers do not satisfy this
panic transport contract. This checkout provides the core/callback contract,
not a physical PS5 driver or a panic installer.

On the host, ingest an exact raw saved/bridged stream into a new durable journal:

```sh
python3 host/checkpoints.py ingest --input panic-stream.bin \
  --session "$SESSION" --build-id "$BUILD_ID" --experiment xeax-001-panic \
  --artifact path/to/exact-resident.elf --output captures/xeax-001-panic.jsonl
python3 host/checkpoints.py summary captures/xeax-001-panic.jsonl
```

`--input -` consumes stdin from an independently configured bridge; it may wait
for that bridge to close. The host can use normal scheduling; the console panic
writer cannot rely on it. No ACK is emitted by ingest. CRC/magic/identity errors
stop decoding without resynchronization and retain the rejected/partial frame.
Trace/panic sequence domains are separate per CPU; timestamps do not establish
a global order. Source CPU rings and panic slots remain volatile until exported
and durably saved on the host. Evidence never received before reboot is lost.

## Record format

Schema 1 is exactly 288 bytes, explicitly little-endian; native C struct layout
is never transmitted. [common/evidence.h](../common/evidence.h) and the host
decoder share the following layout:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | ASCII `PS5EVID1` |
| 8 | 4 + 4 | Schema (1), kind (hello/checkpoint/trace/panic/end = 1/2/3/4/5) |
| 16 | 16 | Fresh session bytes, represented as two little-endian words in C |
| 32 | 8 + 8 | Sequence, source ticks |
| 48 | 4 + 4 + 4 + 4 | CPU, observer thread, site, phase (point/before/after = 0/1/2) |
| 64 | 32 | Source/build ID bytes |
| 96 | 32 | Four raw 64-bit arguments |
| 128 | 144 | RAX..R15, RIP, RFLAGS in the declared order |
| 272 | 4 + 4 + 4 | Flags (bit 0: register values valid), dropped counter, subject PID |
| 284 | 4 | Standard CRC32 over bytes 0–283 |

CPU `0xffffffff` identifies the usermode checkpoint stream, not a measured CPU.
Subject PID 0 is unknown. Unknown flags, invalid phases/identities and register
bytes without their validity flag are rejected. Checkpoint sequences start at
1 with hello and stay contiguous. Resident sequences are per-CPU/per-kind;
panic has one record per CPU, while trace gaps disclose consumed/lost hits.

An ACK is exactly 32 bytes: ASCII `PS5ACK01`, the record's 16 session bytes and
its little-endian 64-bit sequence. Only the checkpoint receiver sends ACKs,
after persistence. CRC and identity fields detect corruption/mixing, not a
malicious sender. No wire instruction authorizes writes, execution or reboot.

## Verification and remaining integration

```sh
python3 -m unittest discover -s tests -p test_checkpoints.py -v
make check
make evidence-check process-debugger
```

`make evidence-check` uses the ordinary SDK/LLVM 18 gate to build a benign
checkpoint example ELF and a freestanding resident compile-check object. The
example requires explicit runtime configuration and is not added to `make all`.
The object contains no installer/entry hook or physical driver.
Its compile flags disable the red zone and FP/SIMD register use, in addition to
freestanding/no-builtin compilation. An actual resident integration must retain
appropriate kernel compilation rules and independently preserve exception state.

Host tests exercise the actual C client against a loopback receiver, fsync-before-
ACK ordering, disk failure, malformed/lost ACKs, runtime groups, partial streams,
identity/replay rejection, summary integrity, and C-to-Python record compatibility.
Native C tests simulate 16 concurrent producer CPUs, bounded rings/budgets,
optional full-width GP state, nested panic capture, an interrupted normal
exporter, partial/backpressured device output and sticky failure. They cannot
validate PS5 panic entry, UART access, actual exception context or resident
coexistence.

Next live integration requires the exact current variant source and build,
reviewed hook ownership and process identities, plus an established independent
debug link. Preserve the [recovery/session constraints](DEBUGGER_RECOVERY.md).
No console deployment, automatic reboot, exploit rerun or loader retry is part
of this implementation.
