# Kernel offset backend

The first backend phase implements **offset resolution and bounded kernel
inspection**. Kernel breakpoints, watchpoints, stopping and stepping are still
unimplemented. It is separate from the usermode process debugger and does not
change that server's address restrictions or retired PCB-writer guard.

Read [recovery](DEBUGGER_RECOVERY.md) and [process validation](DEBUGGER_VALIDATION.md)
for the failed runs and last known console state. No new console deployment is
part of this implementation. The old console address and KASLR base are not
readiness or runtime-base defaults.

## Resolved anchor for 0xcfc12

The matching raw text capture has length `0xcc0000` and SHA-256
`20da45a0910c990153fbfb7c94e16356867e0bd84f7c9fbf754a45a5dd129673`.
It contains bytes `4c 8d 2d f7 c6 58 03` at **raw file offset `0x38fc12`**:
`lea r13,[rip+0x358c6f7]`. The incoming jump at `text+0x38fc0a` targets this
instruction. The next instruction starts at `text+0x38fc19`.

| Explicit anchor | Offset to this instruction |
| --- | --- |
| SDK kernel text base / raw dump start | `+0x38fc12` |
| SDK kernel data base | `-0x9303ee` |
| Investigation's `exec` anchor (`text+0x2c0000`) | `+0xcfc12` |
| kstuff `aslr_fix_start` (`data-0x930568`) | `+0x17a` |

`exec` names this investigation's shorthand anchor; it is not an SDK constant
or a general ELF convention. Do not treat `0xcfc12` as a raw dump offset.
Wrapped ELF file offsets also include the wrapper's program-header layout.
The host planner deliberately accepts only the hash-checked raw image.

The historical capture mapped this instruction to `0xffffffff8d9cfc12`.
That VA is evidence from the old capture only. The new payload obtains bases
from the SDK in its own session; no historical base is compiled into it.
The small [profile](debugger/profiles/retail-13.60-pro.json) records the image
identity, anchors and instruction evidence. Kernel binaries remain outside Git.

## Offline CLI

These commands make no network connection. Set `KERNEL_DUMP` to the local raw
capture, then run from the repository root:

```sh
python3 host/kernel_offset.py --dump "$KERNEL_DUMP" --anchor exec --offset 0xcfc12
python3 host/kernel_offset.py --dump "$KERNEL_DUMP" --anchor text --offset 0x38fc12
python3 host/kernel_offset.py --dump "$KERNEL_DUMP" --anchor data --offset=-0x9303ee
```

All three resolve to the same file offset. A size/hash mismatch, unknown anchor,
out-of-range offset or mismatched profile signature exits 2 with an error.
Use the `=` form for a negative hexadecimal CLI argument. No disassembler or
third-party Python dependency is required.

Other explicitly anchored offsets inside this capture can be inspected, but
`known_instruction` is null unless the profile has reviewed instruction evidence
at that exact boundary. The displayed 32-byte window does not establish a new
instruction boundary. A successful plan does not allocate a breakpoint.

## SDK inspection payload

Build on the normal gpubox LLVM 18 toolchain using the SDK/LLVM paths in
[the build record](DEBUGGER_VALIDATION.md#historical-final-build):

```sh
make kernel-offset check
```

The result is `out/kernel-offset.elf`. The backend checks firmware/model, canonical
aligned live bases, text/data separation, pmap pointers and CR3 bounds. It then
requires a valid versioned readiness handshake, or an explicitly selected legacy
cookie fallback, and audits page permissions. Read the [readiness interface and
fallback guide](KERNEL_READINESS.md) for provider integration, build modes and
strict downgrade rules. The normal build refuses when no provider is linked.
Only after those gates does it read the seven-byte instruction and compare it
with the checked image. There is no credential change, kernel write, PCB access,
IDT/TSS change, kernel function call or debug-register operation in this backend.
It reuses the existing kernel-capture page walker and firmware layout, with the
resume cookie confined to legacy mode. It does not enter prosper0gdb.

A normal kstuff session is not presumed to implement the new interface or
satisfy the legacy resume-instrumentation gates. Refusal is expected without
the appropriate reviewed adapter or explicitly selected historical profile. Do not patch the cookie,
clear protection, run suspend/resume, or install a different resident merely to
make the probe pass. Reads do not freeze other CPUs; mapping/state can change
between a page audit and copyout. This is not a coherent kernel snapshot.

After a separately established ready session, an authorized operator can send
the ELF once with the existing sender and save its log. No deployment command
is supplied as an offline test. The payload emits one line beginning
`KOFFSET_JSON=` with these fields:

| Field | Meaning |
| --- | --- |
| `schema`, `profile` | Version 2 and exact checked profile ID |
| `pid`, `observed_at_unix` | Payload process and console-clock observation time |
| `firmware_raw`, `soc_id` | Observed firmware/model identifiers |
| `kernel_text_va`, `kernel_data_va` | SDK bases from that invocation |
| `text_offset`, `address` | Site offset and resolved VA; address may be zero when base gates fail |
| `status` | Match, mismatch or explicit refusal/error |
| `bytes_read`, `observed` | Seven bytes after a successful site read; otherwise zero/empty |
| `trap_supported` | Always false |
| `readiness` | Source and versioned identity/capability evidence, or explicit legacy fallback; see [readiness](KERNEL_READINESS.md) |

Statuses are `site_signature_match`, `unsupported_firmware_model`, `invalid_bases`,
`metadata_read_error`, `invalid_pmap`, `unverified_resume_state`, `page_missing`,
`page_protected`, `invalid_page_table`, `page_table_read_error`, `site_read_error`,
and `site_signature_mismatch`, plus the [readiness refusal statuses](KERNEL_READINESS.md#json-and-host-handling). Payload exit 0 requires a match; other statuses
return 1. Sender success is not payload success.

The host planner can consume a saved JSON observation or a full sender log with
**exactly one** record:

```sh
python3 host/kernel_offset.py --dump "$KERNEL_DUMP" --anchor exec --offset 0xcfc12 \
  --probe "$SESSION/kernel-offset.log"
```

It validates the profile, firmware/model, layout, site address, byte count,
signature and schema-2 readiness evidence before relocation. Older schema-1
records are explicitly labelled as unreported legacy evidence. The output calls the result `runtime_observation`:
a saved log can be stale, and console clocks can be wrong. This command neither
connects nor establishes present readiness. For another offset,
`target_bytes_observed` is false. Even a matching site leaves
`whole_kernel_identity_verified` false.

## Execution-control adapter still required

Kernel read/write access alone does not supply safe asynchronous traps or an
SMP stop/resume mechanism. The next phase must choose and validate one trap owner:

- A cooperative resident interface could log at an already owned breakpoint,
  preserving the resident's expected instruction emulation and resume path.
  The existing research kstuff snapshots expose counters/rings; this repository
  does not have a versioned general-purpose trap-registration API for them.
- A separate clean-session prosper0gdb adapter needs its own reviewed kernel
  entry, CPU/interrupt, IDT/TSS, exception-chain and restoration behavior. It
  cannot be initialized alongside kstuff merely because the offset resolved.

All four DR slots were occupied in the previous session. No slot stealing,
direct-PCB fallback, software `int3` patch or implicit IDT/TSS replacement is
implemented here. A future adapter needs explicit resident/build identity,
verified ownership, bounded per-CPU event capture, overflow accounting,
reversible disarm, and a transport that does not depend on scheduling network
code while a CPU holds a kernel stop. Full r15, rax and the safely read
`[rbp-0x68]` are useful proposed join observations; low 32-bit r15 alone did not
identify the prior failure. Collecting those registers is not implemented by
this byte-inspection payload.

## LLM and validation contract

Agents should run the offline planner first, preserve its report and raw dump
hash, and report an unresolved kernel execution adapter explicitly. Do not issue
`hbreak` through the process debugger for the resolved kernel VA. A byte match
is not an event, trap hit, root-cause finding or permission to modify the resident.
Preserve dated session facts and stop after a probe refusal instead of choosing
a more invasive fallback. Current local source overrides stale Context7 snippets.

Host tests exercise anchor equivalence, hash/range refusal, probe identity and
address consistency, the actual C backend's page/metadata failure paths,
protected ancestors, signature mismatch and no site reads on refusals. They
cannot validate SDK kernel access, a live page map, console exception handling
or kstuff coexistence. Record an exact LLVM 18 ELF hash separately from those
host checks. This backend has not been deployed or console-validated.

### Build evidence — 2026-10-18

This historical record predates the readiness-handshake change. See
[readiness verification](KERNEL_READINESS.md#verification-boundary) for the new
source and its separate build evidence.

Built on gpubox in `/tmp/ps5-kernel-offset-HSfy8t` through
`make kernel-offset process-debugger check`, with the staged public SDK and
LLVM **18.1.8**. Both payloads compiled without warnings. All **50** Python
tests (including the native kernel backend) and the C paging checks passed
on gpubox and locally. The offline planner also matched the saved real dump.

`kernel-offset.elf`: **117,816 bytes**, SHA-256
`8b89e463d74050dd1f4c0ead07fd2f93c4b049d2bb263164a3bed7607b1baffa`.
The process-debugger hash remains
`3121031f6acd83fbc3e40c64e020f7cadfbaa38d0a603cd91c5644319cdab817`.
The local ignored evidence directory `captures/kernel-offset-20261018/` holds
the new ELF, build/source hash manifest and offline plan. Neither ELF was sent
to the console. The build used an uncommitted working tree; its source hashes
are retained in the local manifest. Publishing the source does not release a
validated kernel debugger or refresh Context7. These checks do not validate
kernel exception handling.
