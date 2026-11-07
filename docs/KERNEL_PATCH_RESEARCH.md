# Kernel patch research for homebrew stability

Recorded 2026-10-20. This research design follows the
[existing staged plan](KERNEL_PATCH_TOOLKIT_PLAN.md). Its objective is a
repeatable PS5 Pro homebrew development environment with attributable failures
and recoverable experiments. A successful experiment is evidence for its
particular operation and build, not a general kernel safety claim.

The [experiment protocol](KERNEL_PATCH_EXPERIMENTS.md) defines falsifiers, a
44,256-case host fault campaign, sensitivity controls and the separate baseline
needed before testing a proposed kernel remedy.

The [Chain Test validity correction](KERNEL_PATCH_EXPERIMENTS.md#chain-test-validity--2026-10-21-correction)
records a missing control: no successful launch of the exact repackaged specimen
was found on any firmware. Its failure under the tested 13.60 configurations
leaves package validity and firmware compatibility confounded. Installation,
builder verification and other titles launching do not establish its launch
validity or a plaintext-wide defect.

## Questions and controls

| Question | Experiment | Evidence needed |
| --- | --- | --- |
| Can we reproduce the resident build? | Build the same pinned private overlay twice with identical LLVM/SDK/assembler inputs and layout | Source/config identity, commands, tool hashes and exact output hashes; investigate differences before a console run |
| Does the transaction path preserve its owned state? | One fixed eight-byte owned-cell exercise | Original, replacement and restored bytes; journal stages; cleanup result and challenged query recovery |
| Can a failed reply be diagnosed without repeating a write? | Lose a reply in the host integration test, then query cached history | One mutation sequence, cached request/result agreement and no second write |
| What precedes the Chain Test failure? | Analyze matching saved code first; eventually capture a bounded event from a cooperative resident adapter | Full register values, safe frame reads, process/session identity, event loss accounting and cleanup evidence |
| Would a particular kernel-data change fix an identified fault? | Specify one field and a falsifiable hypothesis before creating a policy | Field ownership, lifetime, real locking, semantics, baseline and treatment observations; the generic writer does not provide these |

The first three experiments control the tooling. They do not establish why an
application fails or that a kernel behavior change is beneficial. Keep build,
transport, transaction and application outcomes separate. Record refusals and
failed restoration as results, rather than removing them from the study.

## Three different patch subjects

The [owned-cell adapter](KERNEL_PATCH_STAGE3.md) has a concrete policy:
`4b50544553543100` becomes `4b50544553543200`, then returns to the captured
original. It accepts only that resident-owned cell, one exercise sequence and
the pinned session identity. It changes no reviewed kernel instruction and
supplies no arbitrary-address writer. Its journal is resident RAM, not storage
that survives power loss. Host tests cover this implementation; its console
milestone remains unfinished.

The `exec+0xcfc12` subject is an **observation site**, not an established repair.
The [checked capture profile](debugger/profiles/retail-13.60-pro.json) identifies
`text+0x38fc12`, the seven-byte `lea r13,[rip+0x358c6f7]`, and an incoming branch
at `text+0x38fc0a`. Those facts identify an instruction boundary in one hashed
capture. They do not establish a faulty instruction, a justified replacement or
a root cause. The workspace `../OPERATING.txt` records the October 18 xr15
trial collecting full `r15=0`, `rax=0` and `[rbp-0x68]=0xffffff80098d81a0`
twice at this join, followed by the same ShellUI failure. Its ELF SHA-256 is
`cd69e40358ed3dbac1aa35828c09eef644f006e42e416309fc866185cea59cfb`.
These are historical operator-recorded observations, not new toolkit results
or an independent revalidation of the raw ring. No trap adapter for collecting
them is installed by this toolkit.
Historical runtime addresses must be resolved again in a new session.

Selected kernel data has no reviewed real-field policy yet. A note saying a
field is reversible is insufficient: restoring bytes cannot necessarily undo
an allocation, an I/O operation, a reference-count change or another CPU's
observation. The portable core's data capability is an integration interface,
not evidence that arbitrary data is safe to change.

## How a controlled transaction works

The authenticated bridge copies a bounded request into resident-owned storage.
The service checks build/session/generation and its independently compiled exact
policy. Under a real target lease it rechecks identity, mappings and expected
bytes, records PREPARE, attempts the write and verifies the readback. An exercise
then restores the actual preimage and verifies it before recording completion.
A lost response is investigated with the read-only query, not a repeated write.
Uncertain restoration poisons the service and preserves an unknown state.

That contract is implemented for the owned cell. Code mutation is explicitly
refused in `residents/patch/patch.h`. Moving to instructions requires a concrete
hardware adapter, a consistent transition for affected CPUs/tasks and reviewed
restoration. CPU coordination alone cannot prove semantic consistency. The
[Linux livepatch consistency model](https://docs.kernel.org/livepatch/livepatch.html#consistency-model)
is a useful design reference for why active stacks, locks and shared state
matter; its Linux mechanisms are not PS5 APIs or proof of PS5 compatibility.

## Scholarly purpose and legal scope

Scholarly intent describes the study; it does not by itself establish an
exception to every applicable law. For a U.S. analysis, distinguish the specific
interoperability conditions in [17 USC 1201(f)](https://www.govinfo.gov/content/pkg/USCODE-2024-title17/html/USCODE-2024-title17-chap12-sec1201.htm)
from security testing under subsection (j). Ordinary application stability work
should not automatically be characterized as security research.

The [2024 final rule, 37 CFR 201.40(b)(18)](https://www.govinfo.gov/content/pkg/FR-2024-10-28/html/2024-24563.htm)
covers defined good-faith security research on lawfully acquired devices or
owner/operator-authorized systems, with conditions on harm prevention and use
of findings. It does not make every homebrew activity exempt or supply immunity
from other laws. The same rule's console repair and preservation provisions
have specific limitations. This is a research scope note, not a finding that a
particular proposed circumvention qualifies. Jurisdiction and the actual
operation matter.

## Reproducible next milestone

Use the [private resident build runbook](KERNEL_PATCH_BUILD.md) to pin complete
inputs, link the actual resident images, audit the loader contract and compile
the actual installer source. Keep exact build evidence with the
[stage 2](KERNEL_PATCH_STAGE2.md) and [stage 3](KERNEL_PATCH_STAGE3.md) reports.
A linked resident is not a linked SDK installer or a console-tested resident.
The remaining deployment milestone needs that installer integration and fresh
hardware/session evidence; no live experiment was performed for this note.

## Offline verification — 2026-10-20

The actual saved raw dump was rechecked with `host/kernel_offset.py`: its
SHA-256 is `20da45a0910c990153fbfb7c94e16356867e0bd84f7c9fbf754a45a5dd129673`.
An independent Capstone **5.0.7** decode at the two reviewed boundaries returned
`eb06` / `jmp 0x38fc12` at `text+0x38fc0a`, and
`4c8d2df7c65803` / `lea r13,[rip+0x358c6f7]` at `text+0x38fc12`.
The plan and decode are retained with the private build evidence. This verifies
the saved-image bytes and branch target; it supplies no new runtime observation
or evidence that replacing this instruction repairs an application.

## Next evidence to collect

Run and preserve H1's finite host campaign, then document an app-level baseline
reproducer and trial classifications for H2. Keep the treatment hypothesis open
until evidence identifies a mechanism. The [experiment protocol](KERNEL_PATCH_EXPERIMENTS.md)
defines the measurements and criteria; host transaction success does not prove
a reduction in actual console crashes.

## Reboot avoidance hypothesis

The workspace operator records show one instrumented resident per fresh session,
an observer that logs and resumes, and reader3 exports after some black-screen
failures. They do not establish ring fullness as the reason for rebooting. The
[capture reuse investigation](KERNEL_CAPTURE_REUSE.md) records those dated facts
and separates reusable storage, snapshot waits and execution recovery. Three
added host scenarios test repeated capture/restore/release cycles and demonstrate
that empty rings do not resolve missing CPUs or failed restoration. One pinned
resident with bounded observation windows is a proposed way to reduce resident
replacement, subject to exact-build ABI review and actual application recovery.
Current resident identity and health still require fresh evidence; no reboot-free
console recovery has been established.
