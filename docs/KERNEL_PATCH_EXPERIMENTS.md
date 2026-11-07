# Kernel patch study: hypotheses and experiments

Recorded 2026-10-20. This is the next protocol for the
[homebrew stability study](KERNEL_PATCH_RESEARCH.md), not a console deployment
procedure. Freeze the hypothesis, measurements, outcomes and stopping rules
before a new experiment. Host simulations and saved-image analysis cannot
measure a reduction in actual console crashes.

## H1: transfer-fault containment

**Claim under test:** with a stable simulated identity, an exclusive adapter
lease and working journal/finish callbacks, the portable transaction core
correctly handles the transfer faults specified below. A fault must produce
verified unchanged/restored state or explicit uncertainty. Unverified restoration
must poison the engine, retain quarantine and prevent another mutation.
A successful acknowledgment must never substitute for a required readback.

**Falsifier:** any modeled case falsely reports success/restoration, leaves
unexpected bytes in a reported restored state, changes adjacent simulated
memory, invokes adapter callbacks on exact replay, or permits another mutation
after uncertain restoration. One counterexample is sufficient to fail this
finite experiment. Zero counterexamples supports only this specified model.

The [native campaign](../tests/kernel_patch_campaign.c) executes the actual
`patch.h` engine, with the existing host memory adapter and test-only read/write
fault wrappers. It does not use a second Python implementation of the engine.
The three operations are APPLY, EXERCISE and REVERT, for each length 1–64.
REVERT first performs a real successful APPLY: failed REVERT must restore the
replacement preimage, rather than incorrectly restoring the original bytes.
This tests the portable core; the stage 3 bridge still accepts only its fixed
eight-byte EXERCISE.

| Scenario | Injected boundary | Cases |
| --- | --- | ---: |
| Fault-free controls | Three operations × 64 lengths | 192 |
| Short initial write | Actually copy and report 0 through N−1 bytes | 6,240 |
| Initial write error | Actually copy 0 through N bytes, report zero and an error | 6,432 |
| Short restoration write | Actually copy and report 0 through N−1 bytes | 6,240 |
| Restoration write error | Actually copy 0 through N bytes, report zero and an error | 6,432 |
| Short preimage read | Return 0 through N−1 bytes; require no write and no valid preimage | 6,240 |
| Short replacement readback | Return 0 through N−1 bytes; require verified restoration | 6,240 |
| Short restoration verification | Return 0 through N−1 bytes; require unknown/poisoned state | 6,240 |
| **Total** | Fixed deterministic grid | **44,256** |

For APPLY/REVERT restoration scenarios, a full initial write returning an error
triggers the rollback path. This is a specified compound fault, not a claim to
cover every combination of failing callbacks. All cases also check surrounding
sentinels, PREPARE-before-write with the correct preimage, lease completion and
callback-free exact replay. Every uncertain-restoration case checks the
read-only poisoned diagnostic and rejection of the next mutation sequence.

Two sensitivity controls compile **disposable copies** of the core with known
unsafe changes: skipping rollback after an initial-write fault, and ignoring
restoration errors/readback mismatch. The campaign must detect both. The real
core and existing build overlays are not modified by these controls.

## Run and preserve the host experiment

These commands require only a host C compiler and Python. They make no network
connection and build no console payload:

```sh
# Create a NEW evidence directory; choose the parent directory explicitly.
STUDY_SESSION="$(mktemp -d /tmp/ps5-kernel-study-XXXXXX)"
make kernel-patch-campaign \
  KERNEL_PATCH_CAMPAIGN_OUTPUT="$STUDY_SESSION/fault-campaign.json"
python3 -m unittest discover -s tests -p test_kernel_patch_campaign.py -v
```

Use `HOST_CC` to select the host compiler. `make check` includes the campaign,
its evidence tests and its deliberately broken sensitivity controls. The saved
report records UTC observation time, platform/Python, exact source SHA-256s,
compiler version, compile/run commands and diagnostics, exit statuses, executable
hash and per-scenario coverage. It checks source hashes again after the run.
An existing output is refused before compiling; records are flushed and fsynced.

Exit 0 means the complete grid passed. Exit 1 means a recorded failed or
unverified experiment, including a compiler/run failure, incomplete coverage or
source changes. Exit 2 means invalid input or an evidence-file/storage error.
A nonzero exit or incomplete output is not a completed successful record.
On a detected invariant failure the native driver reports scenario, operation,
length, cut and source line for reproducing the first counterexample.

**Boundary:** these experiments assume the adapter owns its byte array. They do
not establish hardware fault containment, live mapping lifetime, real field
locking, transport durability, power-loss recovery, instruction patch safety or
a lower PS5 crash rate. Existing tests cover journal failures, changed identity,
concurrent callers and lost replies separately; this grid is not exhaustive over
those dimensions. A hung callback is bounded by the host runner's process
timeout, not preempted by the transaction core.

## H2: characterize the actual application failure

### Chain Test validity — 2026-10-21 correction

The recorded result is: **this package fails under the tested 13.60
configurations; package validity and firmware compatibility remain confounded.**
Chain Test is a repackaged PS5SX2 app, not a demonstrated working launch control.
No successful launch of this exact package on 11.00, 11.60 or another firmware
was found in the reviewed workspace records.

The saved package is 49,465,990 bytes, SHA-256
`ee2e853aa2a61d27da7017d14ba98d528af71b2af6521373b9551c4f8214511d`.
Both saved copies match that identity. A local comparison confirms that the
staging tree's executable, `libc.prx` and presentation assets match the downloaded
PS5SX2 originals byte for byte; title/content IDs, name and version metadata
were changed. This comparison does not verify the files inside the package or
on the console. The historical builder verification and successful installation
do not establish launch validity. Package construction, metadata/SELF
compatibility, installation state and application assumptions remain candidates.

GT7 launching with the same resident and the original PS5SX2 launching through
its usual installation path are useful observations, but neither validates this
repackaged specimen. “Plaintext-specific” in the older notes means observed
with this plaintext specimen; a plaintext-wide or firmware-specific cause has
not been isolated. Trace progress and a lost loader connection identify observed
boundaries, not proof that a particular copy operation caused the failure.

Before attributing this result to firmware or selecting a kernel remedy:

1. Demonstrate a successful launch of the exact hash-checked package on a
   firmware/resident combination with demonstrated support for its package
   format; observe application progress beyond startup.
2. Compare an independently demonstrated working homebrew FPKG on 13.60,
   recording its exact package and resident identities and trial outcome.
3. Prefer a minimal app with an immediate startup marker and heartbeat for
   further tracing, validating both its normal and FPKG launch paths first.

These are missing controls, not completed experiments or live-run instructions.

### Observation hypothesis

The root-cause hypothesis remains **open**. Before choosing replacement bytes,
write a concrete observable claim, for example: “The failed launch reaches this
join with a distinct full-width state compared with successful launches of the
same app/build/session profile.” That is an observational hypothesis, not yet a
claim that the join causes the failure.

The matching dump confirms the instruction and incoming branch at
`exec+0xcfc12`. Its presence alone does not identify a bad instruction. Full
`r15`, `rax` and a safely read `[rbp-0x68]`, plus the read's success/error status,
are proposed observations. Retain full values; truncation can alias different
states. Record event ordering and lost/dropped-event counts. A missing event
with an unavailable capture path cannot be interpreted as “the path did not
execute.” The cooperative runtime capture adapter is still missing, so this
experiment cannot currently be run by the inspection payload.

Document an app-level reproducer first: exact source/binary, launch steps,
inputs, a completion checkpoint, a finite time budget and an independently
observable result. Use app-side checkpoints and host evidence where available
before attributing a failure to kernel execution. Separate:

- completed workload with the agreed checkpoints;
- observed app error/exit, including its recorded status;
- timeout while the target/session state remains known;
- loss of session connectivity or unknown target/cleanup state;
- unavailable/incomplete capture.

Retain every attempt with its classification. A timeout or lost TCP response
alone does not demonstrate a kernel panic. Missing or invalid evidence remains
inconclusive, rather than being counted as a successful run or silently dropped.

## H3: test one proposed remedy

Define this only after H2 identifies a specific mechanism and the toolkit has
the required live adapter. Record the exact field/instruction, expected and
replacement bytes, ownership/lifetime/locking semantics, expected behavioral
change and what would disprove it. Restoring bytes does not necessarily undo
other CPUs' observations or kernel side effects.

Start with a documented pilot baseline to estimate reproducibility and failure
frequency; do not choose a significance claim or sample size from zero console
observations. A later treatment comparison must keep firmware/model, resident,
compiler/SDK, app and workload fixed and change the reviewed treatment alone.
Specify the number/order of trials and analysis rule before collecting results.
Where a reversible treatment actually permits comparable restoration, a
baseline → treatment → verified-restoration baseline can help expose drift.
Returning bytes to their preimage does not by itself establish an equivalent
system state. Do not pool different builds/sessions as interchangeable trials.

The trial record should include: trial ID; protocol version; timestamps;
source/config/build and final ELF hashes; toolchain; current firmware/model and
resident identity; app hash and current numeric PID/lifetime; baseline/treatment;
workload/checkpoints/budget; raw capture references and errors; observed outcome;
before/replacement/restored bytes where relevant; and explicit cleanup state.
Store large/raw private captures separately and reference their hashes.

Stop the experiment on a failed identity check, unexpected target state,
uncertain restoration or unknown cleanup. Preserve the failed observation and
remaining budget. This protocol supplies no automatic payload resend, reconnect,
reboot or resident replacement.

## Evidence — 2026-10-20

This protocol was developed and exercised as a tooling experiment; it is not
a formally preregistered confirmatory study of console crashes. The new host
campaign passed all **44,256** cases with zero counterexamples.
The same grid passed AddressSanitizer and UndefinedBehaviorSanitizer. Both
known-bad sensitivity controls were rejected with the expected counterexamples.
Compiler failure, unavailable compiler and evidence overwrite refusal are tested.
These results concern host fault containment only; no console test was performed.

Local `make check` passed all **165** Python tests plus C paging checks.
Saved standard and sanitizer reports are retained under the ignored private
evidence directory `captures/kernel-patch-study-20261020-1lg8imjb/`. The
production transaction core and console payload sources were not changed.

### gpubox replication

Observed at `2026-10-21T01:18:45.785294+00:00` on Linux x86-64,
using Ubuntu GCC **13.3.0** in isolated directory
`/tmp/ps5-patch-campaign-pTpTcM`. The exact campaign/core input hashes
were matched before transfer and against both returned reports. Standard and
AddressSanitizer/UndefinedBehaviorSanitizer runs each passed all **44,256** cases
with zero counterexamples. All **four** campaign/evidence tests passed, including
both deliberately broken rollback sensitivity controls. This was the targeted
campaign suite, not a rerun of the entire repository test suite.

Local evidence: `captures/kernel-patch-campaign-gpubox-0l70sr54/` contains the
source pins, reports, commands and logs. These results replicate the finite host
experiment on Linux x86-64/GCC alongside macOS arm64/Apple Clang; they add no
console execution or crash-rate observation.
