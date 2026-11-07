# Kernel patch toolkit: stage 2 integration

Stage 2 now has a pinned resident source overlay, authenticated read-only dispatch,
a synchronized inspection publication, an SDK client and saved-log verification.
The implementation is host-tested and SDK-compiled. It has not been installed or
validated on a console. The [full plan](KERNEL_PATCH_TOOLKIT_PLAN.md) remains open.
As of the 2026-10-18 operator report no console session had been established after
run 007; see the dated [recovery note](DEBUGGER_RECOVERY.md) before planning any
live step.

## Selected source and scope

The [source profile](../residents/patch/stage2-profile.json) pins kstuff-lite commit
`47da23b70685651a475d20247a3c4f2cac433eb4`, with exact hashes for eight integration
files. The supported environment is retail PS5 Pro 13.60, SoC `0x840fd0`, with the
reviewed `data-text = 0xcc0000` layout and instruction signature at `text+0x38fc12`.
A site match does not attest the whole kernel or supply execution control.

The source overlay adds a new `getppid` dispatch selector `0x4b500001`, handled
inside the existing resident hook. The SDK command is `0x4b50000100000027`.
This selector is implemented by the prepared overlay; it is not presumed to exist
on a stock or historical resident. Existing debug-register, trap, PCB, IDT/TSS and
application-policy paths are not modified by the added query handler.

Only inspection capability `1` is published. The stage 2 channel cannot dispatch
`apply`, `exercise`, `revert` or arbitrary memory operations. It has no write
engine or mutation history; its sequence, applied mask and cached records remain
zero. The general [probe interface](KERNEL_PATCH_TOOLKIT.md#read-only-resident-identity-and-lost-command-recovery)
continues to support real engine history for future integration.

## Prepare an isolated private overlay

From the repository root, set `KSTUFF_SOURCE` to the matching local checkout and
choose a new output path under ignored `out/`. The output must not already exist:

```sh
python3 tooling/prepare_kernel_patch_stage2.py \
  --source "$KSTUFF_SOURCE" --output out/stage2-private
python3 tooling/verify_kernel_patch_stage2.py --overlay out/stage2-private
```

The preparer checks the source commit and the integration files against their
pins before writing output. It exports selected **committed** sources; unrelated
uncommitted research files and captures are excluded. It leaves the source
checkout untouched. Changed markers, changed integration files, escaping symlinks
and existing output directories are refused. Failed preparation leaves an
`INCOMPLETE` marker for inspection; use a fresh path after resolving the failure.

The private output contains:

| Path | Purpose |
| --- | --- |
| `source/ps5-kstuff/main.c` | Installer integration: model/entropy gate, per-CPU readback and publication of newly allocated stage 2 state |
| `source/ps5-kstuff/uelf/kekcall.c` | New authenticated selector dispatch; other handlers preserved |
| `source/ps5-kstuff/uelf/shared_area.h` | Append-only 176-byte stage 2 state; existing field offsets and snapshot format preserved |
| `source/ps5-kstuff/uelf/kp_stage2_bridge.c` | Concrete resident permission/copy/query adapter |
| `source/ps5-kstuff/uelf/kp_stage2/` | Portable bridge, producer/client interfaces, bootstrap and private configuration |
| `client-config/kp_stage2_config.h` | Matching SDK client build pin and bearer credential |
| `manifest.json` | Commit/profile, transformed source hashes, configuration hash and source/config build identity |

This is a reviewable source overlay, not a complete resident distribution or
installer ELF. The preparation command does not build or run the research
installer. The selected original installer contains its own preexisting setup;
this integration adds no IDT/TSS writer or debug-slot allocation.

The output directory is mode 0700 and configuration files are mode 0600. A fresh
256-bit bearer secret is generated for each overlay. The configured resident
and SDK ELF contain that secret and must stay with the private build inputs,
outside Git and public bundles. No secret is printed in logs or exported in
query replies. The normal `all` and `bundle` targets exclude the optional stage 2
client. A source/config build ID is distinct from a final resident or payload
ELF hash; record those artifact hashes separately.

The verifier checks current integration source, generated files, the source/config
identity and matching client/resident configuration. Changing integration code
requires a fresh overlay. A build identity or bearer token is not cryptographic
attestation against an already compromised privileged environment.

## Standard SDK builds

Use the standard Payload SDK / LLVM 18 configuration from [building](BUILDING.md).
The default client has no provider and performs no speculative resident call:

```sh
make kernel-patch-stage2
```

It builds `out/kernel-patch-stage2.elf`; when run without a provider it reports
`provider_unavailable` and exits 1. This is an explicit refusal, not evidence that
a live resident lacks the interface.

Build the configured private client and compile-check the actual overlay:

```sh
make kernel-patch-stage2 \
  KERNEL_PATCH_STAGE2_CONFIG="$PWD/out/stage2-private/client-config"
make kernel-patch-stage2-check \
  KERNEL_PATCH_STAGE2_OVERLAY="$PWD/out/stage2-private"
```

The first target verifies the overlay and builds the explicitly linked SDK
provider. The client is rebuilt every invocation so changing between configured
and provider-free modes cannot silently reuse a credential-bearing ELF.
The second emits three freestanding, no-red-zone/general-register-only objects:
resident bridge, actual patched dispatch translation unit and bootstrap fixture.
These objects are compile checks, not a linked resident or installer. The check
uses the SDK's LLVM gate and the exported pinned resident headers. No compiler
version override or research-runtime payload is substituted.

No command here installs the overlay, sends an ELF, reconnects to a target or
checks current console readiness. Use a fresh, separately identified resident
build and session for live verification; follow [recovery](DEBUGGER_RECOVERY.md).
The previous console address and runtime bases are historical observations.

## Authentication, publication and read-only checks

[bridge.h](../residents/patch/bridge.h) accepts only a 104-byte envelope containing
ABI/size, a 32-byte bearer credential and the 64-byte probe. It refuses kernel or
noncanonical user buffers, overlap, wrong lengths/reserved values, invalid queries
and wrong credentials. All credential bytes are compared before deciding. Bad
credentials are refused before querying the resident's pinned metadata; permission
checks needed to copy the caller's envelope happen first. Credentials are wiped
from the temporary request after processing. Authentication errors are not
converted into absence or an unprotected fallback.

[kstuff_stage2.c](../residents/patch/kstuff_stage2.c) supplies the concrete adapter.
It checks present/U/S/R/W permissions at all required page-table levels, protected
ancestors, huge-page shape and physical bounds. Read requests and reply copies
are bounded to 1,024 bytes and tied to the saved caller CR3. The reply destination
is checked again before copying. **These audits are not OS page pins.** Mapping
changes on another CPU can race a permission audit and physical copy. Host tests
cannot validate caller mapping lifetime, the direct mapping or hardware fault
containment; those are material live-integration validation requirements.

[stage2_loader.h](../residents/patch/stage2_loader.h) is integrated only into the
new-installation path. It checks the real SoC, obtains a fresh 128-bit session
from `/dev/urandom`, and verifies the three existing IST entries after each of the
16 CPU setup iterations. These are readbacks, not new TSS writes. Publication
requires all CPU completions, canonical identity/bases, a valid pmap/CR3 and the
reviewed instruction bytes. It refuses nonzero destination storage, so an active,
revoked or incomplete publication is not overwritten as recovery.

The 176-byte state fits both existing shared allocations: the resulting layouts
are 8,064 bytes in an 8,192-byte non-OBS allocation and 14,240 bytes in a 16,384-byte
OBS allocation. No allocation or mapping sizes are expanded at stage 2; the later
stage 3 integration does expand these mappings (see
[stage 3](KERNEL_PATCH_STAGE3.md)). Publication holds
the service gate unavailable while copying and reading back the new state, then
publishes the ready gate with a verified write. It writes only the new shared
tail and its gate. The public resident snapshot does not include this tail or
its credential.

[stage2.h](../residents/patch/stage2.h) serializes queries through a single
nonblocking CAS, with no spinning, allocation or network operations. It checks
pmap pointers, CR3 and the reviewed instruction bytes twice while holding the
service gate. Identity or mapping/signature failure permanently revokes this
publication; later matching metadata does not rearm it. This gate protects the
publication and its own query state. It does not freeze CPUs, protect arbitrary
kernel fields or make the two observations an atomic kernel snapshot.

## SDK observation and saved evidence

The client first checks its SDK-observed firmware/model/base layout, then uses
two distinct nonzero random challenges and the independently compiled build pin.
Both authenticated exchanges must return the same full identity/session/generation,
exact inspection-only capability and matching environment. Busy, malformed,
refused, changed or old-resident fallthrough responses stop the observation.
The calls use the existing intercepted register prefix, including R8/R9 for
reply size/reserved, without relying on R10. There is no retry or auto-discovery.

The payload emits exactly one `KP_STAGE2_JSON=` record with PID, observation time,
SDK environment, client status and the two public request/reply records. Credentials
and authenticated envelopes are excluded. Save the whole sender log and verify
it against the build ID from the private manifest:

```sh
python3 host/kernel_patch.py stage2-decode \
  --log "$PATCH_SESSION/stage2.log" --build "$RESIDENT_BUILD_ID" \
  --output "$PATCH_SESSION/stage2-observation.json"
```

This command makes no connection. It requires exactly one observation, checks
both wire exchanges, challenges, independent build pin, full identity consistency
and SDK environment, and rejects mutation capability/history on this channel.
It retains failure evidence and input hashes. Exit 0 means a matching recorded
observation, 1 means a saved refusal/unverified observation, and 2 means malformed
or inconsistent input or an existing output. A saved match still has
`present_readiness_verified: false` and `whole_kernel_identity_verified: false`.
It is not authority to reuse an old session for a write.

## Validation boundary

Run without a console or SDK:

```sh
python3 -m unittest discover -s tests -p test_kernel_patch_stage2.py -v
make check
```

Tests execute the actual bootstrap helpers, authenticated bridge, syscall client
and SDK entry-point logic using simulated memory/caller IO. They cover private
source preparation, credential/config pins, fixed wire arguments, user-page and
huge-page checks, permission refusal, wrong credentials/build/environment,
publication/readback, overwrite refusal, revocation, two distinct challenges,
changed identity, lost/invalid replies and strict saved-log interpretation.

Still unvalidated: the full linked resident/installer, actual current console
identity and readiness, live syscall interception/copy behavior, SMP mapping
lifetime, hardware page access and resident coexistence. The [stage 3 owned-variable source adapter](KERNEL_PATCH_STAGE3.md) is now
implemented separately. Its live milestone remains gated on that hardware
evidence and a fresh identified session.

### Build evidence — 2026-10-20

Local `make check` passed all **148** Python tests and the C paging checks. The
stage 2 native bootstrap/bridge/client test also passed AddressSanitizer and
UndefinedBehaviorSanitizer. Its SDK entry-point test uses simulated kernel and
syscall IO, not a console.

The isolated gpubox directory `/tmp/ps5-stage2-iw5Wzf` used the standard staged
Payload SDK and LLVM **18.1.8**. Provider-free and configured client builds, the
actual exported resident bridge and patched dispatch, and the bootstrap fixture
all compiled without SDK warnings. `make kernel-patch-check process-debugger
kernel-offset check` also passed. All 148 host tests ran on gpubox, with four
optional Capstone decoder tests skipped there; stage 2 tests ran on both hosts.
Existing host RSP unused-variable warnings remain unrelated to these SDK targets.

The private overlay build pin is
`efc519b5379502b201da0e5dcd52de4c57a7a875bbae71c39fc223c132445263`.
This identifies reviewed source/config inputs, not a linked resident ELF.

| Artifact | SHA-256 |
| --- | --- |
| Configured private SDK client | `898afe838347ab793a15d88146c1f6cf2d63118e44310cf58c4a881c971c37f4` |
| Actual patched dispatch object | `96438605d623eae7d132bba40ed315354490537399e4e8e5b1348ea5428b3c26` |
| Bootstrap compile fixture object | `26b51e190a1b90a19648067f982a80d7f6602f3bb627ab875538e73492071c79` |
| Actual resident bridge object | `f03ef6c5fe1a28e1ce3139a7f135ef73be7afe7395c055aeed0b8ad20cca6097` |

Ignored private evidence under `captures/kernel-patch-stage2-20261020-*/` retains
commands, local/remote logs, source/artifact hashes and the configured SDK ELF.
Its credential-bearing ELF is mode 0600 inside a mode-0700 directory. The prepared
source overlay is under `out/kernel-patch-stage2-final/`; implementation inputs
were matched to the SDK build's source hashes. Keep a protected copy of session
configuration before using `make clean`, which removes `out/`.

No resident was installed and no ELF was sent to a console. These checks do not
establish a full resident link, a working hardware transport, a current console
session or permission to begin stage 3 writes.

## Complete resident build follow-up

See the [private build runbook](KERNEL_PATCH_BUILD.md) for a complete resident
link and actual installer translation-unit compile, including pinned submodule
inputs and strict ELF loader checks. Earlier object-check overlays must be
regenerated with `--link-inputs`; the generator and builder are identity inputs.
The SDK installer startup integration and final installer link remain open, as
do all hardware checks listed above. The prior dated build evidence is retained
for its exact historical artifacts.
