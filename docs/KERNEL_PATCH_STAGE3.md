# Stage 3: resident-owned test cell

Stage 3 now has a concrete owned-cell adapter, authenticated dispatch, installer
bootstrap source, SDK exercise/recovery clients and saved-log validation. The
exercise changes one dedicated eight-byte resident cell, verifies the replacement,
restores its original bytes and verifies restoration. Host tests and LLVM 18
compilation are evidence for this implementation; the live milestone remains
pending SDK installer integration/link, stage 2 hardware validation and a current console
session. No resident has been installed and no console write has been performed.

Read the [plan](KERNEL_PATCH_TOOLKIT_PLAN.md), [stage 2 runbook](KERNEL_PATCH_STAGE2.md)
and [dated recovery facts](DEBUGGER_RECOVERY.md) first. Existing homebrew
research authorization covers this host-side implementation work only; it does
not by itself establish authorization or readiness for any live session. Current
host, firmware/model, loader state, resident/ELF identities and cleanup
conditions still need to be established before deployment; historical addresses
and readiness logs are stale. As of the 2026-10-18 operator report no console
session had been established after run 007; see the dated
[recovery note](DEBUGGER_RECOVERY.md) for the current target state.

## Owned state and transaction

[stage3.h](../residents/patch/stage3.h) uses the portable transaction engine with
one exact `test_data` policy. Its identity advertises inspection and owned-test-data
capabilities (`3`). The original stage 2 query remains inspection-only (`1`), with
its existing ABI and no fabricated command history.

| Field | Fixed stage 3 policy |
| --- | --- |
| Target | `kp_stage3_store.value`, aligned eight-byte cell in the resident's shared allocation |
| Anchor / offset | The cell's kernel alias as `resident_base`, offset zero |
| Original bytes | `4b50544553543100` |
| Replacement bytes | `4b50544553543200` |
| Operation / sequence | `EXERCISE` / `1` |
| Session / generation / build | Exact newly installed publication identity |
| Policy image identifier | The independently pinned resident source/config build identity, identifying this compiled test-data policy |

The adapter checks the full command against this policy before dispatch. It
accepts no other address, size, byte pattern, operation or sequence. The first
exercise consumes the session's sole transaction. An exact replay returns the
cached outcome without invoking the writer. The SDK client never retries a
mutation and stops before writing if it observes any prior history.

All stage 2 and stage 3 service calls share the publication's nonblocking CAS
gate. An additional owned-cell lease spans preimage checks, journal preparation,
write/readback and restoration. The cell uses aligned lock-free 64-bit atomics.
Its lifetime is the resident shared allocation; no other production path uses
it. This ownership supplies synchronization for this particular variable.

The adapter saves PREPARE, OUTCOME and COMPLETE request/result slots in resident
RAM. The engine caches its final request/result before releasing the service gate
and before copying a reply to the caller. A failed reply copy leaves that history
available through a fresh read-only query. This journal survives client loss
while the resident remains alive; it is **not power-loss-persistent storage**.
The completion journal slot is the core's pre-acknowledgement record, so its
snapshot precedes the returned result's `complete_saved` flag.

An identity change after writing, failed restoration or poisoned engine retains
quarantine and blocks further mutation. Diagnostic queries preserve the cached
outcome, including unknown cleanup. There is no rearm or state reset command.
A cached restored outcome describes the recorded transaction, not a new write or
a fresh readback of the cell at the query timestamp.

The engine's adapter pointers are bound only while the shared gate is held and
cleared before release. Each CPU has its own uelf code/stack addresses; those
addresses must not be retained in shared state between calls.

## Private source preparation

The existing generator supports an explicit stage selection, using the same
reviewed kstuff-lite commit `47da23b70685651a475d20247a3c4f2cac433eb4`:

```sh
python3 tooling/prepare_kernel_patch_stage2.py --stage 3 \
  --source /ABSOLUTE/PATH/TO/kstuff-lite \
  --output out/stage3-private
python3 tooling/verify_kernel_patch_stage2.py --stage 3 \
  --overlay out/stage3-private
```

The source checkout is read-only. Preparation exports selected committed files
into a new mode-0700 directory, applies fixed integration markers, and generates
matching mode-0600 resident/client credentials. Existing outputs are refused.
Changing integration source requires a fresh overlay. Stage 2 and stage 3
configuration are distinguished by the manifest and build identity; the build
verifier rejects using an overlay for the wrong stage.

The integration appends the 5,464-byte stage 3 store after the 176-byte stage 2
tail, preserving all original field offsets. The non-OBS layout is 13,528 bytes
inside a 16,384-byte shared mapping; OBS is 19,704 bytes inside 24,576 bytes.
This mapping expansion is applied by `patch_stage3` in
[tooling/prepare_kernel_patch_stage2.py](../tooling/prepare_kernel_patch_stage2.py),
which raises the overlay's non-OBS `SHARED_AREA_SIZE` from 8,192 to 16,384 and
the OBS size from 16,384 to 24,576. The stage-2-only overlay leaves the pinned
kstuff allocations unexpanded.

The existing installer allocation is 131,072 bytes with an aligned 65,536-byte
comparison table. Its existing free-side selection contains either enlarged
mapping; the existing mapper walks each backing page. The allocation itself is
unchanged. Both expanded mappings remain below the existing two-megabyte uelf
window. The public resident snapshot continues to exclude the appended tail and
credentials.

[stage3_loader.h](../residents/patch/stage3_loader.h) first refuses any nonzero
stage 2 or stage 3 destination. It initializes and reads back the new cell/store
in bounded chunks, then calls the original stage 2 publication helper last.
The authenticated service becomes available only after that helper's profile,
CPU completion, identity, mapping metadata and readback checks. This source is
part of new-installation preparation; it is not an upgrade command for a running
stage 2 resident. Existing installer setup remains outside this adapter.

## SDK builds and read-only recovery

Use the normal [Payload SDK and LLVM 18](BUILDING.md). These optional clients
are excluded from `all` and public bundles because configured ELFs contain a
bearer credential:

```sh
# Provider-free clients report provider_unavailable and issue no resident call.
make kernel-patch-stage3 kernel-patch-stage3-query

# The configured exercise client can change only the dedicated cell.
make kernel-patch-stage3 \
  KERNEL_PATCH_STAGE3_CONFIG="$PWD/out/stage3-private/client-config"

# This separate client issues one read-only query, including cached history.
make kernel-patch-stage3-query \
  KERNEL_PATCH_STAGE3_CONFIG="$PWD/out/stage3-private/client-config"

# Compile actual resident bridge/dispatch plus bootstrap fixture; objects only.
make kernel-patch-stage3-check \
  KERNEL_PATCH_STAGE3_OVERLAY="$PWD/out/stage3-private"
```

Outputs are `out/kernel-patch-stage3.elf` and
`out/kernel-patch-stage3-query.elf`. Both clients rebuild on each invocation to
avoid reusing a credential-bearing ELF after switching configurations. Keep
private configurations and linked artifacts outside Git and public releases.

[stage3_bridge.h](../residents/patch/stage3_bridge.h) uses query selector
`0x4b500002` (104-byte authenticated request, 720-byte reply) and exercise selector
`0x4b500003` (360-byte authenticated command, 248-byte result). Both use the same
reviewed intercepted `getppid` register prefix as stage 2. Exact lengths,
canonical nonoverlapping user buffers, reserved values, permissions, credential
and copied request contents are checked before service dispatch. The credential
is wiped from temporary envelopes and excluded from evidence.

The concrete adapter retains stage 2's page permission audits and copy helpers.
These checks are **not OS page pins or SMP fault containment**. Caller mappings,
actual physical copies, exception behavior and resident coexistence remain live
validation requirements. Permission checks are repeated before copying replies;
an interrupted or failed transfer does not authorize a repeat mutation.

The exercise client checks the SDK environment and makes two fresh challenged
read-only queries with identical full identities and no history. It then issues
one exercise and a third fresh read-only query. Success requires the exact fixed
request and a cached result with verified before/replacement/restored bytes,
known cleanup, successful lease completion and all journal flags. A lost direct
reply can be recovered from that third query without replay. If recovery itself
fails, save the unknown result and use the separate read-only client later.

The read-only client reports `query_checked` for an unused session and
`cached_result` for matching cached history. Poisoned/refused replies still
retain diagnostic bytes in the log. A successful query exit establishes a
matching recorded exchange; check the cached operation status and cleanup state
separately before calling restoration successful.

## Saved evidence and validation

Both clients emit exactly one `KP_STAGE3_JSON=` line with PID/time, SDK environment,
public requests/replies and command/result transport flags. No bearer envelope
is logged. Decode the saved sender log offline:

```sh
python3 host/kernel_patch.py stage3-decode \
  --log "$PATCH_SESSION/stage3.log" --build "$RESIDENT_BUILD_ID" \
  --output "$PATCH_SESSION/stage3-observation.json"
```

The decoder independently checks build pins, challenge uniqueness for the exercise,
full identity/environment, the exact compiled test-data policy and result bytes,
journal/cleanup flags and direct-versus-cached consistency. It preserves failure
records and their raw public evidence. Duplicate JSON keys/records, forged success,
truncated exchanges and existing output files are refused. Exit 0 means a verified
recorded restoration or valid read-only query; 1 means preserved unverified/failure
evidence; 2 means malformed/inconsistent input. Saved evidence always retains
`present_readiness_verified: false` and `whole_kernel_identity_verified: false`.

Run host checks without a console:

```sh
python3 -m unittest discover -s tests -p test_kernel_patch_stage3.py -v
make check
```

The tests exercise the real owned-cell callbacks, journals, bootstrap, bridge,
raw-syscall client argument path and SDK entry points with simulated IO. Cases
include 16 concurrent callers, wrong credentials/build/session/policy, malformed
transport, overwrite refusal, lost replies, read-only recovery, existing history,
exact replay, identity loss after writing, sticky quarantine and forged saved
restoration. Sanitizers cover the native integration test. These cannot establish
real hardware transport, mapping lifetime, a full resident link or console cleanup.

### Build evidence — 2026-10-20

Local `make check` passed all **155** Python tests and the C paging checks. The
native stage 3 integration passed AddressSanitizer and UndefinedBehaviorSanitizer.
The seven stage 3 tests also passed on gpubox; all 155 tests ran there with four
optional Capstone decoder tests skipped. Existing host RSP unused-variable
warnings are unrelated to the new SDK targets.

The isolated build `/tmp/ps5-stage3-final-8feIWE` used the standard staged Payload
SDK and LLVM **18.1.8**, without overriding the version gate. Provider-free and
configured exercise/query clients, actual resident bridge and dispatch in both
non-OBS and OBS layouts, and the bootstrap fixture compiled without SDK warnings.
`kernel-patch-check`, `process-debugger` and `kernel-offset` SDK builds also passed.

The private overlay at `out/kernel-patch-stage3-final/` has source/config identity
`80ad062e0253863fa47001825d277133f663495fbfb96ef6931e282f8ad14fff`.
This is not a final linked resident ELF hash.

| Artifact | SHA-256 |
| --- | --- |
| Configured exercise SDK client | `d64cd051085a176c155269d7518804e2e099ae1dc351b3989749df1c5655206d` |
| Configured read-only SDK client | `70508bf19f42374304b637adc791b37bd3d04b77226d5ec8e513c5db01940626` |
| Actual resident bridge, non-OBS | `182c099125c1a0a6e43d22a9aae22b035d96ca06078e59255a8733720c76b044` |
| Actual resident bridge, OBS | `3df95a9a8b9ae59c9d109aae278b07f5b0e2808b1b628c3980a327f07cacfe9f` |
| Actual dispatch, non-OBS | `f8dc9f51ff1aeed5260eeb450a1856fb709b1f539dc6a93c9052539a3fae4809` |
| Actual dispatch, OBS | `7737c6b5e3845ea049252794e1812b9593841dc900c1e7b715ca588dc1c4afa0` |
| Bootstrap compile fixture | `f0ce39ae70b2b03d9bbce3629a7c1d981208567d5b6173779a73c2ea02ede06d` |

Ignored `captures/kernel-patch-stage3-20261020-blyc8zze/` retains commands,
local/remote logs, matched implementation-source hashes, overlay manifest and
private artifacts. Credential-bearing ELFs are mode 0600 inside that mode-0700
directory. These compiled objects are not a linked resident or installer. No
payload was sent to a console, and no live restoration or current readiness is
claimed.

## Complete resident build follow-up

The [private build runbook](KERNEL_PATCH_BUILD.md) adds `--link-inputs` and
`make kernel-patch-resident`. It links both resident images, audits the pinned
loader contract and compiles the actual installer with those images embedded.
The source overlay also renames the installer's private string comparator to
avoid the toolkit header's external `strcmp` declaration. This closes an actual
translation-unit failure missed by the earlier bootstrap fixture. SDK installer
startup integration/link and console validation remain unfinished. Historical
object-build hashes above retain their original validation boundary.
