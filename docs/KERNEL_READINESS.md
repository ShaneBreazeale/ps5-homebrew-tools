# Kernel inspection readiness and legacy fallback

The kernel-offset backend now prefers a versioned challenge/reply interface.
The normal payload requires a deliberately linked provider. No current kstuff
resident implements this interface merely because the client headers exist.
The [kernel backend guide](KERNEL_DEBUGGER.md) describes the separate byte
inspection operation; neither path installs traps or permits execution control.

## Build modes

The standard SDK / LLVM 18 target remains:

```sh
make kernel-offset
```

With no provider linked, this build reports `readiness_provider_unavailable`
and performs no instruction read. It does not issue a guessed resident syscall,
scan kernel memory for a structure, or manufacture a ready record.

An integrator with an implemented, reviewed resident transport supplies a C
adapter that exports `const struct ko_provider ko_readiness_provider`:

```sh
# Use a fresh build directory when changing flags or provider sources.
make kernel-offset KERNEL_OFFSET_PROVIDER=/path/to/reviewed-provider.c
```

The provider descriptor in [readiness.h](../payloads/kernel-offset/readiness.h)
contains an exchange function, context and a **pinned** 32-byte producer build
SHA-256. The pinned value comes from the reviewed build configuration; it must
not be copied from the response being validated. A source path automatically
sets `KERNEL_OFFSET_HAS_PROVIDER=1`. Missing symbols fail linking.

For the separately established historical Pro 13.60 resume-instrumentation
profile, an explicit compatibility build enables fallback:

```sh
make kernel-offset CPPFLAGS=-DKERNEL_OFFSET_LEGACY_FALLBACK=1
```

That choice asserts operator-established compatibility with
`resume-13.60-pro-v1`; the cookie cannot identify the resident's build. It does
not make an arbitrary kstuff session compatible. The default is zero. A provider
may be linked along with the flag, but fallback still requires an explicit
`KO_QUERY_UNAVAILABLE` result. The absence of a linked provider counts as
unavailable only when this legacy mode was explicitly selected.

| Provider result | Outcome |
| --- | --- |
| Valid ready response | Inspect under the handshake path |
| Explicitly unavailable, legacy flag off | Refuse |
| Explicitly unavailable, known legacy mode selected | Check cookie, hook state, mappings and site bytes |
| Available but malformed, wrong ABI/build/environment or stale | Refuse, without fallback |
| Initializing, failed, incomplete CPUs or active hooks | Refuse, without fallback |
| Error, timeout, unknown return or failure to obtain a challenge | Refuse, without fallback |
| Provider disappears or changes during inspection | Discard observed bytes; refuse, without fallback |

An adapter must not translate a timeout, malformed response or unfamiliar ABI
into `KO_QUERY_UNAVAILABLE`. That result is reserved for established absence of
the interface on a recognized legacy deployment. Its exchange must be bounded
by the transport and return one synchronized snapshot. The client cannot safely
preempt an arbitrary adapter function that hangs. Review the transport itself
before linking it.

## Version 1 provider ABI

The fixed-width request is 48 bytes, the reply 160 bytes; compile-time assertions
check their layouts. The initial transport contract is native little-endian
x86-64. A transport on another architecture must serialize fields explicitly.
There is no format magic used as a readiness decision.

The request includes ABI version/size, a random 128-bit challenge from
`/dev/urandom`, and the SDK-observed firmware, SoC and text/data bases. A second,
distinct nonzero challenge is used after the instruction observation. Challenge
bytes are opaque; JSON prints them in memory order.

The response must contain:

- Version 1 and exact size; all reserved bytes zero.
- The exact challenge and a nonzero, freshly generated producer session ID.
- The pinned producer build SHA-256 and a nonzero generation counter.
- Exact observed firmware/SoC, SDK bases and the independently read pmap CR3.
- State READY, no active hooks, and only the inspection capability (`1`).
- A nonzero expected CPU mask within bits 0–15, with exactly those CPUs complete.

The expected CPU set must come from the producer's real initialization scope,
not an invented mask chosen to make completion pass. Both responses must describe
the same session, build, generation, environment and capabilities. Reserved bits,
additional capabilities and unknown ABI versions are refused in this version.
A challenge establishes freshness to a trusted provider; it is not a signature
or authentication against a malicious resident. Trust requires the deliberately
selected adapter and producer build.

The backend independently validates its pmap and walks the target page tables.
After reading at most seven instruction bytes, it rechecks the pmap, page mapping
and readiness. A changed or invalid final state discards the bytes. These checks
reduce stale-state mistakes; they do not freeze CPUs or make the observation
atomic with a concurrent mapping change. Protected/missing/unreadable mappings
are refused under both modes. A matching cookie cannot override those gates.

## Producer lifecycle and completion cookie

[readiness_producer.h](../payloads/kernel-offset/readiness_producer.h) implements
the producer state helpers. They are portable integration code, **not an installed
resident or a new kstuff command**. The unversioned research producer was not
modified or deployed as part of this change.

The resident must hold its appropriate lock across each lifecycle operation and
reply snapshot. The adapter must expose that synchronized exchange; raw copying
of a mutable structure is insufficient. No helper acquires kernel locks or
changes CPU interrupt/preemption state for the integrator.

1. Start with a zero-initialized producer. Supply actual environment/build identity,
   expected CPU mask and a fresh random session ID to `ko_producer_begin`.
   If maintaining a legacy marker, supply its writer: the helper clears it before
   initialization can start. Reusing the same session ID is rejected.
2. Perform the real per-CPU prerequisites. Call `ko_producer_cpu_complete` only
   after each expected CPU's work succeeds. Unexpected/duplicate CPUs are rejected.
3. Complete actual cleanup, then call `ko_producer_finish` with observed active
   hook count. Missing CPUs or active hooks leave it unready. Only after these
   prerequisites does it publish the optional completion cookie and READY state.
   A cookie-write failure leaves the primary interface FAILED.
4. Before changing initialized state, call `ko_producer_invalidate` under the same
   lock. It revokes capabilities and clears the optional legacy marker. Failure
   to clear that marker must abort the intended state change. A new initialization
   session needs a new random ID. Generation wrap is refused.
5. Route queries through `ko_producer_exchange` under that lock. It returns
   initializing/failed records as **available records**, never as unavailable.

The legacy writer is supplied by the producer integration, not the inspection
payload. It must perform the appropriate atomic marker write and report failure.
The helpers neither install a hook nor set page protections, and they do not
claim that a CPU operation happened merely because a completion helper was called.

Legacy consumers recheck the historical cookie and hook state before and after
inspection. If a provider explicitly reported unavailable, that result must
also remain unavailable at the final check; an appearing interface or new error
discards the observation. This cannot establish freshness: a cookie can remain stale even
when both reads agree. Legacy fallback therefore grants no session identity,
versioned capability, trap ownership, stop, step or resume guarantee.

## JSON and host handling

New payload observations use schema **2**, retaining `KOFFSET_JSON=` framing.
The `readiness` object records source (`versioned_handshake`, `legacy_cookie`,
or `none`), fallback reason, legacy profile, ABI/size, state/hooks/CR3, build ID,
session ID, generation, capabilities, CPU masks and both challenges. Legacy
records leave all handshake identity/capability fields zero. Failures cannot be
accepted by the planner just because an evidence object is present.

The host planner validates the corresponding evidence before relocation, and
preserves it in `runtime_observation.readiness`, adding `fresh_handshake`.
Historical schema-1 probes are still accepted as dated observations, explicitly
labelled `legacy_schema1_unreported` with `fresh_handshake=false`. Neither label
means a saved log is presently fresh. The host does not contact the console or
authenticate the log, and whole-running-kernel identity remains unverified.

Additional refusal statuses are `readiness_provider_unavailable`,
`readiness_query_error`, `invalid_readiness`, `readiness_not_ready`,
`stale_readiness_reply`, `readiness_changed` and `challenge_unavailable`.

## Draft resident integration

The integration sources under `residents/readiness/` are a draft,
separate from the standard provider-free SDK target. Their loader and bounded
service core now have a native host simulation in `tests/test_readiness_resident.c`,
run by `make check`. It drives 16 CPU completions and 56 live checks, including
packed TSS IST fields at offsets `0x34`, `0x3c` and `0x54`, then exercises
publication, permission refusal, torn-publication refusal and sticky revocation.
Live-check values are copied as bytes and may be unaligned; publication sequence
words still require eight-byte alignment. These tests do not exercise the syscall
bridge, generated build identity, installer integration or resident execution.
The draft does not establish a working transport or console readiness.

## Verification boundary

Host tests execute the real C consumer, producer helpers and SDK entry point
with simulated kernel/provider access, then validate its actual JSON with the
host parser. They cover downgrade refusal despite a valid cookie, stale challenges,
wrong versions/builds/bases, incomplete CPUs, hook activity, session/generation
changes, provider disappearance, publication ordering and permission failures.
The standard SDK default and explicit legacy modes are built separately on
gpubox. These checks do not validate a live resident transport, kernel locking,
console entropy device, exception handling or coexistence. No console was sent
a payload for this change.

### Build evidence — 2026-10-18

Final build: gpubox `/tmp/ps5-kernel-readiness-final-Pst7Jk`, staged public Payload
SDK and LLVM **18.1.8**, standard `make kernel-offset`. Each mode was rebuilt
with no cached ELF. All three modes compiled without warnings. `make check`
passed **54** Python tests and the C paging checks on gpubox and locally.
Documentation links/anchors, fences and shell/JSON examples passed for 24 files.

| Artifact / mode | Bytes | SHA-256 |
| --- | --- | --- |
| Default, provider required | 119,680 | `a93b9211876d3d29539cecc4f21f8a992c20b5a9db094bc7c44acfb0ab9a7b17` |
| Explicit legacy fallback | 122,680 | `55bffb8204cf09d956a8f8432da037f989150a546ed436ec3a8c2095815a482f` |
| Uninitialized provider linkage fixture, test only | 127,152 | `ad3acd080b98654be3f771448d54b9aa5383c255e1a471cb323a2bbc35f80bbd` |

The local ignored directory `captures/kernel-readiness-20261018/` preserves
the first two ELFs, full build/test log and source/artifact hash manifest. The
fixture ELF remains only in the isolated remote build and cannot grant readiness.
No ELF was sent to the console. These source changes have not been committed,
pushed or indexed by Context7. A real resident transport still needs integration
and separate runtime validation.
