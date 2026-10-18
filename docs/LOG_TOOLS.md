# Decode and compare diagnostic captures

The host tools read existing text captures locally and emit JSON on standard
output. They use Python 3 and its standard library. They do not connect to a
console or modify input files.

## Select a resident event profile

The resident-snapshot payload retains its historical `debug-reader` and
`log-word[sequence]=0x...` output format. A marker alone does not establish an
event's layout: historical resident experiments reused markers with different
fields. Select the schema matching the **producer**, not the snapshot reader.

| Profile under `profiles/events/` | Historical producer | Decoded events |
| --- | --- | --- |
| `read-entry-v1.json` | rdlog | `PPRRD001`: read kind/fd, count, offset |
| `exec-unmount-v1.json` | xin | `PPREXV01`: executable path; `PPRUMX01`: thread, pinned flag, scope kind |
| `scope-state-v1.json` | xslot | xin events plus `PPRSCP01`: occupied slots, packed kinds, first PPR thread, state |
| `app-info-v1.json` | xapp | xin events plus `PPRWRF01`: copy status, appinfo pointer, action |
| `raw-words-v1.json` | Any or unidentified | No semantic decoding; preserve all words |

These are partial schemas derived from the
[archived patches](../residents/README.md), not a complete description of every
inherited baseline event. Each profile records its source archive. Historical
ELF identities are recorded in the resident catalogue; neither a filename nor
a matching marker verifies the binary's identity. Exact source for the xlog
variant has not been recovered here; use the raw profile for its captures.

`PPREKX01` remains unknown even with the xin/xslot/xapp profiles. Their patch
emits two payload words on failure and three on success under the same marker,
without an unambiguous discriminator. The decoder reports this ambiguity
instead of assigning fields.

## Decode a capture

Run from the repository root:

```sh
python3 host/decode_events.py captures/resident-after.log \
  --profile profiles/events/scope-state-v1.json \
  > captures/resident-after.json
```

Output contains the profile ID and an ordered `snapshots` array. Every snapshot
includes metrics, ring words, decoded records, process observations, original
lines with line numbers, and diagnostics. Each record has one of these states:

- `decoded`: the selected schema supplied the name and fields. Original words
  remain available; 64-bit words are also preserved as hexadecimal strings.
- `unknown`: an unrecognized word, ambiguous marker, or fragment whose event
  header may have been overwritten.
- `truncated`: a known marker lacks its required contiguous payload words.

The numeric fields are JSON integers. Consumers that cannot represent integers
above 2^53 exactly should use the original hexadecimal words.

The reader prints the ring **before** the `core` metrics for each snapshot.
The parser associates those records with that following metric group. Subsequent
ring/message output or another `core` line starts the next snapshot. Repeated
windows keep their original records and receive `repeated: true` only when the
sequence, status, and words match a prior record within the inferred epoch.
A truncated record that later becomes complete is a newly observed record.
Incomplete events are not joined across snapshot boundaries.

`ring_gaps` reports unavailable earlier words and non-contiguous sequences.
This describes missing evidence, not a count of lost events. In particular, a
16-word ring can begin halfway through an event. `errors` preserves malformed
ring lines and reported payload failures; the full original text also remains
in `lines`.

The executable-path interpretation uses little-endian bytes, matching the PS5
producer's memory copy. Read kinds 1–4 are read, readv, pread, and preadv; count
means bytes for read/pread and iovec count for readv/preadv. Offset is meaningful
for positioned reads. The rdlog patch can emit zero fields after failing to
copy arguments, so zeros alone do not prove an actual read of fd 0 and length 0.
App-info action 1 indicates an attempted write, not a verified write. Occupied
scope slots are in-flight wrappers, not a mounted-filesystem count.

## Compare two captures

```sh
python3 host/compare_captures.py captures/resident-before.log \
  captures/resident-after.log \
  --profile profiles/events/scope-state-v1.json \
  > captures/comparison.json
```

Use the raw profile for process-watch captures or an unidentified resident:

```sh
python3 host/compare_captures.py captures/process-before.log \
  captures/process-after.log \
  --profile profiles/events/raw-words-v1.json
```

The result provides:

- `final_metric_changes`: last-snapshot values in each file, including fields
  present in only one file. Cross-file values are never subtracted because a
  capture does not establish that both files came from the same resident session.
- `before` and `after`: per-snapshot metric changes, newly observed event/unknown
  records, process observations, gaps, diagnostics, and session/epoch boundaries.
- `process_identity_changes`: observed identities found only in one file, using
  PID, process start value, and command name. PID reuse becomes a distinct identity.
- `process_observation_changes`: exact observation lines unique to each capture,
  preserving birth/death/zombie records and application metadata. Different
  timestamps or sampled state can produce differences for the same identity.

Observed identities do not imply that a process was still alive at capture end.
Neither file is assumed to be a complete census or complete event history.

Within a capture, only the known cumulative `core.*` fields receive deltas,
and only between snapshots in the same inferred epoch. Other numeric values
include gauges, addresses and identifiers; they are reported as before/after
observations. A reader start, process baseline, decreasing core counter,
regressing ring sequence, or sequence reused with different data breaks
continuity. The resulting boundary is reported explicitly and suppresses
deltas/deduplication across it. Reordering or inconsistent captures can cause
the same symptoms as a reset. Resets that leave no observable discontinuity
cannot be identified from these logs alone.

The two input files must use the same selected event schema. Decode different
producer profiles separately. Retained unknown words are intentional evidence;
do not choose another schema simply to make more markers decode.

## Validation

```sh
python3 -m unittest discover -s tests -p 'test_log_*.py' -v
```

Synthetic tests cover overlapping windows, truncation, sequence gaps, ambiguous
markers, explicit sessions, resets, endianness, process identity reuse, and both
JSON commands. Historical captures can be checked locally without copying
console logs into the repository. Successful decoding verifies parser behavior,
not the correctness of the producer's instrumentation.
