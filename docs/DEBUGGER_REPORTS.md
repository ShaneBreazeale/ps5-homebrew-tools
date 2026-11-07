# Saved stop reports, bulk reads and offline analysis

These tools inspect an already attached, stopped **usermode** target. They use
the [target API](DEBUGGER_BACKEND.md) through the existing GDB connection and
save raw evidence for offline wildcard searches and x86-64 cross-references.
They do not establish console readiness, attach another PID, resume execution,
write target memory or create a second debugger connection. Follow the
[session contract](DEBUGGER_AGENTS.md) and [recovery note](DEBUGGER_RECOVERY.md).
The new paths are host-tested/SDK-built and have no console validation.

## Capture the current stop

Use a Python-enabled GDB with `RemoteTargetConnection.send_packet`, x86-64
support and preferably the FreeBSD OS ABI handler. Source the compatibility
profile and connect/attach through the existing authorized CLI workflow first.
Load the command from an absolute checkout path:

```gdb
source /ABSOLUTE/ps5-homebrew-tools/host/gdb_debugger.py
ps5-report /ABSOLUTE/SESSION/stop-001.json
```

Sourcing the file registers `ps5-report`; it sends no packets. Running the
command uses `selected_inferior().connection.send_packet` on that same connection.
It checks the server capabilities, expected numeric PID, stopped state and a
nonzero stop serial. It never falls back to opening its own socket or a legacy
server without these checks. No automatic stop hook is installed.

The report contains:

- Server source/LLVM fingerprint, firmware, server PID and capability reply.
- Native stop event, provider stop serial, poison flags and selected/resume LWPs.
- Available process name/start/path/app/title metadata and map list; explicit
  unsupported errors are retained when discovery is unavailable.
- GP registers for the selected LWP first and up to 255 other enumerated LWPs.
- Raw bytes starting at selected RSP (default 4 KiB) and RIP (default 128 bytes),
  any explicitly requested ranges, read errors and SHA-256 hashes of successful chunks.
- Optional module lookups, a labelled heuristic RBP-chain walk, raw frame records,
  the full command/reply transcript, limits and selection-restoration outcome.

For a larger bounded capture or matched local file identities:

```gdb
ps5-report /ABSOLUTE/SESSION/stop-002.json --stack-bytes 0x2000 --code-bytes 0x100 --frame-depth 16 --module test.sprx --range 0xVERIFIED_ADDRESS:0x10000 --server-elf /ABSOLUTE/process-debugger.elf --target-elf /ABSOLUTE/target.elf
```

Replace `0xVERIFIED_ADDRESS` before using the example. Local file hashes record
what the operator supplied, with `match_verified:false`; a basename, local hash
or server source fingerprint does not prove target ELF identity. The output is
created exclusively before target inspection; an existing file is never replaced.
Some invalid plans can leave an empty reserved file, and partial captures retain
their successful bytes and transcript. Choose a fresh output name for another
intentional capture. There is no automatic retry.

`status:complete` means the requested capture operations completed, all requested
threads fit, and no requested memory chunk failed. `status:partial` preserves
errors or omitted data. `consistency:same_observed_stop` means PID/stop serial
and stopped state matched at the start and end; `changed` or `unknown` must not
be treated as a coherent stop. Shared mappings can still change while the process
is stopped, so every report has `memory_atomic:false`. Saved bytes are the
debugger's logical user-memory view: existing software-breakpoint shadows are
applied, as identified by `memory_view`; they are not a physical INT3 dump. A transcript is private
capture data; do not send it to an external documentation/indexing service.

Register inspection changes the server's selected LWP temporarily. The collector
restores its original selection even after a local request/time budget expires.
After a transport failure it sends no further packets and records restoration as
unknown. The command does not detach: the operator retains the existing debugging
session and must perform the usual explicit cleanup.

Default memory budget is 1 MiB, configurable up to 16 MiB. Stack bytes are capped
at 64 KiB, code bytes at 4 KiB, frame depth at 64, requested regions/modules at
64 each, and threads at 256. There are at most 32,768 normal requests. Time checks
occur between packets (default 30 seconds, at most 300); an in-flight request is
also bounded by GDB's remote timeout. One final selection-restoration packet may
follow a local budget expiration. These limits do not cancel or resume a target.

### Frame-chain interpretation

The walk stores `method:rbp_chain`, `heuristic:true`, `unwind_verified:false` and
an explicit limitation that frame pointers can be omitted. It records raw
16-byte frame records in addition to the independent raw stack window. It stops
at zero, cycles, nonincreasing/unaligned/out-of-range pointers, unreadable records
or the depth/byte budget. Candidate return addresses are not proven callers.
A register value that looks like a valid RBP is not unwind metadata. Use matching
symbols/unwind information independently when available; raw bytes survive even
when this heuristic cannot produce a useful chain. Use `--frame-depth 0` to omit it.

## Multiple-range reads

`target_ops.read_memory_ranges` and its shared checked helper support 1–16 ranges
and at most 1,024 requested bytes in total. Envelope validation happens before
any read. Each successful range returns its exact bytes; a failed range returns
negative native errno, length zero, and a zeroed output slice. Later ranges are
still attempted. Software-breakpoint shadow reads retain their existing behavior.
The operation neither resumes nor writes and is not atomic against outside writers.

On the same GDB connection:

```gdb
maintenance packet qPS5:readv:ADDRESS,LENGTH;ADDRESS,LENGTH
maintenance packet qPS5:state
```

Addresses/lengths/indexes/errors are hex on the wire. Replace placeholders before
use. `qPS5:readv` returns `count:N;0:ERR,LENGTH,HEX;1:ERR,LENGTH,HEX;...`, where
ERR zero means success. Global malformed-envelope/stopped-state errors use normal
`Ehh` replies. Kernel/non-user ranges produce per-entry EFAULT. `max_ranges:10`
in capabilities is hexadecimal 16. Capability bits `200` and `400` identify the
multiple-range and stop-serial interfaces. The stop serial changes at each new
native stop across attach/detach in one provider lifetime; zero means no current
stop. Correlate it with server identity, not with a historical server instance.

The report collector splits larger captures into these packets and keeps per-chunk
faults, rather than filling missing memory with invented bytes.

## Wildcard searches

Report capture and wildcard analysis use only Python's standard library. Analysis
makes no connection and does not change execution:

```sh
python3 host/debugger_analyze.py search captures/stop-001.json \
  --role requested --pattern '48 8B ?? A? ?F' --max-results 100 \
  --output captures/search-001.json
```

Patterns contain 1–256 space-separated byte tokens. `??` or `?` matches any byte;
`A?` and `?F` match one fixed nibble. Matches can overlap and cross adjacent
successful chunks, but never cross a missing/unreadable gap. Conflicting overlapping
observations fail rather than choosing a value silently. Use `--role` or
`--start ADDRESS --length LENGTH` to select the intended captured observations.
Results include addresses and available mapping names/object offsets, not guessed
symbol slides. Truncated map names remain labelled. A complete search covers
only the selected captured successful bytes, not the target's entire address space.

To capture a search region through the same live GDB session, use `ps5-report`
with `--stack-bytes 0 --code-bytes 0 --frame-depth 0 --range ADDRESS:LENGTH`, then
run the offline search. Increase `--max-bytes` explicitly if needed. This retains
the evidence behind each search rather than scanning unsaved live memory.

## Cross-references

Install the optional tested decoder in a host environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r host/requirements-debugger.txt
.venv/bin/python host/debugger_analyze.py xrefs captures/stop-001.json \
  --role code --target 0xVERIFIED_RUNTIME_ADDRESS --output captures/xrefs-001.json
```

Replace the placeholder address. Capstone is pinned to `5.0.7`; missing or different
versions produce an explicit error. Reports/searches remain usable without it.
For raw code bytes instead of a report, both operations accept `--binary --base
ADDRESS`; the base and instruction boundaries must come from reviewed evidence.

Cross-reference analysis decodes x86-64 instructions from each supplied boundary.
It resolves RIP-relative operands and direct call/branch targets. An indirect
RIP-relative call references a **pointer slot**, not the eventual callee; register
indirect targets remain unresolved. Segment-relative addresses retain their
unresolved segment dependency. Arbitrary integer immediates are not interpreted
as pointers. No remote function evaluation or speculative register execution occurs.

This is linear decoding, not control-flow discovery or proof that bytes are
executed code. Decoding stops at an invalid/truncated instruction and records the
undecoded remainder; it never silently slides one byte to find another instruction.
Specify code beginning at a known instruction, such as the captured RIP. Offline
analysis can include data or incomplete captures; the result retains the source
consistency label and incomplete coverage instead of claiming all references.

Both analyses cap input memory at 16 MiB and results at 1,000 by default (maximum
100,000). Cross-references default to 100,000 instructions (maximum 1,000,000),
with C decoder batches of at most 256 instructions. The default analysis deadline
is five seconds, configurable up to 300. Limit hits return `complete:false` and
an explicit reason; a result limit does not prove more matches exist. Stop-report
JSON input is capped at 128 MiB, accounting for raw bytes plus the wire transcript.
Output files are exclusive and retain the input SHA-256, selected ranges and
successful-byte coverage. These tools write analysis results, not target patches.

## Verification

`make check` runs actual RSP/fake-target capture tests, the multiple-range C
failure/zeroing tests, ordinary provider regressions, and offline search tests.
Cross-reference tests run when the pinned optional decoder is installed; use
`make check-debugger-analysis` to require it and prevent a skipped decoder check.
The standalone `tests/gdb_stop_report_smoke.py --gdb PATH --evidence NEW_DIRECTORY`
checks GDB against a loopback-only fake target, including the Python command,
saved stack, stop identity and selection restoration. It makes no PS5 connection.
The ordinary `make process-debugger` target checks the production SDK build.
None of these checks validates console runtime, maps/XSAVE availability or game
attachment. Keep the exact source/ELF hashes with the test evidence.

API references: [GDB connection packets](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Connections-In-Python.html),
[target descriptions](https://sourceware.org/gdb/current/onlinedocs/gdb.html/i386-Features.html),
and [Capstone Python detail mode](https://www.capstone-engine.org/lang_python.html).

The current host integration check also passed with GDB 15.1 configured for
`x86_64-unknown-freebsd`, requiring acceptance of the target description. Ubuntu
GDB builds without that OS ABI handler produced fallback warnings; they are not
evidence that the FreeBSD description is invalid or that console integration
has passed. The 560-byte layout remains unchanged on the wire.
