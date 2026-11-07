# Host utilities

Run these commands with Python 3.9+ from the repository root. The scripts use
the standard library unless noted and support `--help`. The optional x86-64
cross-reference decoder uses pinned Capstone; the GDB command runs inside GDB.

## Send one payload

```sh
mkdir -p captures
python3 host/send_payload.py out/process-snapshot.elf \
  --host "$PS5_HOST" --log captures/process-snapshot-001.log
```

Set `PS5_HOST` to your console address before using the example. The script
itself reads the required `--host` argument, not that environment variable.

| Argument | Default | Meaning |
| --- | --- | --- |
| `elf` | Required positional path | ELF64 little-endian file with at least a complete header |
| `--host` | Required | Console address or hostname |
| `--port` | `9021` | Loader TCP port, from 1 to 65535 |
| `--log` | Required | New file in an existing directory; existing files are never overwritten |
| `--idle-timeout` | `60` | Positive finite seconds to wait for the next received data |

The connection timeout is eight seconds. The idle timeout resets as data arrives;
it is not a total run-time limit. The script checks the ELF prefix, reserves the
log, connects, sends once, and receives until EOF or an error. It does not install
the payload on console storage or retry the send.

| Sender exit code | Meaning |
| --- | --- |
| `0` | The remote connection reached EOF without a host transport error |
| `1` | File or socket error; any received bytes remain in the log |
| `2` | Argument/ELF validation error, or receive idle timeout; inspect the displayed message |

These are host exit codes. The ELF loader's stream does not provide the payload's
return value to this script. Check the payload's completion or error messages.

Only received bytes are stored in the log. The sender's `Sent ...` line and
local error messages appear in the terminal. A failed connection may leave an
empty reserved log; keep it and choose a new filename for another deliberate
attempt after establishing session state. A failed **connect** (before any ELF
bytes are written) pings once and records `session_health` in the sidecar; it
does not connect to the loader a second time. An idle timeout after a successful
send does not ping and is not `elfldr_dead`.

## Classify a console session

```sh
python3 host/session_health.py --host "$PS5_HOST"
python3 host/session_health.py --host "$PS5_HOST" --loader-result refused
python3 host/session_health.py --host "$PS5_HOST" --json --ping-result alive --loader-result open
```

This tool sends one ICMP ping. It never opens TCP port 9021. Loader
refused/open/timeout state comes from `--loader-result`, `--loader-error`, or
from `send_payload.py` after a connect failure. Use `--ping-result` when ping
was already observed. `--hdmi-two-beep` selects the display-sync class.

| Argument | Default | Meaning |
| --- | --- | --- |
| `--host` | Required | Console address or hostname |
| `--port` | `9021` | Loader port identity in the report; never contacted |
| `--loader-result` | `unknown` | `unknown`, `open`, `refused`, `timeout`, `unreachable`, `reset`, or `error` |
| `--loader-error` | unset | Failed-send OSError text; used only when `--loader-result` is `unknown` |
| `--ping-result` | unset | Skip ICMP and use `alive`, `dead`, `unresolved`, or `unknown` |
| `--hdmi-two-beep` | off | Operator saw HDMI black with two beeps |
| `--json` | off | Print the report as JSON |

| Classifier exit code | Meaning |
| --- | --- |
| `0` | `kernel_answers` or `loader_ready`; a send may proceed or already succeeded |
| `1` | Recovery class; do not send another ELF into this session |
| `2` | Argument error |

Classes and next actions are in [Troubleshooting](../docs/TROUBLESHOOTING.md#black-session-classes).

## Summarize a v2 capture

```sh
python3 host/summarize_threads.py captures/thread-probe-v2.log \
  > captures/thread-summary.json
```

The input must be a plain-text, completed v2 capture. Decompress a `.gz` capture
before passing it to the script. V1 logs and resident snapshot logs are different formats.

The parser checks contiguous raw chunks, process/thread record sizes, ownership,
TID consistency, the live layout-validation marker, completion, and the presence
of all three process/thread passes. Invalid or incomplete captures print an
`error:` line to stderr and exit with status 2. Shell redirection can still leave an
empty JSON file after such a failure; retain the raw input and terminal error.

| JSON field | Contents |
| --- | --- |
| `process_counts` | Number of captured process records per pass |
| `captured_thread_counts` | Counts grouped by pass and PID |
| `processes` | Decoded process records, grouped by pass |
| `threads` | Thread records, addresses, and candidate fields, grouped by pass |
| `app_title_candidates` | Candidate titles reconstructed from the observed app-info layout |
| `limits` | Research interpretation limits retained in the summary |

JSON object keys for pass numbers and PIDs are strings. Candidate fields remain
candidates; the summary is not a crash diagnosis. The current parser always
includes the historical ShellCore-cap note in `limits`; inspect actual thread
counts and raw `threads_end` records to assess your capture's truncation.

## Kernel offset planning

`kernel_offset.py --dump RAW --anchor exec --offset 0xcfc12` validates the
profile hash and resolves the investigation's shorthand to raw offset `0x38fc12`.
It makes no connection and emits no breakpoint command. With `--probe LOG`, it
can relocate from one validated, dated kernel-offset probe observation. See
[the kernel backend guide](../docs/KERNEL_DEBUGGER.md) for anchors, required
readiness/page gates, refusal statuses and unfinished execution control. Schema-2
reports preserve [handshake or legacy evidence](../docs/KERNEL_READINESS.md);
schema-1 observations are labelled as unreported legacy evidence.

## Stream until the connection dies

```sh
python3 host/stream_logger.py out/follower-live.elf \
  --host "$PS5_HOST" --log captures/follower-live-001.log
```

`stream_logger.py` sends one ELF and writes stdout until the loader
connection closes. It sets no idle timeout. Use it for `follower-live`
and `thread-probe-v3`. It refuses to overwrite `--log`. A failed connect
does not retry and does not classify the session; use `send_payload.py`
when you need the session-health sidecar.

## Other host tools

- [Durable checkpoints](../docs/DURABLE_CHECKPOINTS.md): `checkpoints.py listen` saves each app record before ACK; `ingest` saves raw resident trace/panic streams; `summary` rechecks evidence and identifies pending calls. No console deployment or physical panic driver.
- [Kernel execution codec](../docs/KERNEL_EXECUTION.md#polled-mailbox-and-offline-host-codec): encode/decode saved mailbox records; no network or live execution adapter.
- Session classifier: ping vs a real send; never probe 9021. See above.
- [Capture receiver](../docs/CAPTURE_TOOLS.md): receive and verify a kernel capture.
- [Log tools](../docs/LOG_TOOLS.md): decode and compare resident captures.
- [Analysis tools](../docs/ANALYSIS_TOOLS.md): audit offsets, patches, and binary dumps.
- [Bundle packaging](../docs/BUILDING.md): create a source-and-artifact archive.

The sender writes a `*.log.json` sidecar with payload/capture hashes, source
revision, timestamps, transport outcome, and optional operator-supplied firmware,
model, and resident profile. Keep this sidecar with the raw log.

## Debugger validation

`validate_debugger.py --host HOST --elf out/process-debugger.elf --report NEW.json`
exercises the process debugger with its own disposable child and preserves a
non-overwritten JSON transcript and payload hash. It requires a running debugger
(default port 1234) and currently fails at the known-unvalidated data watchpoint
check on retail 13.60. See [the CLI runbook](../docs/DEBUGGER.md), [agent guide](../docs/DEBUGGER_AGENTS.md), and [recovery note](../docs/DEBUGGER_RECOVERY.md).

## Debugger stop reports and offline analysis

[Stop-report guide](../docs/DEBUGGER_REPORTS.md) covers `host/gdb_debugger.py`
(`ps5-report` on the existing GDB connection), the transport-independent
`debugger_report.py` collector, and `debugger_analyze.py search` / `xrefs`.
Raw stack bytes and per-range errors are retained; RBP chains are explicitly
heuristic. Capture/search use the standard library. Cross-references require
`requirements-debugger.txt`. Offline analysis never opens a target connection.

## Offline kernel patch toolkit

`kernel_patch.py` validates hash-checked manifests, generates independently reviewed
resident policy headers, encodes saved requests and simulates the portable C
transaction service. Build its private-memory backend with `make kernel-patch-host`.
The [toolkit guide](../docs/KERNEL_PATCH_TOOLKIT.md) includes a synthetic example,
fault injection, evidence formats and the adapter contract. No command connects
to a console; saved identity inputs do not prove readiness. Live resident
integration and kernel code mutation remain unfinished.

`kernel_patch.py stage2-decode` validates exactly one saved `KP_STAGE2_JSON`
observation against an independently pinned build and checks both challenges,
identity consistency and the SDK environment. The [stage 2 guide](../docs/KERNEL_PATCH_STAGE2.md)
also covers private source preparation and client builds. Read-only integration
source and the concrete dispatch are now implemented; full resident and console
validation, write integration and code mutation remain unfinished.

`kernel_patch.py stage3-decode --log LOG --build BUILD --output NEW_JSON` checks
saved owned-cell exercise or read-only recovery evidence. It makes no connection.
See [stage 3](../docs/KERNEL_PATCH_STAGE3.md) for status and cleanup semantics.

## Kernel patch research campaign

`python3 host/kernel_patch_campaign.py --output /NEW/PATH/campaign.json` runs
the real portable core against 44,256 deterministic host transfer-fault cases.
It preserves compiler/source identity, commands, diagnostics and explicit failed
experiments. Existing output files are refused. See the
[experiment protocol](../docs/KERNEL_PATCH_EXPERIMENTS.md) for falsifiers,
sensitivity controls and the separate application baseline required to test a
kernel remedy. It uses no SDK or console connection.
