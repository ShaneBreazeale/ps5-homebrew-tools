# Host utilities

Run these commands with Python 3.9+ from the repository root. Both scripts use
the standard library and support `--help`.

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
attempt after establishing session state.

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

## Other host tools

- [Capture receiver](../docs/CAPTURE_TOOLS.md): receive and verify a kernel capture.
- [Log tools](../docs/LOG_TOOLS.md): decode and compare resident captures.
- [Analysis tools](../docs/ANALYSIS_TOOLS.md): audit offsets, patches, and binary dumps.
- [Bundle packaging](../docs/BUILDING.md): create a source-and-artifact archive.

The sender writes a `*.log.json` sidecar with payload/capture hashes, source
revision, timestamps, transport outcome, and optional operator-supplied firmware,
model, and resident profile. Keep this sidecar with the raw log.
