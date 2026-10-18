# PS5 Homebrew Tools

Diagnostic payloads and host utilities for developing PS5 homebrew. Capture
process changes, inspect thread snapshots, and read instrumented kstuff logs
from one independently buildable repository.

This is an initial source collection. The diagnostics were used during PS5 Pro
firmware 13.60 research; newly built artifacts still need console validation.

## Features

| Tool | Purpose | Requirements |
| --- | --- | --- |
| [reader3](payloads/reader3/README.md) | Three snapshots of kstuff counters and event rings, one second apart | Resident exposing the matching 6,200-byte snapshot ABI |
| [procwatch](payloads/procwatch/README.md) | Process births, disappearances, and zombie transitions over 180 seconds | Firmware process-record layout matching the 13.60 research |
| [shellshot](payloads/shellshot/README.md) | One snapshot of shell, system, and app-related processes | Same process-record layout |
| [thread-probe-v1](payloads/thread-probe-v1/README.md) | Raw sysctl process and selector captures | Compatible sysctl interface |
| [thread-probe-v2](payloads/thread-probe-v2/README.md) | Bounded kernel thread captures with live layout checks | Firmware 13.60, SoC `0x840fd0`, and SDK kernel-read support |
| `send_payload.py` | Send an ELF once and save raw output | A running ELF loader, usually on port 9021 |
| `summarize_threads.py` | Validate and summarize a completed v2 capture | Python 3.9+; no console connection |

The [resident catalogue](residents/README.md) preserves what xlog, rdlog, xin,
xslot, and xapp measured. Their recovered patch scripts are archived separately
from buildable payloads.

## Installation

Use a local checkout or download and extract this repository's source. The
repository currently provides source; it has no published binary release or
automatic console installer.

Install Python 3.9+, Make, and the public
[PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk). Host utilities use only
the Python standard library. SDK installation and LLVM configuration are
described in [Building](docs/BUILDING.md).

From the repository root:

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make all
```

ELF files are written to `out/`. To build selected tools:

```sh
make reader3 procwatch
```

## Usage

Set your console address and create a directory for local captures:

```sh
export PS5_HOST=your-console-address
mkdir -p captures
python3 host/send_payload.py out/shellshot.elf \
  --host "$PS5_HOST" --log captures/shellshot-001.log
```

For a launch window, start procwatch before opening the app:

```sh
python3 host/send_payload.py out/procwatch.elf \
  --host "$PS5_HOST" --idle-timeout 240 --log captures/procwatch-001.log
```

For an existing v2 thread capture:

```sh
python3 host/summarize_threads.py captures/thread-probe-v2.log \
  > captures/thread-summary.json
```

Every send requires a new log filename. The sender opens one connection, sends
once, and never retries or probes the loader. An idle timeout returns exit code
2 and preserves partial output; it does not prove the payload stopped.

Read [Compatibility](docs/COMPATIBILITY.md) before choosing a payload. In
particular, reader3 requires matching resident instrumentation; an ordinary
kstuff build is not sufficient.

The sender's exit code describes the host connection, not the payload's return
code. Check the tool's readiness, completion, and error output in the capture.
The [Getting started guide](docs/GETTING_STARTED.md) walks through that first run.

## Documentation

Start with the [documentation index](docs/README.md), or choose a guide:

- [Getting started](docs/GETTING_STARTED.md): build, capture, and check a first run.
- [Build reference](docs/BUILDING.md): SDK configuration and Make targets.
- [Host utilities](host/README.md): command options, exit codes, and JSON summaries.
- [Troubleshooting](docs/TROUBLESHOOTING.md): build, connection, and capture problems.
- [Architecture](docs/ARCHITECTURE.md): payloads, host tools, logging, and residents.
- [Compatibility](docs/COMPATIBILITY.md): firmware gates and interpretation limits.
- [Resident experiments](residents/README.md): profiles, archived scripts, and event layouts.

## Start a new payload

Copy [the minimal payload template](templates/minimal-payload/README.md) to start
a standalone SDK project. It prints readiness, its PID, and completion. A native
TV app template and app packaging tools are future additions.

## Development

```sh
make check
```

Host tests require no SDK or console. `make all` compiles payloads without sending
them. Build output and local captures are ignored by Git.

## Contributing

See [Contributing](CONTRIBUTING.md) for adding tools and
[Provenance](docs/PROVENANCE.md) for import hashes and validation boundaries.

## License

New repository code and the diagnostics carrying GPL notices use
GPL-3.0-or-later; see [COPYING](COPYING). Imported files retain their own notices
and provenance. See [Third-party notices](THIRD_PARTY_NOTICES.md) for the BSD
header and the imported kstuff files' licensing status.
