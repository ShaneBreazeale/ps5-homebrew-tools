# PS5 Homebrew Tools

Console diagnostics and host utilities for PS5 homebrew development. Watch
processes during an app launch, capture thread records, and inspect logs from
an instrumented kstuff resident.

**Status:** initial source collection, based on PS5 Pro firmware 13.60 research.
All included payloads compile locally; the standalone builds still need console
validation. See [compatibility](docs/COMPATIBILITY.md) and
[validation results](docs/VALIDATION.md) before running them.

## Features

Choose a tool for the question you want to answer:

| Tool | Use it to |
| --- | --- |
| [Shellshot](payloads/shellshot/README.md) | Take one snapshot of shell and app-related processes |
| [Procwatch](payloads/procwatch/README.md) | Watch process births, disappearances, and zombie transitions over three minutes |
| [Reader3](payloads/reader3/README.md) | Read three snapshots of counters and event rings from a matching instrumented kstuff resident |
| [Thread probe v1](payloads/thread-probe-v1/README.md) | Capture raw sysctl records and check which selectors are available |
| [Thread probe v2](payloads/thread-probe-v2/README.md) | Capture selected processes' kernel thread records on firmware 13.60, SoC `0x840fd0` |

The [host utilities](host/README.md) send payloads, preserve raw output, and turn
completed v2 thread captures into JSON summaries. The
[minimal payload template](templates/minimal-payload/README.md) provides a starting
point for your own diagnostic.

Historical resident variants—xlog, rdlog, xin, xslot, and xapp—are documented in
[Resident experiments](residents/README.md). Recovered patches are archived there;
resident builds are not included in the tool targets.

## Installation

You need Python 3.9+, Make, and the public
[PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk) with its host LLVM
prerequisites. Python utilities use the standard library. Follow the
[build guide](docs/BUILDING.md) for SDK and LLVM configuration.

From a checkout or extracted source directory:

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make shellshot procwatch
```

Built ELF files appear in `out/`. Use `make all` to build every included payload,
including the starter template. Builds do not upload or run anything on the
console. Prebuilt downloads and an automatic console installer are not yet
provided.

## Usage

Your console must already have a working homebrew environment and a reachable
ELF loader. Replace the address below with your console's address; the sender
uses port `9021` by default.

### Take a process snapshot

```sh
export PS5_HOST=your-console-address
mkdir -p captures
python3 host/send_payload.py out/shellshot.elf \
  --host "$PS5_HOST" --log captures/shellshot-001.log
```

Look for `shellshot: ready`, the process records, and
`shellshot: complete procs=...`. Received output is displayed in the terminal and
saved to the log.

### Watch an app launch

```sh
python3 host/send_payload.py out/procwatch.elf \
  --host "$PS5_HOST" --idle-timeout 240 --log captures/procwatch-001.log
```

Wait for the baseline before opening the app. The watch runs for 180 seconds and
ends with `procwatch: complete births=... deaths=...`.

Use a new log filename for every run. The sender sends once and never retries.
Its exit status describes the host connection; check the payload's output for
completion. A timeout can leave the payload running. See the
[host reference](host/README.md) for options, exit codes, and offline summaries.

## Documentation

- [Getting started](docs/GETTING_STARTED.md) — first build, capture, and result check.
- [Build reference](docs/BUILDING.md) — SDK configuration and available targets.
- [Troubleshooting](docs/TROUBLESHOOTING.md) — build failures, connection issues, and incomplete captures.
- [Documentation index](docs/README.md) — all tool guides, architecture, compatibility, and source provenance.

## Development

```sh
make help     # List build and test targets
make check    # Run host tests without an SDK or console
```

Generated binaries and local captures are ignored by Git. To start a new tool,
copy the [minimal payload template](templates/minimal-payload/README.md); it builds
independently of this repository.

## Contributing

See [Contributing](CONTRIBUTING.md) for adding tools, documenting compatibility,
and recording verification. Preserve source identities and distinguish build
results from console testing.

## License

New repository code and diagnostics carrying GPL notices use GPL-3.0-or-later;
see [COPYING](COPYING). Imported files retain their own notices. The
[third-party notices](THIRD_PARTY_NOTICES.md) cover the BSD header and the imported
kstuff files' licensing status.
