# PS5 Homebrew Tools

Console diagnostics and host utilities for PS5 homebrew development. Watch
processes during an app launch, capture thread records, and inspect logs from
an instrumented kstuff resident.

**Status:** source collection and local build tooling, based on PS5 Pro firmware 13.60 research.
All included payloads compile locally; the standalone builds and native app still need console
validation. See [compatibility](docs/COMPATIBILITY.md) and
[validation results](docs/VALIDATION.md) before running them.

## Features

Choose a tool for the question you want to answer:

| Tool | Use it to |
| --- | --- |
| [Kernel offset backend](docs/KERNEL_DEBUGGER.md) | Resolve checked kernel offsets and inspect the exec-join bytes; execution control unfinished, no console validation |
| [Kernel patch toolkit](docs/KERNEL_PATCH_TOOLKIT.md) | Plan a patch, simulate verified writes on synthetic memory, and check saved evidence; no console validation |
| [Process debugger](payloads/process-debugger/README.md) | Attach by PID, inspect registers/memory, step instructions, and set hardware execution breakpoints; partial console validation |
| [Process snapshot](payloads/process-snapshot/README.md) | Take one snapshot of shell and app-related processes |
| [Process watch](payloads/process-watch/README.md) | Watch process births, disappearances, and zombie transitions over three minutes |
| [Resident snapshot](payloads/resident-snapshot/README.md) | Read three snapshots of counters and event rings from a matching instrumented kstuff resident |
| [Thread probe v1](payloads/thread-probe-v1/README.md) | Capture raw sysctl records and check which selectors are available |
| [Thread probe v2](payloads/thread-probe-v2/README.md) | Capture selected processes' kernel thread records on firmware 13.60, SoC `0x840fd0` |
| [Thread probe v3](payloads/thread-probe-v3/README.md) | Keep capturing one title's kernel thread records while the app is alive |
| [Follower-live](payloads/follower-live/README.md) | Stream new resident ring words and first-seen ioctl commands until the session ends |
| [Kernel capture](docs/CAPTURE_TOOLS.md) and [capture export](docs/CAPTURE_TOOLS.md) | Collect and transfer a bounded kernel-text capture on the matching PS5 Pro 13.60 setup |
| [Native app starter](docs/NATIVE_APP.md) | Build a controller, logging, and notification app folder and ZIP |

The [host utilities](host/README.md) send payloads, preserve raw output, stream
a follower or thread walk until the connection dies, simulate kernel-patch
transactions offline, and provide
[log decoding](docs/LOG_TOOLS.md), [binary analysis](docs/ANALYSIS_TOOLS.md), and
thread summaries. The
[minimal payload template](templates/minimal-payload/README.md) provides a starting
point for your own diagnostic.

Historical resident variants—xlog, rdlog, xin, xslot, and xapp—are documented in
[Resident experiments](residents/README.md). Recovered patches are archived there;
resident builds are not included in the tool targets.

## Installation

You need Python 3.9+, Make, the public
[PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk), and LLVM 18. Newer LLVM
releases produce different payload bytes, so the build refuses them. Python
utilities use the standard library. Follow the [build guide](docs/BUILDING.md) for
SDK and LLVM configuration, or run `make container-build` with Docker for the
pinned [reproducible build](docs/BUILDING.md#reproducible-builds).

From a checkout or extracted source directory:

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make process-snapshot process-watch
```

Built ELF files appear in `out/`. Use `make all` to build every included payload,
including the starter template; `make bundle` packages them with source and hashes. Builds do not upload or run anything on the
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
python3 host/send_payload.py out/process-snapshot.elf \
  --host "$PS5_HOST" --log captures/process-snapshot-001.log
```

Look for `shellshot: ready`, the process records, and
`shellshot: complete procs=...`. Received output is displayed in the terminal and
saved to the log.

### Stream a resident while a title launches

`follower-live` needs an instrumented kstuff already loaded in this boot.
It prints each new ring word once, and each tracked ioctl command the
first time that command appears. On firmware 13.60 a PPR mount is a pfs
SM ioctl, group `0x32`, not `nmount`.

```sh
python3 host/stream_logger.py out/follower-live.elf \
  --host "$PS5_HOST" --log captures/follower-live-001.log
```

The stream logger has no idle timeout. It writes until the loader
connection dies. See [follower-live](payloads/follower-live/README.md).

### Watch an app launch

```sh
python3 host/send_payload.py out/process-watch.elf \
  --host "$PS5_HOST" --idle-timeout 240 --log captures/process-watch-001.log
```

Wait for the baseline before opening the app. The watch runs for 180 seconds and
ends with `procwatch: complete births=... deaths=...`.

Use a new log filename for every run. The sender sends once and never retries.
Its exit status describes the host connection; check the payload's output for
completion. A timeout can leave the payload running. After a failed connect,
the sender pings once and records a session class; `host/session_health.py`
classifies ping vs a send that already ran and never opens port 9021. See the
[host reference](host/README.md) and
[black-session classes](docs/TROUBLESHOOTING.md#black-session-classes).

## Documentation

- [Getting started](docs/GETTING_STARTED.md) — first build, capture, and result check.
- [Build reference](docs/BUILDING.md) — SDK configuration, targets, and bundles.
- [Native app](docs/NATIVE_APP.md), [capture tools](docs/CAPTURE_TOOLS.md), [log tools](docs/LOG_TOOLS.md), and [analysis tools](docs/ANALYSIS_TOOLS.md).
- [Troubleshooting](docs/TROUBLESHOOTING.md) — build failures, connection issues, and incomplete captures.
- [Documentation index](docs/README.md) — all tool guides, architecture, compatibility, and source provenance.
- [Context7 guide](docs/CONTEXT7.md) — index these docs for coding agents.

## Development

```sh
make help          # List build and test targets
make check         # Run host tests without an SDK or console
make native-check  # Rebuild the native runtime and verify pinned checksums
```

Continuous integration runs both checks on Linux and macOS for every push and
pull request; it never builds payloads or contacts a console. Generated binaries
and local captures are ignored by Git. To start a new tool,
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
