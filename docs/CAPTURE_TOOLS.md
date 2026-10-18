# Kernel capture and export

These tools collect and transfer an existing diagnostic capture. `kernel-capture`
reads kernel text on **PS5 Pro firmware 13.60 only**. `capture-export` only reads
files and serves one receiver; it does not access the kernel. Both builds have
been checked locally; the imported versions have not been validated on a console.

## Kernel collector

`kernel-capture` requires working SDK kernel read primitives and the exact resume
instrumentation described by `payloads/kernel-capture/profile_13_60_pro.h`. A
matching firmware alone is insufficient: the expected cookie, inactive hook state,
base layout, pmap, and readable page mappings must all pass. It does not install
instrumentation or remove memory protections. Firmware-specific addresses and
state values remain in the named profile header; changing names does not make
these assumptions portable to other consoles or firmware.

The collector writes a new `/data/capture-<unix-time>-<pid>/` directory:

- `manifest.json`: firmware, model, addresses, page audit, completion, expected and
  written byte counts, and CRC32 of fully written blocks.
- `kernel_text.bin`: present only after the complete file is synced and renamed.
- `kernel_text.bin.partial`: retained when a read/write/sync fails; never exported
  as a completed capture.

Console output ends with `CAPTURE_DIR=...` and `STATUS=...` after a manifest is
written. Exit 0 means complete; exit 2 means skipped or partial; exit 1 means a
preflight or filesystem failure. Inspect the manifest for the exact reason.

## Export and receive

Load `capture-export.elf` using your normal payload loader. Wait for
`EXPORT_LISTENING`, then on the computer run:

```sh
python3 host/receive_capture.py CONSOLE_ADDRESS captures/run-001
```

The output directory must not exist. The receiver connects once, validates the
capture in a temporary sibling directory, and creates the requested directory
only after receiving a complete transfer. It adds `transfer.json` with file sizes,
CRC32 and SHA-256 values. If verification fails, it removes temporary files and
returns nonzero. An existing destination, including a symlink, is never reused.
The destination parent must be a trusted local directory.

The exporter selects the lexicographically greatest `capture-*` directory under
`/data` with a nonempty regular `kernel_text.bin` of at most 1 GiB. This is a name
ordering heuristic, not a claim about capture timestamps. If that candidate has
an invalid or missing manifest, the transfer fails; it does not silently choose
another capture. To export a specific directory, build with
`CAPTURE_DIRECTORY`. Selection copies directory names before closing the directory
stream, fixing the original source's dangling pointer.

The exporter waits up to 120 seconds for a receiver, uses a 30-second socket send
timeout, serves one connection, and exits with `EXPORT OK` or `EXPORT FAILED`.
A stalled or truncated transfer must be inspected before manually rerunning it.
Neither tool automatically reloads a payload or retries a transfer.

Receiver options:

```sh
python3 host/receive_capture.py CONSOLE_ADDRESS captures/run-002 \
  --port 9030 --timeout 30 --max-bytes 1073741824
```

The timeout bounds individual socket operations. The byte limit bounds payload
size; manifests are separately limited to 1 MiB. It is not a whole-transfer
wall-clock deadline. CRC32 is checked against the collector's manifest; SHA-256
is recorded locally for subsequent comparisons, not authenticated by the sender.

## Build configuration

Both payloads accept `CAPTURE_ROOT` as a C preprocessor string (default `/data`).
The exporter also accepts `CAPTURE_PREFIX` (default `capture-`),
`CAPTURE_DIRECTORY` (explicit directory, bypasses selection), and `LISTEN_PORT`
(default 9030). Pass these through the build's `CPPFLAGS`, for example:

```sh
make capture-export CPPFLAGS='-DLISTEN_PORT=9031'
```

String definitions need quotes preserved for the compiler; for example the
compiler argument `-DCAPTURE_DIRECTORY='"/data/capture-example"'`. An explicit
path can also export an older `fpkg-research-1360-*` capture with a compatible
manifest. The collector's profile is deliberately fixed to 13.60 Pro.

## Transfer protocol

Each file frame is a 16-byte little-endian header: `FPK1`, a 32-bit filename
length, and a 64-bit content length, followed by filename bytes and content.
Only `manifest.json` and `kernel_text.bin` are accepted, exactly once each.
`END1` plus twelve zero bytes terminates the transfer and must be followed by
connection close. EOF before this marker, a partial header or body, unexpected
filenames, duplicates, excess bytes, or an incomplete manifest fail verification.
The original research receiver/exporter omitted this marker; use this matched
sender/receiver pair together.

Provenance and original SHA-256 hashes are in [capture-imports.json](capture-imports.json).
Host tests cover traversal, truncated transfers, limits, duplicates, completion,
integrity and existing output paths. `tests/test_capture_paging.c` checks page
walks against mock memory without contacting a console.
