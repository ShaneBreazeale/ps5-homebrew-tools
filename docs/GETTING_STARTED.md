# Getting started

This guide builds a one-shot process snapshot and saves its output on your
computer. Read the [compatibility notes](COMPATIBILITY.md) first: the diagnostic
record layouts come from PS5 Pro 13.60 research.

## 1. Prepare the host and console

On your computer, install Python 3.9+, Make, and the public
[PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk). Its upstream README
describes SDK archives and host LLVM prerequisites. No Python packages are
required for this repository.

The console must already have a working homebrew/exploit environment and an ELF
loader reachable from your computer. Obtain its address and loader port from
your existing setup. This repository does not install or start the exploit or
loader. Avoid testing a loader with an empty connection; the sender connects
only when it has a payload to send.

## 2. Build a payload

From the repository root, point to your SDK installation:

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make shellshot
```

The result is `out/shellshot.elf`. If the SDK needs an explicit LLVM path, set
`LLVM_CONFIG` as described in [Building](BUILDING.md).

To start with the template instead, use `make minimal-payload` and send
`out/minimal-payload.elf`. That starter prints its PID and completion without
interpreting firmware process-record fields.

## 3. Save a first capture

Replace `your-console-address` with the actual address:

```sh
export PS5_HOST=your-console-address
mkdir -p captures
python3 host/send_payload.py out/shellshot.elf \
  --host "$PS5_HOST" --port 9021 --log captures/shellshot-001.log
```

The sender displays received text and writes the original bytes to the log.
Use a new filename for each capture. The log directory must already exist.

A normal shellshot run prints `shellshot: ready`, a timestamp and byte count,
matching `proc` records, and `shellshot: complete procs=...`. The final count
includes all enumerated processes, not just the filtered records printed.

A normal sender exit means the connection closed without a host error; inspect
the payload's output to determine whether its work completed.

## 4. Choose the next diagnostic

| Question | Next step |
| --- | --- |
| Which processes appear or disappear during a launch? | [Procwatch](../payloads/procwatch/README.md); wait for its baseline before launching |
| What did the already-loaded instrumented resident record? | [Reader3](../payloads/reader3/README.md); confirm its snapshot ABI first |
| Which sysctl selectors return useful data? | [Thread probe v1](../payloads/thread-probe-v1/README.md) |
| What thread records remain in the researched 13.60 environment? | [Thread probe v2](../payloads/thread-probe-v2/README.md) |

Keep app launch timing and resident identity alongside the capture. Procwatch
and thread probes are separate payloads; this repository does not orchestrate
concurrent diagnostic runs.

## 5. Keep the evidence together

Record the source commit, payload checksum, firmware/model, resident profile if
any, send time, app launch time, and visible result. Preserve raw captures when
creating JSON summaries. `captures/` is ignored by Git.

An idle timeout or lost connection can leave the payload running. The sender
does not retry. Use [Troubleshooting](TROUBLESHOOTING.md) to interpret the result
before deciding on another run.
