# Thread probe v2

Capture raw process records and bounded kernel thread records for selected
processes in the researched PS5 Pro 13.60 environment. V2 adds kernel reads,
firmware/model gating, and a live thread-layout self-check to the raw collector.

## Requirements

The compiled gate requires `(firmware & 0xffff0000) == 0x13600000` and SoC
`0x840fd0`. It returns 7 after `unsupported firmware/model` otherwise. SDK kernel
read support must already work in the payload environment.

The self-check matches its thread owner, list links, and TID against its own PID
and `thr_self`. If `kernel_layout_validated=0`, process capture continues but
kernel thread reads are skipped. Such a log is not accepted by the summarizer.

## Build, capture, and summarize

From the repository root, with `PS5_PAYLOAD_SDK` and `PS5_HOST` set:

```sh
make thread-probe-v2
mkdir -p captures
python3 host/send_payload.py out/thread-probe-v2.elf \
  --host "$PS5_HOST" --log captures/thread-probe-v2-001.log
```

After confirming `kernel_layout_validated=1`, all three passes, and
`thread-probe: complete`, summarize the saved file:

```sh
python3 host/summarize_threads.py captures/thread-probe-v2-001.log \
  > captures/thread-probe-v2-001.json
```

## What is captured

The probe takes three process-only snapshots with a one-second delay between
passes. Thread selection includes the probe itself, `SceShellCore`, `SceShellUI`,
`SceAIO`, names containing `eboot`, and an app-info match for the historical test
title `PPSA90001`. That title is a source constant, not a runtime option; the
app-info layout itself remains a compatibility limitation.

Each selected process traversal emits at most 256 thread records of 0x480 bytes.
It stops on a repeated list pointer or read/owner mismatch. A nonzero `next` in
`threads_end` indicates traversal did not reach the end of the list, including
when the cap was reached.

| Prefix | Meaning |
| --- | --- |
| `firmware=... soc=...` | Values used by the compatibility gate |
| `kernel_layout` / `kernel_layout_validated` | Live self-check evidence and result |
| `thread` | PID/name, thread index and TID, thread and owner addresses |
| `raw tag=td-...` | Hexadecimal chunks of a thread record |
| `threads_end` | Remaining next pointer after the bounded traversal |
| `thread-probe: complete` | The main capture loop ended; individual thread lists can still be incomplete |

## Interpretation limits

Threads are not stopped while records are read. A pointer is an observation,
not a proven blocked instruction. The host parser labels unverified field
interpretations with `_candidate` and retains the 256-thread cap limitation.
The implementation performs no explicit kernel writes, hooks, or debug-register
changes; it uses the SDK runtime for kernel access.

Payload return values 1–4 describe query/record failures (4: a pass could not list
processes, logged as `process_query_failed`), 7 the firmware/model
gate, and 0 completion of the main capture. The host sender does not return those
values. See [Host utilities](../../host/README.md) for JSON fields and parser errors.
