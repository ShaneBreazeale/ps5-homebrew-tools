# Thread probe v1

Preserve raw sysctl records while checking which process/thread selectors are
available. This collector uses sysctl rather than explicit kernel-memory reads.
It is useful for ABI research, including firmware where thread selectors return
`ENOENT`.

## Build and run

From the repository root, with `PS5_PAYLOAD_SDK` and `PS5_HOST` set:

```sh
make thread-probe-v1
mkdir -p captures
python3 host/send_payload.py out/thread-probe-v1.elf \
  --host "$PS5_HOST" --log captures/thread-probe-v1-001.log
```

## Capture flow

The probe first queries its own PID and checks the record length, own PID field,
and terminated name prefix. A mismatch ends interpretation. It then takes three
passes, sleeping one second between them, and prints raw bytes in chunks of at
most 64 bytes.

It tries the all-thread selector, then falls back to a process-only list and
per-PID thread queries. On the first pass it also queries process pathnames.
Unsupported selectors are logged, and the collector can continue through
fallback paths.

| Prefix | Meaning |
| --- | --- |
| `thread-probe: ready (sysctl only)` | Collector reached its main function |
| `prefix_validation` | Self-record prefix check and returned size |
| `snapshot pass=0/1/2` | Beginning of a capture pass |
| `query` | Selector, PID, returned byte count, and query status |
| `record` | Record size plus candidate PID/name fields |
| `raw` | Record tag, sequence, chunk offset, and hexadecimal bytes |
| `records_end` | Record count and consumed/total byte counts |
| `path` | Best-effort pathname query result |
| `thread-probe: complete` | Main capture loop completed |

Queries are bounded to 4 MiB buffers and 4,096 records per interpreted buffer;
PID discovery keeps up to 256 unique entries. The self-prefix check does not
validate all candidate fields on other firmware.

## Interpreting failures

`refusing record interpretation after self mismatch` or `layout_invalid` means
the source's field assumptions did not hold. Keep the original bytes for offline
inspection. Payload failures return values 1–6 depending on the query or record
stage; completion returns 0. Check messages rather than the sender's exit code.

The current [thread summarizer](../../host/README.md) accepts V2 captures only.
V1 data has no validated kernel thread records and must not be passed to it as
if it were V2.
