# process-watch

Public build name: `process-watch`. Historical alias: `procwatch`. Existing output prefixes are preserved.

Observe process births, disappearances, and transitions to the raw zombie state
during a three-minute launch window. Procwatch queries sysctl every 50 ms and
keeps a bounded table of up to 256 processes.

## Build and run

From the repository root, with `PS5_PAYLOAD_SDK` and `PS5_HOST` set:

```sh
make process-watch
mkdir -p captures
python3 host/send_payload.py out/process-watch.elf \
  --host "$PS5_HOST" --idle-timeout 240 --log captures/procwatch-001.log
```

Wait for `procwatch: ready (sysctl only)` and the `baseline` records before
opening the app. Note the launch time and visible result. Leave the capture
running until `procwatch: complete births=... deaths=...` appears.

The receive timeout measures silence, not total duration. Regular `tick` output
normally keeps the connection active throughout the watch.

## Output reference

| Prefix | Meaning |
| --- | --- |
| `baseline` | Capture start time, process count, and collector PID |
| `base` | Each process present in the initial list |
| `birth` | A PID present now but absent from the previous sample |
| `app` | Best-effort app-info query for a newly observed process |
| `death` | A PID absent now; fields come from its last observed sample |
| `zombie` | An observed transition to raw `stat=5` |
| `tick` | Approximate one-second polling heartbeat and accumulated totals |

Process records include `time`, `pid`, `ppid`, `start`, `stat`, `xstat`,
`slptime`, `nthr`, and `comm`. `time` is the console's seconds-since-epoch clock;
do not assume it agrees with the host clock. Status fields are raw observations,
and the app-info title layout is a known candidate rather than an authoritative
title identifier.

## Bounds and compatibility

The imported offsets were checked during PS5 Pro 13.60 research. Procwatch
validates record bounds and the presence of its own PID; it does not have V2's
explicit firmware/model gate. Those checks do not establish support for another
firmware. Poll duration and interval are constants in [main.c](main.c), not CLI
options.

A short-lived process can fall entirely between polls. Matching is by PID, so
rapid PID reuse can also be missed. A disappearance records an observation,
not the cause of termination.

The implementation makes no explicit kernel-memory reads/writes, hooks,
debug-register changes, or console-file writes; it uses the SDK payload runtime.

## Payload return values

| Value | Meaning |
| --- | --- |
| `0` | Watch completed |
| `1` | Initial query/allocation failed |
| `2` | Invalid layout, table limit, or missing self process |
| `3` | A later query failed |

These values are not the [host sender's exit codes](../../host/README.md).
