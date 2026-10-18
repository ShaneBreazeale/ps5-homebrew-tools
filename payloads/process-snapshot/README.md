# process-snapshot

Public build name: `process-snapshot`. Historical alias: `shellshot`. Existing output prefixes are preserved.

Take one sysctl process snapshot and print entries whose names contain `Shell`,
`SysCore`, `eboot`, `NK`, `kstuff`, or `payload`. Use it to check which shell and
app-related processes remain after a launch.

## Build and run

From the repository root, with `PS5_PAYLOAD_SDK` and `PS5_HOST` set:

```sh
make process-snapshot
mkdir -p captures
python3 host/send_payload.py out/process-snapshot.elf \
  --host "$PS5_HOST" --log captures/shellshot-001.log
```

## Output

The run begins with `shellshot: ready`, followed by a console timestamp and raw
byte count. Each matching `proc` line includes:

| Field | Meaning |
| --- | --- |
| `pid`, `ppid` | Observed process and parent process IDs |
| `stat`, `nthr` | Raw state and thread count from the process record |
| `comm` | Sanitized process name, up to 20 characters |
| `app_rc` | Return status from the app-info query |
| `appid`, `type`, `title` | Fields using the imported app-info layout; treat title interpretation as a candidate |

`shellshot: complete procs=...` reports the total enumerated process count,
including entries that did not match the name filter. It is not the number of
printed `proc` lines.

The snapshot captures a moment in time. A missing process may have exited before
the query or may not match the filter; use [procwatch](../process-watch/README.md) to
observe changes over a launch window.

## Compatibility and failures

Record offsets come from PS5 Pro 13.60 research. The tool does not explicitly
gate firmware/model. It makes no explicit kernel-memory accesses, hooks, or
console-file writes beyond the shared SDK runtime's behavior.

`size_failed` or `query_failed` reports a sysctl problem. `layout_invalid`
rejects an unexpected record stride. Payload return values are 0 for completion,
1 for query/allocation errors, and 2 for an invalid layout. These do not become
the host sender's exit code; inspect the capture.
