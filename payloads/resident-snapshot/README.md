# resident-snapshot

Public build name: `resident-snapshot`. Historical alias: `reader3`. Existing output prefixes are preserved.

Read three snapshots from an already-loaded instrumented kstuff resident, with
one second between snapshots. Each pass prints counters, available message and
word rings, syscall instrumentation statistics, and tracked ioctl commands.

## Requirements

The resident must expose `KEKCALL_SHARED_AREA_SNAPSHOT` with the exact layout in
[shared_area.h](../../vendor/kstuff/uelf/shared_area.h): a 6,200-byte snapshot,
16-word event ring, and 488-byte message ring. Ordinary kstuff builds need not
provide that interface. A matching size alone does not verify every field's
meaning; pair the reader with the producing source/profile.

## Build and run

From the repository root, with `PS5_PAYLOAD_SDK` and `PS5_HOST` set:

```sh
make resident-snapshot
mkdir -p captures
python3 host/send_payload.py out/resident-snapshot.elf \
  --host "$PS5_HOST" --log captures/reader3-001.log
```

This sends the reader only. It does not build, load, or replace a resident.

## Read the output

Startup should print `debug-reader: ready`, `debug-reader: start`, and
`debug-reader: attached`. The `debug-reader` prefix is preserved from the
imported source. After attachment, expect three metric groups beginning with
`core`; there is no separate final completion line.

| Record | Meaning |
| --- | --- |
| `log-msg:` | Available text from the resident's bounded message ring |
| `log-word[sequence]=0x...` | Numeric ring word; decode using the resident profile |
| `core`, `dispatch`, `crypto`, and other groups | Accumulated resident counters |
| `syscall[name]` | Arming, trap, and emulation counters for that syscall |
| `ppr_lifetime outstanding=...` | Snapshot of the tracked outstanding-pair gauge |
| `ioctl-com-meta` / `ioctl-com[index]` | Bounded ioctl tracking table and overflow information |

Each pass starts its ring cursors at zero, so the same available window can
appear three times. Compare sequence numbers and counters; repeated printed
words are not necessarily new events. Global counters also include activity
from other payloads, including this reader.

See the [resident event catalogue](../../residents/README.md) for profile-specific
fields. Missing events can reflect ring overwrite or an unarmed path.

## Failures and side effects

`debug-reader: ps5-kstuff is not loaded` indicates a failed resident check.
`shared_area snapshot failed: ...` means the snapshot request failed. The reader
returns 1 in either case and 0 after three successful passes; the host sender
does not propagate those payload return values.

The main loop streams through the loader and never opens the dormant
`/data/kstuff_debug.log` helper. A successful rebuild has not been console-tested
as part of this standalone repository. See [Compatibility](../../docs/COMPATIBILITY.md).
