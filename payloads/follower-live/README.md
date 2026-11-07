# Follower-live — continuous kstuff ring streamer

Streams new ring words from a resident kstuff observer (`KSTUFF_OBS=1`)
to stdout continuously at 4 Hz, with a compact `LIVE` liveness line every
five seconds, so the host log holds everything up to a quarter second
before a console panic power-off. A ten-minute hard cap bounds a
forgotten process; an early exit fires when the kekcall liveness probe
reports kstuff gone.

Derived from the campaign's `debug-follower` burst snapshotter; the
ring/message/metric decoding and the `PPRMAP01` destination-source dump
are unchanged. This port drops the on-console `/data` log tee — pair it
with `host/stream_logger.py` so the trace lives on the host instead.

## Requirements

A resident `KSTUFF_OBS=1` kstuff in the same boot (the kekcall shared
area and read probes live there). Firmware 13.60, SoC `0x840fd0`.

## Build and run

```sh
make follower-live
python3 host/stream_logger.py out/follower-live.elf \
  --host "$PS5_HOST" --log captures/follower-live-001.log
```

The logger never applies an idle timeout; it writes until the loader
connection dies, which is the point — a panic only costs the final
in-flight poll.

## Output

- `debug-reader: ready/start/attached` — handshake (stderr first, before
  anything that could hang)
- new `log-word[seq]=…` lines when the ring advances. Cursors persist
  across passes, so a word prints once
- `ioctl-com-new` the first time a tracked ioctl command appears, with
  its group byte. Group `0x32` is the 13.60 pfs SM transport (for
  example `0x80103207`). `ioctl-com-overflow` prints when the table
  overflows
- `LIVE pass=N kek=… ioctl=… ioctl_trap=… nmount_trap=… fself_traps=…
  fpkg_traps=… mbx=… mbx_fpkg=… fpkg_disp=… lw_writes=…
  outstanding=… next_seq=…` every ~5 s
- `follower: PPRMAP01 …` plus `src`/`dst` hex dumps once per boot

On 13.60 a PPR mount is that group-`0x32` ioctl, issued from ShellCore,
not `nmount`. `nmount_trap` staying 0 during a title launch is expected.
The shared-area table contains only commands the resident chose to
record. A table with no group `0x32` means this resident did not record
the pfs command, not that the mount was absent.
