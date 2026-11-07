# Thread probe v3 — plateau walker

Continuously capture a target title's kernel thread records while the app
is alive, so a wedged application can be observed mid-plateau and the trace
survives a later console panic on the host side (pair with
`host/stream_logger.py`, which never times out).

v3 keeps v2's read-only core — SDK `kernel_copyout` reads, the allproc
walk with owner-checked thread chains, raw `0x480`-byte thread records —
and adds title-targeted discovery plus a live loop.

## What it prints

- `WALK pass=N pid=P proc=0x…` — target found for this pass
- `thread pid=P index=I tid=T td=0x…` + one `raw td-T-N=<hex>` line per
  thread (the full thread struct; decode wait channels host-side)
- `walk_end pid=P threads=N` — chain walk finished
- `WALK pass=N target=… not_found` — target process absent this pass

## Build and run

From the repository root, with `PS5_PAYLOAD_SDK` set:

```sh
make thread-probe-v3
```

Send like any payload, but keep the connection alive across a wedge or
panic with the streaming logger:

```sh
python3 host/stream_logger.py out/thread-probe-v3.elf \
  --host "$PS5_HOST" --log captures/plateau-001.log
```

Optional argv on the console side: `argv[1]` title id (default
`PPSA90001`), `argv[2]` interval ms (default 2000), `argv[3]` pass cap
(default 300). elfldr passes no argv, so the defaults apply unless a
sender wrapper injects them.

## Requirements and limits

Same gate as v2: firmware 13.60 (`0x13600000`) and SoC `0x840fd0`.
Kernel reads use the SDK primitive available in a fresh elfldr payload —
no kstuff residency required, no kernel writes, no hooks, no debug
registers. The raw thread records deliberately avoid ABI guesses; the
host summarizer owns offset decoding.
