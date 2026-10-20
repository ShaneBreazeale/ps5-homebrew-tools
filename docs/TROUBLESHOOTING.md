# Troubleshooting

Inspect both the host terminal and the raw log. The sender's exit status is not
the payload's return code. Keep partial output when a run fails.

## Build and setup

| Symptom | Check or next action |
| --- | --- |
| `Set PS5_PAYLOAD_SDK ...` | Export the SDK root before building a payload; `make help` and `make check` work without it |
| `must contain toolchain/prospero.mk` | Point to the extracted SDK root, not its parent or `target/` |
| Compiler wrapper cannot find LLVM tools | Configure `LLVM_CONFIG` according to the public SDK's instructions; see [Building](BUILDING.md) |
| `LLVM ... found; payloads require LLVM 18` | The SDK picked up a newer LLVM. Set `LLVM_CONFIG` to an LLVM 18 `llvm-config`, or use `make container-build` |
| Same source builds different bytes on another machine | Compare `make checksums` with the CI `payloads` artifact; see [reproducible builds](BUILDING.md#reproducible-builds) |
| `Ignoring CFLAGS from the environment` | Your shell exports build flags; pass intended flags on the `make` command line |
| `make` only prints help | This is the default target; use `make all` or a tool name |
| Changes appear to have no effect | Confirm the target/source path; after changing SDK or compiler settings, use `make clean` and rebuild |
| Reader emits an unused `reopen_log_file` warning | This is inherited source; its main loop never calls that helper |

## Sending and capture

| Symptom | Check or next action |
| --- | --- |
| `File exists` | The log is preserved deliberately; use a new capture filename |
| `No such file or directory` | Check the ELF path and create the parent log directory |
| ELF validation error | Pass the built `.elf`, not a package, flat binary, or truncated download |
| Connection refused, unresolved host, or timeout | Classify ping vs the failed send; see [Black-session classes](#black-session-classes). Do not probe port 9021 |
| Idle timeout | The loader accepted the ELF (`loader_ready` evidence); the payload may still be running. Preserve partial output and establish session state before another send |
| Exit code 0 but no useful output | EOF only confirms the stream ended; look for the tool's readiness, completion, or error messages |

`captures/` is local and ignored by Git. Host errors are printed in the terminal,
so an empty log by itself cannot distinguish a connection failure from an empty
remote response. A failed connect also writes `session_health` into the log
sidecar after one ICMP ping.

## Black-session classes

A black or frozen picture needs a ping-vs-loader class. Classify from **ICMP
ping** and from a **send that already ran**. `host/session_health.py` pings
only; an empty loader connect consumes elfldr's accept.

```sh
python3 host/session_health.py --host "$PS5_HOST"
python3 host/session_health.py --host "$PS5_HOST" --loader-result refused
python3 host/session_health.py --host "$PS5_HOST" --ping-result alive --loader-result open
```

`--loader-result` is evidence from a send, not a probe. After a failed
`send_payload.py` connect, the sender pings once and prints the same class.

| Class | Ping | Loader (from a real send) | Typical picture | Next action |
| --- | --- | --- | --- | --- |
| `loader_ready` | alive | connected (send succeeded) | black after a title launch | Send `resident-snapshot` once. Extra non-kstuff diagnostics may follow. Do not send a second kstuff, process-debugger, or kernel-offset |
| `elfldr_dead` | alive | connection refused | black or frozen | Power-hold recovery. Do not send another ELF into this session |
| `kernel_unreachable` | dead | n/a (do not probe 9021) | black / no HDMI | Power-hold recovery. Historical KERNEL_DBREGS / run-007 class. Do not send payloads into this boot |
| `kernel_answers` | alive | unknown (not probed) | any | Send the intended ELF once if a payload is ready. Do not probe port 9021 |
| `display_sync` | either | n/a | HDMI black + 2 beeps | Safe Mode display reset; this is not a brick. Then classify ping and loader from a new send (`--hdmi-two-beep`) |
| `loader_silent` | alive | connect timeout | any | Do not retry the loader connect. Power-hold if elfldr was expected |
| `host_unresolved` | unresolved | n/a | n/a | Check the configured address. Do not probe port 9021 |

Keep process-debugger, kernel-offset, prosper0gdb, and a second kstuff out of
`elfldr_dead`, `kernel_unreachable`, and `loader_silent`. An idle timeout after
a successful send is `loader_ready` evidence.

## Payload output

| Message or observation | Interpretation |
| --- | --- |
| Reader: `ps5-kstuff is not loaded` | The resident check failed; confirm the intended resident/session without resending it into a live session |
| Reader: `shared_area snapshot failed: -22` | Historically associated with a layout-size mismatch; check the exact reader/resident ABI rather than treating every failure as the same cause |
| `layout_invalid` or `self_missing` | The expected process record layout or self-check failed; do not interpret the remaining bytes using assumed offsets |
| V2: `unsupported firmware/model` | The compiled gate requires 13.60 and SoC `0x840fd0`; rebuilding unchanged will not add support |
| V2: `kernel_layout_validated=0` | Kernel thread capture is skipped; sysctl output may continue, but the v2 summarizer will reject it |
| V2: `cycle_detected` or `read_or_owner_failed` | A bounded traversal stopped; retain the partial records and note the incomplete thread set |
| Sysctl `ENOENT` on a selector | Some researched selectors are unavailable; v1 can retain other useful raw output |
| An expected process/event is absent | Check launch timing, polling gaps, ring overwrite, and whether that logging path was armed |

## Offline summary

If `summarize_threads.py` rejects the input, check that it is a plain-text v2 log
with `kernel_layout_validated=1`, `thread-probe: complete`, and all three passes.
Missing records, discontinuous raw chunks, or changed ownership invalidate the
summary. Preserve the error and original capture rather than editing raw bytes
to satisfy validation. See [Host utilities](../host/README.md) for the JSON fields.
