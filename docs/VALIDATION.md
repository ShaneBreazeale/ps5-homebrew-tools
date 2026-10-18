# Initial import validation

Validated locally on 2026-10-18 using the existing PS5 Payload SDK installation
and host LLVM 23.1.1. The external SDK installation was not fetched or upgraded
as part of this import.

> **Note (added later):** LLVM 23.1.1 is not the reference toolchain. The SDK's
> libraries are built with LLVM 18, and LLVM 20+ uses a different SDK link path.
> These ELFs therefore do not represent the intended output. Current builds require
> LLVM 18; see [reproducible builds](BUILDING.md#reproducible-builds).

## Reproducible build check (commit `be12627`)

Checked on 2026-10-18. No payload was sent to a console.

- **Linux workstation** (Pop!_OS 24.04, official LLVM 18.1.8 release, SDK libraries
  identical to v0.44): two checkouts at different paths produced identical
  `SHA256SUMS` for all eight payloads.
- **CI reference container** (Ubuntu 24.04 clang 18.1.3, SDK v0.44): the same eight
  full-file SHA-256 values as the workstation.
- **Against the historical research ELFs** built with LLVM 18.1.8: every allocated
  (loaded) section is byte-identical for `thread-probe-v2` vs `thread-probe-v2.elf`,
  `process-snapshot` vs `shellshot-v1.elf`, and `process-watch` vs `procwatch-v1.elf`.
  Only non-loaded debug paths and `.comment` differ.

| Payload | SHA-256 |
| --- | --- |
| `capture-export.elf` | `e9ff66375afeb48f25db9454e6c4ebc4ac39360f4ffc9caed4ba6e76e8c8d3b3` |
| `kernel-capture.elf` | `aa5dd8d0ff5ec9eed2a8c2c63133eb6e97fdbd3cd74797a592f5c6adcbb8a248` |
| `minimal-payload.elf` | `90b258083a1831e76b5f6c60924e9d6ea019baa8dd6b9a28de4eca9dab9a3547` |
| `process-snapshot.elf` | `f0d7eda67154ad133663d447c5eac590d533485de4a4bad33e9186431b2b2a79` |
| `process-watch.elf` | `036e9caf3a25d13e605ab71cbcdf37832b37042516ef3557c769d1a62342a9e7` |
| `resident-snapshot.elf` | `77150b47490fff58cb9d8c2c8586b66e6d9682ed4073cc94acb0b45e0dc66740` |
| `thread-probe-v1.elf` | `9257bc93aa7dffd699c2aa5489b006d9c5b0f95b34e56334f212518902bca71a` |
| `thread-probe-v2.elf` | `41d56bfe14fe3b177a17a763dfd04ef7e11a74ab72a324833af7ad6055253e4d` |

These values apply to commit `be12627` only; any payload source change changes them.

- `make all`: all seven diagnostic ELF files and the minimal payload compiled.
- The standalone minimal-payload directory also built with its own Makefile.
- Each output was identified as an x86-64, little-endian ELF PIE executable.
- `make check`: all 35 host tests passed without connecting to a console. The native paging mock test also passed.
- The imported thread summarizer parsed the historical completed v2 capture:
  82 process records in each of three passes, with the expected 256-thread
  ShellCore cap retained in the result.
- The native app and clean-room runtime built locally. Generated runtime checksums matched the pinned values; the converter reported valid signed containers.
- The source-and-artifact bundle was created and its archive contents were listed.
- Original/imported file hashes and relative documentation links were checked.
- The GitHub README skill's strict audit passed all checks.

The preserved reader source emits an unused-function warning for its dormant
`reopen_log_file` helper. Its three-pass main loop does not call that helper.

No payload or native app was sent, installed, or console-tested during repository creation. These new
builds are not asserted to reproduce historical binary checksums. The imported
resident patch archives were not executed or rebuilt.

Build output and the historical capture used for validation are excluded from
the source repository.
