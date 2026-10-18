# Initial import validation

Validated locally on 2026-10-18 using the existing PS5 Payload SDK installation
and host LLVM 23.1.1. The external SDK installation was not fetched or upgraded
as part of this import.

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
