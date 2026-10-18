# Source provenance

This repository collects source from the existing local PS5 research workspace.
The original workspace remains unchanged.

[imports.json](imports.json) records original file locations relative to that
workspace, source SHA-256 values, initial imported SHA-256 values, and explicit
import changes. The source checkout's checkpoint is
`47da23b70685651a475d20247a3c4f2cac433eb4` from the local kstuff-lite history.
Some imported files were untracked there; the checkpoint alone cannot reproduce
this collection. Hashes identify the actual imported bytes.

The reader source and snapshot header were already present in that local
checkpoint. Its three-pass loop and 6,200-byte layout agree with the reader3
research notes. A new standalone build is not claimed to reproduce the
historical reader3 ELF byte for byte. The historical ELF had SHA-256
`626e503d59ab2e01c793a2a53bfdd123f2ad5207e9db429d0e61ab4b114544fc`.

The standalone build relocates one reader include path. The original header
layouts and tool names are preserved so the imports can be compared with the
research implementation.

The payload sender is adapted from the research sender. It requires an explicit
console address and reserves a new log file before opening a loader connection.
It has host tests for one-send behavior, invalid inputs, existing captures,
partial output, timeouts, and connection errors.

## Resident recovery

The recovered xin, xslot, xapp, and rdlog patch scripts are preserved byte for
byte as `.py.txt` archives. They embed historical machine paths and depend on
temporary baseline files unavailable in this checkout. They are evidence for
reconstructing experiments, not portable build entry points. Their bytes and
provenance are recorded in the import manifest.

No resident ELF, kernel dump, console executable, credential, or raw session
capture is imported into this repository. Resident catalogue binary checksums
come from research notes, not a rebuild here.

## Validation records

For a future release, record the source commit and local modifications, SDK
version or archive checksum, host compiler version, build command, output
checksums, and console model/firmware used for testing. Distinguish compiled,
host-tested, and console-tested artifacts.
