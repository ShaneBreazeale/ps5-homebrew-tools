# Third-party notices

## Diagnostic source

The process and thread diagnostics carry `GPL-3.0-or-later` identifiers. Their
notices are preserved. New sender, starter payload, and repository support code
are also provided under GPL-3.0-or-later. The complete GPL version 3 text is in
[COPYING](COPYING).

## kstuff reader and headers

`payloads/reader3/main.c` and `vendor/kstuff/uelf/` were imported from the local
kstuff-lite research checkout, whose remote points to
[EchoStretch/kstuff-lite](https://github.com/EchoStretch/kstuff-lite). Their
original source locations, hashes, and import changes are in
[docs/imports.json](docs/imports.json).

Those imported files do not carry explicit license notices, and that local
checkout did not contain a top-level license file. This repository does not
assign new license terms to those imports or to archived resident patches that
include kstuff-derived code. Their upstream licensing must be established before
redistributing them as a public release.

## FreeBSD ioctl header

`vendor/freebsd/sys/ioccom.h` retains the University of California copyright
notice, BSD conditions, and disclaimer from the original header. Retain those
terms when redistributing source or binaries that incorporate it.

## External SDK

The public PS5 Payload SDK is an external build prerequisite. It is not vendored
or downloaded by this repository. Its own code and dependencies retain their
upstream licenses.
