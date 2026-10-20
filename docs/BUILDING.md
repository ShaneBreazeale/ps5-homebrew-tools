# Building

## Prerequisites

Use the public [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk), Make,
Python 3.9+, and **LLVM 18** (clang, lld, and llvm tools). The SDK documents
prebuilt archives and host prerequisites. No proprietary SDK is needed.

The quickest path to correct output is the [reference container](#reproducible-builds),
which needs only Docker.

Set the SDK path to a directory containing `toolchain/prospero.mk`, `bin/`, and
`target/`:

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make all
```

The SDK uses the first LLVM it finds (`$LLVM_CONFIG`, then `llvm-config-23` down
to `llvm-config-15`), so a machine with a newer LLVM installed silently builds with
it. The build stops unless that LLVM is major version 18. Point `LLVM_CONFIG` at
LLVM 18:

```sh
export LLVM_CONFIG=/usr/bin/llvm-config-18                    # Ubuntu/Debian
export LLVM_CONFIG=/opt/homebrew/opt/llvm@18/bin/llvm-config  # macOS Homebrew
make all
```

The official LLVM 18 Linux release archives (`clang+llvm-18.1.x-...-ubuntu-18.04`)
link against `libtinfo.so.5`, which Ubuntu 24.04 no longer ships. If `clang` fails
with `libtinfo.so.5: cannot open shared object file`, put a copy of that library on
`LD_LIBRARY_PATH`, or use the distribution's `clang-18`.

The build uses the SDK's `prospero-clang` wrapper and does not download or
globally install dependencies.

## Reproducible builds

Same source, same SDK, and the same LLVM release give byte-identical ELFs on any
host. Your CPU does not matter: the `x86_64-sie-ps5` target always generates code
for the PS5's `znver2` CPU. What does matter:

| Cause | Handling |
| --- | --- |
| LLVM release | The SDK's `crt1.o` and `libc.a` are built with Ubuntu clang 18.1.3. LLVM 20+ also makes the SDK skip `crt1.o` and use clang's built-in PS5 link path. The build requires LLVM 18. Ubuntu clang 18.1.3 and the official 18.1.8 release produced identical payloads ([validation](VALIDATION.md#reproducible-build-check-commit-be12627)). Set `PS5_LLVM_VERSION` to require one exact release. |
| Checkout and SDK paths | `-g` stores source paths. `-ffile-prefix-map` rewrites them to `.` and `/ps5-payload-sdk`. |
| Compiler vendor string | `-fno-ident` drops it from objects. The linker's `.comment` section is removed after linking. |
| Exported `CFLAGS`, `CPPFLAGS`, `LDFLAGS`, `LDLIBS` | Ignored with a warning, since flags like `-march=native` would retarget the payload. Pass flags on the `make` command line instead. |

For the reference build, use the container: Ubuntu 24.04, clang 18.1.3, and SDK
v0.44 pinned by SHA-256 ([Dockerfile](../tooling/container/Dockerfile)). It runs as
`linux/amd64`, including on Apple silicon (emulated, slower):

```sh
make container-build   # builds every payload and writes out/SHA256SUMS
```

CI runs the same build and uploads the ELFs and `SHA256SUMS` as the `payloads`
artifact. To check a local build, run `make checksums` and compare the result with
that artifact. Builds made before these rules, for example with Homebrew LLVM
23.1.1, are not expected to match.

## Targets

| Command | Result |
| --- | --- |
| `make` or `make help` | Show targets without requiring an SDK |
| `make all` | Compile both debugger/inspection tools, seven diagnostic payloads and the minimal payload |
| `make resident-snapshot process-watch` | Compile selected payloads |
| `make kernel-offset` | Build the kernel offset inspection payload; see [kernel backend](KERNEL_DEBUGGER.md) |
| `make process-debugger` | Build the usermode GDB server; see [debugger runbook](DEBUGGER.md) |
| `make process-snapshot` | Compile the one-shot process snapshot tool |
| `make thread-probe-v1 thread-probe-v2` | Compile the raw collectors |
| `make kernel-capture capture-export` | Build the collector and exporter |
| `make bundle` | Build payloads and package source, binaries, SHA-256 inventory, and toolchain versions |
| `make container-build` | Build all payloads in the pinned reference container |
| `make checksums` | Write and print `out/SHA256SUMS` for built payloads |
| `make native-app` | Build the native app folder and ZIP; see [native app](NATIVE_APP.md) |
| `make native-check` | Rebuild the native host tools and runtime and verify pinned checksums, without an SDK |
| `make minimal-payload` | Compile the starter payload |
| `make reader3`, `make procwatch`, `make shellshot` | Copy a tool to its historical research name in `out/` |
| `make check` | Run Python host tests and the C paging mock test (`HOST_CC`, default `cc`) without an SDK or console |
| `make clean` | Remove generated payload files |

All root-build artifacts go into `out/`. `make bundle` writes
`dist/ps5-homebrew-tools.tar.gz` and refuses to replace an existing archive.
The archive contains Git-tracked source, built ELFs, `manifest.json`, and `SHA256SUMS`;
untracked files are never included, and `source_dirty` records uncommitted changes;
keep the manifest with binaries when sharing builds. Override `CFLAGS`, `CPPFLAGS`,
`LDFLAGS`, and `LDLIBS` using Make variables if needed.

For example, a build with explicit optimization flags:

```sh
make clean
make process-watch CFLAGS='-O2 -g -Wall -Wextra'
```

Make tracks source/header timestamps, not SDK installation or compiler-flag
changes. Clean first when changing the SDK, compiler, or build settings so an
existing ELF is not mistaken for a new build.

The standalone template has its own Makefile and can be built after copying it
outside this repository. Resident experiment archives are never executed by
these targets.

## Reader ABI

The checked-in kstuff snapshot header asserts a size of 6,200 bytes, a 16-word
event ring, and a 488-byte message ring. Build the reader with those exact
definitions. A different resident can reject the snapshot or assign different
meanings to its words even if the total size matches.

Compiler success is not a runtime compatibility check. No build target uploads
anything or connects to a console.

## Kernel readiness provider

The kernel-offset default requires an explicitly linked readiness provider; no
current resident gains that interface automatically. The optional
`KERNEL_OFFSET_PROVIDER` source and opt-in
`CPPFLAGS=-DKERNEL_OFFSET_LEGACY_FALLBACK=1` build mode are documented in
[readiness and fallback](KERNEL_READINESS.md#build-modes). Use a fresh build
directory when switching modes. Both remain inspection-only.
