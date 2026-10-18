# Building

## Prerequisites

Use the public [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk), Make,
Python 3.9+, and the host LLVM tools required by that SDK. The SDK documents
prebuilt archives and host prerequisites. No proprietary SDK is needed.

Set the SDK path to a directory containing `toolchain/prospero.mk`, `bin/`, and
`target/`:

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make all
```

On macOS, set `LLVM_CONFIG` to the executable for your chosen LLVM installation,
as described by the SDK. For example, if LLVM 18 is already installed there:

```sh
export LLVM_CONFIG=/opt/homebrew/opt/llvm@18/bin/llvm-config
make all
```

The build uses the SDK's `prospero-clang` wrapper and does not download or
globally install dependencies. No local workspace paths are compiled into the
build configuration. The SDK is supplied externally; a portable, checksum-pinned
SDK bootstrap is not included in this initial import.

## Targets

| Command | Result |
| --- | --- |
| `make` or `make help` | Show targets without requiring an SDK |
| `make all` | Compile all five diagnostic payloads and the minimal payload |
| `make reader3 procwatch` | Compile selected payloads |
| `make shellshot` | Compile the one-shot process snapshot tool |
| `make thread-probe-v1 thread-probe-v2` | Compile the raw collectors |
| `make minimal-payload` | Compile the starter payload |
| `make check` | Run host tests without an SDK or console |
| `make clean` | Remove generated payload files |

All root-build artifacts go into `out/`. Override `CFLAGS`, `CPPFLAGS`,
`LDFLAGS`, and `LDLIBS` using Make variables if needed.

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
