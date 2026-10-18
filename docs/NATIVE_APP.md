# Native app starter

The native starter builds an installable app folder and ZIP from the source in
[`templates/minimal-app`](../templates/minimal-app/README.md). It demonstrates
controller input, debug logging, a notification, and clean exit. Cross logs a
marker; Circle or Options exits. The app and build pipeline compile locally,
but **the resulting app has not been installed or tested on a console**.

## Build

Install the public PS5 Payload SDK and its required host LLVM tools. Set the
SDK path and, where needed, `LLVM_CONFIG` to the matching `llvm-config` binary.
The native pipeline also requires a host C++20 compiler and zlib development
files. From the repository root:

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
export LLVM_CONFIG=/path/to/llvm-config
python3 tooling/native/build.py
```

The command writes `out/native-app/PPSA99001/`, `PPSA99001.zip`, the host
converter and runtime generator, and an intermediate `eboot.elf`. The folder
contains `eboot.bin`, `sce_module/libc.prx`, `sce_sys/param.json`, a generated
icon, and `build-manifest.json` with source and output hashes. The ZIP mirrors
the app folder. Select a new `--output` directory to build again; existing
application output is refused. `--sdk` and `--template` override the defaults.

The runtime is generated from checked-in source and API lists. Its raw and signed
SHA-256 values are pinned and verified during the build. The converter checks
the signed output container structure. This is a local build check, not a
runtime compatibility or installation test. The app metadata uses an example
title and content ID; choose your own unique IDs before distribution.

## Scope and provenance

The native toolchain source was adapted from the local Orbit Store app pipeline;
original paths and hashes are recorded in [native-imports.json](native-imports.json).
The starter main and icon were created for this repository. Source files retain
their GPL notices and attribution. The public Payload SDK remains an external
dependency. The starter has no graphics renderer; adding one requires a graphics
API and matching SDK support. The build has not been validated against other SDK
versions or on a PS5.
