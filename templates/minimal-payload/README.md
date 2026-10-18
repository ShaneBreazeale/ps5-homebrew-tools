# Minimal payload

A standalone C payload that prints readiness, its PID, and completion to the ELF
loader. Use it as a small starting point for a diagnostic tool. It has no hooks,
kernel-memory access, or dependency on the rest of this repository.

Copy this directory to a new project, set the public PS5 Payload SDK path, and
build from the copied directory:

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make
```

The output is `out/minimal-payload.elf`. Keep `main.c`, `Makefile`, and this README
together when copying. Configure `LLVM_CONFIG` if your SDK requires it.

This is an ELF payload starter. A native app with a TV icon, controller input,
graphics, and package metadata requires a separate app template.
