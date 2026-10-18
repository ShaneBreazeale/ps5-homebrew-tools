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

## Customize the project

Change the messages and add your diagnostic work in `main.c`. Keep the readiness
write near the start of `main` so a blocked initialization does not hide whether
the payload began executing. The example uses line-buffered stdout and returns
after printing `minimal-payload: complete`.

To rename the output, update both occurrences of `out/minimal-payload.elf` in
the copied Makefile. Keep the SPDX notice when distributing this starter and
include the repository's GPL license text with your derived source.

## Run it

If using the template inside this repository, run from the repository root with
`PS5_HOST` set to your console address:

```sh
make minimal-payload
mkdir -p captures
python3 host/send_payload.py out/minimal-payload.elf \
  --host "$PS5_HOST" --log captures/minimal-payload-001.log
```

When using a copied template, pass its built ELF path to the repository's sender
instead. The script requires a running ELF loader; building alone does not start
one. Expect `minimal-payload: ready`, `minimal-payload: pid=...`, and
`minimal-payload: complete`. See [Host utilities](../../host/README.md) in the
original repository for sender options and capture behavior.
