# Reproducible private kernel resident builds

This extends the [toolkit plan](KERNEL_PATCH_TOOLKIT_PLAN.md) from individual
object checks to complete resident image linking. It supports the stage 2
inspection bridge and stage 3 owned-cell adapter with the same pinned upstream
commit. It builds locally or on the documented gpubox environment, and never
contacts a console. See the [research design](KERNEL_PATCH_RESEARCH.md) for the
questions these builds and later experiments can answer.

## Inputs and environment

Use the standard public Payload SDK and LLVM **18**, plus Yasm and NASM. The
builder enforces LLVM 18 independently of Make and invokes the SDK compiler
wrapper. It prioritizes the pinned resident FreeBSD headers, uses freestanding
code without the SDK startup/libraries for resident images, and preserves the
existing upstream assembly/cryptography implementations. The actual installer
translation unit is also compiled with that compiler.

The reference gpubox environment is:

```sh
export PS5_PAYLOAD_SDK=/home/shane/stage0-build/ci-sdk/opt/ps5-payload-sdk
export LLVM_CONFIG=/home/shane/stage0-build/llvm/bin/llvm-config
export LD_LIBRARY_PATH=/home/shane/stage0-build/libdeps/lib/x86_64-linux-gnu
export YASM=/home/shane/stage0-build/yasm-prefix/bin/yasm
export NASM=/home/shane/stage0-build/nasm-prefix/bin/nasm
```

These are recorded build-host locations, not portable installation defaults.
The build downloads and installs no dependencies. The source checkout needs
initialized BearSSL and ISA-L Crypto submodules at the parent commit's exact
gitlinks. Dirty dependency files and prebuilt archives are not imported.

## Prepare and build

Choose a new overlay directory and a new private build directory. They must not
already exist. `--link-inputs` includes and hashes all exported headers, source,
assembly and dependency files, the submodule commits and the build script.
The existing smaller object-check overlays cannot be used for this link.

```sh
python3 tooling/prepare_kernel_patch_stage2.py --stage 3 --link-inputs \
  --source /ABSOLUTE/PATH/TO/kstuff-lite --output out/stage3-link-inputs
python3 tooling/verify_kernel_patch_stage2.py --stage 3 \
  --overlay out/stage3-link-inputs
make kernel-patch-resident \
  KERNEL_PATCH_RESIDENT_OVERLAY="$PWD/out/stage3-link-inputs" \
  KERNEL_PATCH_RESIDENT_OUTPUT="$PWD/out/stage3-linked"
```

Use `--stage 2` with a separate overlay for inspection-only integration. For
OBS layout, build the same overlay into another new directory with
`KERNEL_PATCH_RESIDENT_OBS=1`. The direct Python interface also supports
`--jobs`, `--yasm` and `--nasm`; use `--help` for the exact arguments.

Preparation pins the generator and builder. A source or builder change requires
a fresh overlay and matching SDK clients. Every exported input is verified
before and after linking. Unexpected translation units, changed dependencies
and modified generated structure headers are refused. These checks assume the
local build inputs remain stable during the compiler invocation.

## Outputs and interpretation

| Output in the private build directory | Meaning |
| --- | --- |
| `uelf/uelf`, `uelf/uelf.bin` | Complete linked resident, unstripped and stripped |
| `kelf` | Complete linked, unchanged upstream kernel entry image |
| `installer.o` | Actual installer source compiled with both linked images embedded; not a loadable installer |
| `build-evidence.json` | Source/config identity, layout, LLVM version, tool hashes, output hashes and loader audits |
| `commands.json`, `logs/` | Exact compiler/assembler/link commands, exit statuses and diagnostics |
| `INCOMPLETE` | Build has not completed; partial artifacts are not accepted results |

The ELF audit checks x86-64 format, bounded load segments and entry, the
`0x1f0000` resident image limit, exact external symbol inventory, and only the
RELA types supported by the pinned `load_kelf`. It rejects dependencies, PLT,
TLS, unsupported relocation forms and unresolved helper functions. It also
checks the stripped resident. This is static compatibility checking, not
execution or validation of the resident's kernel logic.

The upstream `kelf` stores relocated words in `.text`; only its link uses
`-z notext`. The [LLVM 18 linker source](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/lld/ELF/Driver.cpp)
implements this text-relocation option. The custom loader already handles these
words before entry. This flag changes a host link check; it installs no kernel
write primitive and does not change page permissions on a console.

All artifacts/configurations may contain the bearer credential. The overlay and
build directories are mode 0700; completed artifact/log files are mode 0600.
Keep them outside Git and public bundles. This target is opt-in and excluded
from `all` and `bundle`. Protect any needed configuration before `make clean`,
which removes `out/`.

## Remaining boundary

`resident_linked: true` and `installer_compiled: true` are precise build claims.
`installer_linked` and `console_validated` remain **false**. The inherited
installer still uses a research-runtime entry/bootstrap contract; compiling it
does not supply a reviewed SDK startup integration. Do not relabel an old
research-runtime ELF as an SDK installer or use it as automatic recovery.
Fresh console readiness, stage 2 hardware integration and stage 3 live
write/readback/restoration remain separate milestones.

## Build evidence — 2026-10-20

The isolated gpubox build `/tmp/ps5-kernel-linked-g5fSFY` used the standard
staged Payload SDK and LLVM **18.1.8**, Yasm and NASM at the locations above.
Stage 2 and stage 3 complete resident links, ELF audits and actual installer
compiles passed in both non-OBS and OBS layouts. The assembler/crypto sources
were built from the pinned commits, with no prebuilt library imports. The new
freestanding `runtime.c` supplies the upstream OBS logger's missing `strlen`
dependency; logging semantics are preserved. The installer compiles retain 15
inherited assignment/string-pointer warnings. Resident links emitted no warnings.

Local `make check` passed all **161** Python tests and C paging checks. The same
host suite passed on gpubox with four optional Capstone tests skipped. Standard
`make process-debugger kernel-offset kernel-patch-check` and configured stage 2
and stage 3 exercise/query SDK clients also passed. New regression tests cover
complete source inventories, changed dependencies/generated headers, unexpected
imports, malformed ELF tables, unsupported relocations and local load-bias errors.

Two stage 3 non-OBS builds of the same overlay into different directories
produced identical hashes for all four recorded artifacts, including the actual
installer object. This demonstrates repeatability for those exact inputs and
build host; it does not establish cross-toolchain or cross-platform identity.

Source/config identities (not ELF hashes):

- Stage 2: `8818afdf16edba96873da2a1c00d3321902f39f7634463843cd2d4926c4eca4d`.
- Stage 3: `f24f2ac7db93b494c035f3a5f0625ff1fecf2a2839b7539cde9c371b35bc1557`.

These are this runbook's overlay identities generated during the linked build
(`out/kernel-patch-linked-stage2-verified/` and
`out/kernel-patch-linked-stage3-verified/`). They are separate overlay
generations from the ones the stage runbooks pin as their prepared source
overlays:
`efc519b5379502b201da0e5dcd52de4c57a7a875bbae71c39fc223c132445263` in
`out/kernel-patch-stage2-final/` (see
[stage 2](KERNEL_PATCH_STAGE2.md)) and
`80ad062e0253863fa47001825d277133f663495fbfb96ef6931e282f8ad14fff` in
`out/kernel-patch-stage3-final/` (see [stage 3](KERNEL_PATCH_STAGE3.md)).
Each identity is valid only for its own recorded inputs and build identity.

| Resident image | Stripped `uelf/uelf.bin` SHA-256 |
| --- | --- |
| Stage 2, non-OBS | `5564c1581a691193db818c25c6a15c38a038622cd4ea465b962f8d3a3f82db02` |
| Stage 2, OBS | `1991344316fbca11d1f096b68fe21ee5a006d9132d4eb77e66d8a807878e3b18` |
| Stage 3, non-OBS | `4a6063369c2f35294802f05c98152d55c851eefcd33f1621d8d64ef68424b1f7` |
| Stage 3, OBS | `a7eebce64033cc9e6a0d8655126e73550080a0b25b75bcbec5eea94cb986841f` |

| Configured SDK client | ELF SHA-256 |
| --- | --- |
| `kernel-patch-stage2.elf` | `7ca5498425bc89a17e08f6284f516c9f3feda79836b470db15d2ae8e70187d4e` |
| `kernel-patch-stage3.elf` | `b75c268db95666ae3ab1f6925d79b559ad0389e1f43e5c55497f1510be75a816` |
| `kernel-patch-stage3-query.elf` | `ca52b38610f4568262b136020064abdf6b4d5c2ff32b15dc09ffa67ef43f0c93` |

Private evidence under `captures/kernel-patch-linked-20261020-1tltdr22/` retains
per-build commands/logs, complete artifact/tool hashes, linked images, installer
objects, SDK client ELFs and saved offline site analysis. The matching overlays
are `out/kernel-patch-linked-stage2-verified/` and
`out/kernel-patch-linked-stage3-verified/`. Their credentials are private.
No installer ELF was produced and no payload was sent to a console.
