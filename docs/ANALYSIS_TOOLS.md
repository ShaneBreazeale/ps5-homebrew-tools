# Offline binary analysis tools

These Python 3 tools inspect files on your computer. They do not contact a console or apply patches. Run commands from the repository root. All commands have `--help` and use only the Python standard library.

## Offset checks and table comparison

```sh
python3 host/validate_offsets.py offsets.h \
  --dump kernel_text.bin --base 0xffffffff8d640000 --origin 0xffffffff8e300000 \
  --profile profiles/analysis/ps5-pro-13.60-capture.json > offset-report.json
python3 host/validate_offsets.py old-offsets.json --compare new-offsets.json > comparison.json
```

`address = origin + table value`; `file offset = address - base`. Provide mapping addresses from the actual capture. The included profile describes one PS5 Pro 13.60 capture and checks eight original instruction byte signatures. Its addresses are not universal firmware constants; the dump must have its recorded size. Explicit `--base` and `--origin` override profile defaults. Without a profile, both mapping options are required and offsets are reported as `unverified`, even when they fall inside the captured range.

Tables accept a JSON object mapping names to integers or integer strings, or one `DEF(name, expression)` per line. Expressions support integer constants, symbol references, parentheses and addition/subtraction only. A conventional single include guard, includes, and `START_FW(number)`/`END_FW()` wrappers are accepted. Includes are **not expanded**; C preprocessing and conditional table selection are unsupported. Feed one selected table. Cycles, unsupported expressions and duplicate DEF names fail parsing. Tables containing structure-field offsets alongside address offsets must be split before mapping: one origin cannot describe both meanings.

A custom profile is a JSON object with optional `name`, `base`, `origin`, `size`, and `checks`; checks map symbol names to exact hex byte strings:

```json
{"name": "example", "checks": {"read_register": "0f32"}}
```

Reports distinguish `match`, `mismatch`, `missing`, `outside_capture`, and `unverified`. Missing or out-of-range requested signatures fail the check. Other uncaptured offsets remain explicitly unverified. The report records the dump SHA-256. Byte equality does not establish function identity, instruction boundaries, calling conventions or hardware support.

`--compare` compares the union of names from two tables and exposes missing names and unequal numeric values. It can be combined with dump checks. Normalize aliases and address origins before comparing. This replaces the reusable part of the old firmware migration audit; project-specific alias maps, constants and source-reference scanning are not imported as universal rules.

## Patch instruction-shape audit

```sh
python3 host/audit_patches.py module.elf patches.json > patch-report.json
python3 host/audit_patches.py module.elf patch-table.h --array selected_patch_array > patch-report.json
```

JSON patches are a nonempty list, for example:

```json
[{"offset": "0x120", "bytes": "eb"}]
```

C input requires an explicit array name and entries of the form `{0x120, "\xeb", 1}`. The declared length must equal the byte-string length; unsupported entries and overlapping patches are rejected. Offsets are relative to the lowest file-backed `PT_LOAD` address unless `--base` supplies a different origin.

The ELF reader requires little-endian x86-64 ELF64 (types 2, 3, or captured console type `0xfe10`) and checks header/segment bounds, file-backed overlap, address overflow and segment alignment. BSS and absent capture bytes cannot satisfy patch reads. Supported heuristics check complete short/near conditional-branch encodings and call-skip encodings. A one-byte jump over a six-byte near branch is a mismatch. A two-byte `eb04` replacement requires a six-byte near conditional branch, rather than accepting any short branch.

`shape_match` means only that the local encoding fits the recognized replacement pattern. Return stubs, padding, constants and arbitrary detours produce `manual_review`; they are never automatically certified. Branch destinations, incoming branches, function boundaries and runtime semantics still require analysis.

## Wrap a captured region as ELF

```sh
python3 host/wrap_dump.py kernel_text.bin kernel_text.elf \
  --base 0xffffffff8d640000 --anchor 0xffffffff8e300000
```

The wrapper writes an RX load segment containing every input byte. `--anchor` optionally adds an empty RW segment to record an external address; it supplies **no data bytes**. The output is an analysis image, not a runnable payload. The default segment alignment is 4096 bytes; `--alignment` accepts a power of two up to 1048576. File offsets are padded so the ELF alignment congruence holds even for an unaligned virtual address. Existing output files are refused.

## Exit codes and validation

Offset and patch audits return 0 when requested checks pass, 1 for unequal tables, failed signatures, patch mismatches or manual review, and 2 for invalid input. Offset inspection without signatures can return 0 while rows remain unverified; always read the report. Wrapping returns 0 on creation and 2 for invalid input or output errors.

Run synthetic tests with:

```sh
python3 -m unittest discover -s tests -p 'test_analysis_*.py'
```

Tests cover mapping boundaries, malformed and aligned ELF segments, strict table/patch parsing, unsupported expression rejection and known branch-shape errors. No console behavior is tested. Source paths and hashes are recorded in [analysis import provenance](analysis-imports.json).
