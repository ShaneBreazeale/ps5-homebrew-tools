# Contributing

Keep each tool independently buildable and document the firmware and ABI it
requires. Start with `templates/minimal-payload` for a small ELF payload.

For a new diagnostic:

1. Put its implementation under `payloads/<name>/` and add its build target.
2. Document its observable behavior, bounds, output, and compatibility.
3. Preserve imported notices and record source provenance when importing code.
4. Run `make check` (and `make native-check` for `tooling/native` changes) and
   compile the changed payload. Record console validation separately, including
   the actual binary checksum and firmware/model.

Use `host/` for computer-side capture and interpretation. Keep profile-specific
event meanings explicit rather than guessing a decoder from a marker alone.

Do not commit `out/`, local captures, SDK installations, kernel dumps, or console
binaries. Resident modifications belong in versioned upstream patches or a
dedicated fork once a reproducible baseline has been recovered.

## Document a tool

Add `payloads/<name>/README.md` beside its source. Include the build target,
root-relative command examples, firmware/model checks, required resident or SDK
features, output fields, completion/error markers, and interpretation limits.
Distinguish the payload's return value from the sender's transport status.

Link new guides from both the root README and [documentation index](docs/README.md).
Keep examples consistent with actual source constants and command-line options.
If a capability is archived or planned, label its status rather than describing
it as an available build target.

For documentation changes, check local links and documented `--help`/Make
commands. Avoid console execution merely to validate a prose change. Update
[compatibility notes](docs/COMPATIBILITY.md) when source changes alter assumptions.
