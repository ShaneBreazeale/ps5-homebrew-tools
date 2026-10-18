# Contributing

Keep each tool independently buildable and document the firmware and ABI it
requires. Start with `templates/minimal-payload` for a small ELF payload.

For a new diagnostic:

1. Put its implementation under `payloads/<name>/` and add its build target.
2. Document its observable behavior, bounds, output, and compatibility.
3. Preserve imported notices and record source provenance when importing code.
4. Run `make check` and compile the changed payload. Record console validation
   separately, including the actual binary checksum and firmware/model.

Use `host/` for computer-side capture and interpretation. Keep profile-specific
event meanings explicit rather than guessing a decoder from a marker alone.

Do not commit `out/`, local captures, SDK installations, kernel dumps, or console
binaries. Resident modifications belong in versioned upstream patches or a
dedicated fork once a reproducible baseline has been recovered.
