# Resident instrumentation experiments

These names identify experimental kstuff resident variants used during PS5 Pro
13.60 research. They are not independently loadable diagnostic tools or validated
launch fixes. None is built by the root Makefile.

| Profile | Instrumentation | Source status |
| --- | --- | --- |
| xlog | Post-handshake unmount events; historical ring overflowed | Documented; exact patch not recovered here |
| rdlog | First four post-flip read/readv/pread/preadv entries, without installing debug registers in that logging path | Original patch script archived; needs the drzero baseline |
| xin | `/app0/eboot.bin` pin and first in-scope game/PPR unmount | Original patch script archived; needs relemu3/drzero snapshots and other baseline files |
| xslot | xin instrumentation plus occupied count, packed scope kinds, and first PPR thread/state at the pin | Original patch script archived; same baseline recovery needed |
| xapp | xin instrumentation plus distinct appinfo copy status, pointer, and wire-flag action | Original patch script archived; same baseline recovery needed |

## Archived source

The [archive](archive/) contains original scripts as text. They use historical
absolute paths, restore files from `/tmp`, and can partially rewrite a source
tree before failing. They are not executable repository commands. Preserve them
for comparison while recovering a complete, versioned baseline in a dedicated
kstuff fork.

## Historical artifact identities

| Profile | Historical ELF SHA-256 |
| --- | --- |
| rdlog | `d5d90985a3edfa8b790cfb1faf48f25e5c6a43465e62868e2de890e7e9aeef0d` |
| xin | `10c8b3eaf34ca7b2b3c90f04ca0ac8da3429a7190e5ba1bccde647f48a55adff` |
| xslot | `40a1b1d1e109a378ac47164e93bd5f5be6f56681c5301cf431676afe6f146176` |
| xapp | `e4bff31eabd107cd98c02bcb8b4532726ffcf23a970c3138124e1f9dd85a87ba` |

The binaries are not included. The observed 13.60 launch failure remained after
these probes; the names identify measured experiments, not working fixes.

## Event decoding

Interpret event words using the profile that produced them:

| Event | Profile | Words following the marker |
| --- | --- | --- |
| `PPRRD001` | rdlog | kind in upper 32 bits and fd in lower 32; count; offset |
| `PPREXV01` | xin / xslot / xapp | Two words containing the eboot path |
| `PPRUMX01` | xin / xslot / xapp | Thread; whether pinned; scope kind |
| `PPRSCP01` | xslot | Occupied count; packed kinds; first PPR thread; state |
| `PPRWRF01` | xapp | Copy return code; appinfo pointer; action indicator |

Scope kinds are 2 for game unmount and 4 for PPR unmount. The xslot scope table
tracks in-flight wrapper entries, not mounted filesystem objects. For xapp,
copy status 0 and pointer 0 mean a successful copy of a null pointer. Its action
indicator 1 records an attempted flag write, not proof the write succeeded.

Other historical profiles reused markers with different fields. A future shared
logging API must version event schemas before combining those profiles.
