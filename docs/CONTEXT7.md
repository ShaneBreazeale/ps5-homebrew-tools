# Context7 guide

Context7 can index this repository's Markdown documentation so coding agents can
find commands, examples, and compatibility limits by tool name. The root
[`context7.json`](../context7.json) points it at the maintained guides in
`docs/`, `host/`, `payloads/`, and `templates/`. Root-level Markdown, including
the README, is indexed as well. Historical resident archives, vendored headers,
tests, and native toolchain implementation files are outside the configured
folders; source files are not the primary documentation for these tools.

## Add the public repository

Open [Context7's Add Library page](https://context7.com/add-library), choose
GitHub, and submit:

```text
https://github.com/ShaneBreazeale/ps5-homebrew-tools
```

Context7 assigns a library ID in `/org/project` form after indexing. Confirm the
actual ID on its library page before citing it; adding `context7.json` to GitHub
does not itself submit or claim the library. Maintainers can request a refresh
through Context7 after documentation changes are published.

## What to look up

| Need | Documentation |
| --- | --- |
| First payload build and capture | [Getting started](GETTING_STARTED.md) and [building](BUILDING.md) |
| Firmware and console boundaries | [Compatibility](COMPATIBILITY.md) and [validation](VALIDATION.md) |
| Process and thread diagnostics | [Tool index](README.md) and the linked payload guides |
| Kernel capture transfer | [Capture tools](CAPTURE_TOOLS.md) |
| Resident event decoding and comparison | [Log tools](LOG_TOOLS.md) |
| Offset, patch, and dump inspection | [Analysis tools](ANALYSIS_TOOLS.md) |
| Native app folder and ZIP | [Native app](NATIVE_APP.md) |

For example, ask an agent to use this repository's Context7 docs to find the
command for decoding a resident snapshot with the matching event profile, or to
check which firmware and instrumentation the kernel collector requires. Specify
the exact payload or profile where possible. Some event markers were reused
across historical resident variants, so the profile name matters.

These docs describe local build and host checks separately from console tests.
The imported payloads and native starter were built locally, but the new builds
have not been validated on a console. Raw capture logs, kernel dumps, and build
outputs are not committed to this repository or indexed as docs.
