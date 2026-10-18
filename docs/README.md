# Documentation

Use [Getting started](GETTING_STARTED.md) for the first build and capture.
Commands in the guides run from the repository root unless stated otherwise.

## Run the tools

| Guide | Use it to |
| --- | --- |
| [Build reference](BUILDING.md) | Configure the SDK and select Make targets |
| [Host utilities](../host/README.md) | Send once, preserve output, and summarize v2 captures |
| [Shellshot](../payloads/shellshot/README.md) | Take one filtered process snapshot |
| [Procwatch](../payloads/procwatch/README.md) | Watch process changes during an app launch |
| [Reader3](../payloads/reader3/README.md) | Read matching resident counters and event rings |
| [Thread probe v1](../payloads/thread-probe-v1/README.md) | Inspect raw sysctl records and selector availability |
| [Thread probe v2](../payloads/thread-probe-v2/README.md) | Capture selected processes' kernel thread records |
| [Troubleshooting](TROUBLESHOOTING.md) | Interpret setup failures and incomplete output |

## Understand and extend the repository

- [Architecture](ARCHITECTURE.md): component boundaries and capture flow.
- [Compatibility](COMPATIBILITY.md): supported baseline and interpretation limits.
- [Minimal payload](../templates/minimal-payload/README.md): start a new ELF tool.
- [Resident experiments](../residents/README.md): historical profiles and event fields.
- [Contributing](../CONTRIBUTING.md): add tools and record verification.
- [Provenance](PROVENANCE.md) and [import manifest](imports.json): source identities.
- [Initial validation](VALIDATION.md): what was actually built and tested.
- [Third-party notices](../THIRD_PARTY_NOTICES.md): imported code and license notices.
