# Context7 and LLM documentation

Context7 indexes this repository's maintained guides for coding agents.
The library ID **`/shanebreazeale/ps5-homebrew-tools`** was returned by
`resolve-library-id` on 2026-10-18. That confirms an existing listing; it does
not prove this working tree's new debugger docs have been indexed or refreshed.
Published/indexed versions can lag behind current source and validation notes.

The root [context7.json](../context7.json) selects `docs/`, `host/`, `payloads/`
and `templates/`. Root Markdown, including [AGENTS.md](../AGENTS.md), is included
by Context7's documented indexing behavior. `rules` communicates operational
limits. Generated binaries/captures, research archives, tests, vendor code and
native implementation files are excluded. Indexing docs is not console validation.

## Retrieve documentation for a debugging task

Start by resolving the library name with the actual question:

```json
{
  "libraryName": "ShaneBreazeale/ps5-homebrew-tools",
  "query": "Use the process debugger from an LLM CLI: current 13.60 limits, offline recovery, authorized PID attachment, logging and cleanup."
}
```

After confirming the returned ID/version, query the matching topic. Example
`query-docs` inputs (requests to the MCP tool, not shell commands):

```json
{
  "libraryId": "/shanebreazeale/ps5-homebrew-tools",
  "query": "What are the current process-debugger capability and recovery limits? Distinguish kernel offset 0xcfc12, title IDs, occupied kstuff DR slots, and the retired kernel-dbregs fallback."
}
```

```json
{
  "libraryId": "/shanebreazeale/ps5-homebrew-tools",
  "query": "How should an LLM run a bounded GDB CLI or GDB/MI inspection with this server, log evidence, handle stop notifications, and detach without assuming cleanup succeeded?"
}
```

```json
{
  "libraryId": "/shanebreazeale/ps5-homebrew-tools",
  "query": "Which RSP packets, GP register indices, memory sizes, thread identifiers, resume forms and error codes does process-debugger implement?"
}
```

If a query returns older guidance suggesting a PCB fallback, do not use it.
Read the current source and local Markdown and report the indexing mismatch.
The former build flag is retired; Z2/Z4 remain disabled on retail 13.60. The
server does not become a kernel debugger because a generic GDB guide supports
kernel targets.

## Recommended reading map

| Task | Repository documentation |
| --- | --- |
| Establish actual session state | [Recovery and kernel scope](DEBUGGER_RECOVERY.md) |
| Know what was tested | [Debugger validation](DEBUGGER_VALIDATION.md) |
| Human CLI operation | [Debugger CLI runbook](DEBUGGER.md) |
| LLM/agent controlling GDB | [Agent contract and MI](DEBUGGER_AGENTS.md) and [AGENTS.md](../AGENTS.md) |
| Packet syntax and runtime limits | [Protocol reference](DEBUGGER_PROTOCOL.md) |
| Local GDB defaults | [Compatibility profile](debugger/compat.gdb); settings only, no connection |
| SDK/LLVM 18 build | [Building](BUILDING.md), including gpubox paths in validation |
| Other collectors / captures | [Tool index](README.md), [capture tools](CAPTURE_TOOLS.md) |
| Resident event decoding | [Log tools](LOG_TOOLS.md) and the exact producing profile |
| Kernel readiness and fallback | [Versioned provider and legacy policy](KERNEL_READINESS.md) |
| Kernel offsets and inspection phase | [Kernel backend](KERNEL_DEBUGGER.md); no execution adapter yet |
| Offset/patch/dump analysis | [Analysis tools](ANALYSIS_TOOLS.md) |
| Native app build | [Native app](NATIVE_APP.md) |

For external GDB CLI/MI syntax, resolve **GNU GDB** separately and use official
GDB documentation. For SDK APIs, resolve the public PS5 Payload SDK and inspect
its documented samples/source when indexing is insufficient. Generic upstream
docs explain syntax; this repository's packet table and validation record
limit what the particular server supports.

## Copyable task brief for an LLM

```text
Use the current PS5 Homebrew Tools docs, not generic gdbserver assumptions.
Read recovery, validation, CLI, agent and protocol guides first. Report which
capabilities are implemented, host-tested and console-tested for this exact ELF.
Use the existing authorization for the named target/session; request only
missing facts. Do not deploy to the recorded offline console or infer a PID
from a title. Use one RSP client, fresh logs and bounded steps/resumes.
For kernel offset work, retrieve `KERNEL_DEBUGGER.md`: the new `kernel-offset`
backend implements explicit anchor resolution and bounded byte inspection only.
`exec+0xcfc12` is `text+0x38fc12` / `data-0x9303ee` in the checked capture.
It does not yet provide a kernel trap or step command.

Preserve kstuff's DR slots. No retired PCB fallback and no kernel-offset trap
through this usermode server. Record observed replies and unknown cleanup state.
```

## Publish and refresh

Commit/publish the maintained docs and config through the normal repository
workflow, then use [Context7's library owner/indexing workflow](https://github.com/upstash/context7/blob/master/docs/library-owners.mdx)
to request a refresh for the repository's listing. If it needs to be added anew,
use [Add Library](https://context7.com/add-library) with the repository URL:

```text
https://github.com/ShaneBreazeale/ps5-homebrew-tools
```

Do not claim a refresh was submitted or completed merely because files changed
or a push succeeded. Verify indexed results include the new capability limits
and links after refresh. Do not upload private captures, credentials, kernel
dumps or raw session transcripts to Context7. No indexing refresh is performed
by editing this file.

Config field reference: [Context7 library-owner documentation](https://github.com/upstash/context7/blob/master/docs/library-owners.mdx)
and [configuration schema](https://context7.com/schema/context7.json).
