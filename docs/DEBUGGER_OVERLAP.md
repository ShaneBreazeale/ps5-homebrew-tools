# ps5debug-NG overlap and attachment-context research

This review uses ps5debug-NG commit
[`938d1a735018073844dc2d8f69fea25f2a8aaa4b`](https://github.com/Pharaoh2k/ps5debug-NG/tree/938d1a735018073844dc2d8f69fea25f2a8aaa4b).
It informed the changes below. No ps5debug-NG implementation or patched SDK was
imported into this repository, and no console was contacted for this work.

| Shared area | Implemented here | Evidence boundary |
| --- | --- | --- |
| Target operations | Typed provider API, independent RSP adapter | Provider-only and fake-provider host tests |
| Memory writes | One verified transaction for ordinary writes, breakpoint planting/removal, step-over and detach restoration | Fault injection; no new console test |
| Process identity | Name, parent PID, start timestamp, optional executable path and app/title metadata | Checked 13.60 sysctl record decoder; optional fields marked explicitly |
| Maps | Bounded SDK-format sysctl query, ranges/offsets/permissions/names, truncation and snapshot fingerprint | Selector/layout support remains unvalidated on console; errors are returned without a kernel fallback |
| Module addresses | Explicit basename lookup through SDK dynlib helpers; handle, map base and entry | SDK build and mocks; no automatic ELF identity or load-bias proof |
| Register coverage | Read-only FS/GS bases and size-reported XSAVE image through ptrace | Host tests and SDK build; runtime availability unknown |
| Runtime identity | Source/LLVM fingerprint, firmware/server PID, implemented-operation mask and limits | Source fingerprint is not the final ELF hash or proof of target readiness |
| Attachment context | Source study and an explicit validation plan below | No new hosting, injection or policy patch implementation |

The existing GDB GP register layout remains compatible. New inspections use the
[custom packets](DEBUGGER_PROTOCOL.md#read-only-discovery-packets). They do not
provide a ps5debug-compatible server, kernel debugger, or additional DR slots.

## Why ShellCore hosting matters to investigate

Their [architecture description](https://github.com/Pharaoh2k/ps5debug-NG/blob/938d1a735018073844dc2d8f69fea25f2a8aaa4b/README.md#architecture)
attributes game attachment behavior to the debugger executing inside SceShellCore
and PS5 AppContext policy. Their
[installer](https://github.com/Pharaoh2k/ps5debug-NG/blob/938d1a735018073844dc2d8f69fea25f2a8aaa4b/installer/source/main.c)
finds ShellCore, attempts a kernel attach-policy patch, unlocks its syscall
filter, and injects the inner debugger there. These are multiple simultaneous
changes. Source inspection alone cannot isolate hosting as the reason a game
continues successfully, establish portability to our firmware/resident, or prove
a standalone attach is safe here.

Our debugger runs as a standalone SDK payload and temporarily elevates caller
credentials around ptrace/signal syscalls. That does not establish equivalent
AppContext, syscall-origin policy, or behavior inside an SCE process. Historical
success attaching our own disposable child does not test this difference.
The runtime capability reply identifies `hosting:standalone` and the server PID;
it never advertises arbitrary-game compatibility.

A future separately established research session should record the same target's
numeric PID, name/start/title, firmware/model/resident, host process identity,
exact server ELF/source identity and authorization. Compare child attachment
with an explicitly permitted disposable application using bounded inspection,
one instruction step and explicit detach, recording whether execution progresses
after cleanup. Any comparison involving different hosting or policy changes needs
its own reviewed implementation, isolated session and restoration evidence.
Keep observed errors, stops and lifetime changes rather than substituting another
system PID. No injection or kernel-policy experiment is performed automatically.

## Why the FP sizes differ

The staged SDK's FreeBSD-derived `struct fpreg` is 512 bytes: the legacy
x87/SSE image, including 16 XMM registers. ps5debug-NG sets its wire FP buffer to
832 bytes (`0x340`) and normally
[copies that amount from the PCB's saved-FPU pointer](https://github.com/Pharaoh2k/ps5debug-NG/blob/938d1a735018073844dc2d8f69fea25f2a8aaa4b/debugger/source/kern_dbreg.c#L170-L185).
832 matches an AVX XSAVE image comprising 512 legacy bytes, a 64-byte XSAVE
header and 256 upper-YMM bytes. This is a layout inference consistent with
[FreeBSD's savefpu_ymm declaration](https://github.com/freebsd/freebsd-src/blob/releng/11.4/sys/x86/include/fpu.h),
not validation of the PS5 saved image. A public ptrace structure and an internal
kernel save area need not expose the same extent of state.

Their [FP handler](https://github.com/Pharaoh2k/ps5debug-NG/blob/938d1a735018073844dc2d8f69fea25f2a8aaa4b/debugger/source/debug.c#L1020-L1043)
also falls back to PT_GETFPREGS after zeroing the larger buffer. If that syscall
returns only the legacy structure, the remaining bytes can be padding rather
than observed AVX state; the wire length alone cannot establish coverage.

We query `PT_GETXSTATE_INFO` for its reported length and feature mask, then read
`PT_GETXSTATE` only when the image fits the 4,096-byte inspection limit. FS/GS
bases use their separate ptrace getter requests. These declarations are present
in the supplied SDK; that does not prove Sony implements them on this console.
An unsupported or malformed result remains an error. We do not use PT_GETFPREGS's
unsized firmware-dependent blob, read/write PCBs, or add extended-register writes.
