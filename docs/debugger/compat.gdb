# Local GDB settings only: this file never connects or resumes a process.
# Source from the repository root before connecting. See docs/DEBUGGER.md.
set pagination off
set architecture i386:x86-64
set non-stop off
set remotetimeout 10
set tcp auto-retry off
set tcp connect-timeout 5
set remote verbose-resume-packet off
set remote interrupt-sequence Ctrl-C
set remote memory-read-packet-size 256
set remote memory-write-packet-size 256
set remote hardware-breakpoint-limit 4
set remote hardware-watchpoint-limit 0
# `break` uses Z0 (INT3). `hbreak` uses Z1 and needs a free DR slot.
