/* SPDX-License-Identifier: GPL-3.0-or-later
 * Describe the existing 560-byte wire file exactly. Only its first 164 bytes
 * are available; all x87/SSE and legacy padding registers remain 'x'.
 */
#ifndef PROCESS_TARGET_DESCRIPTION_H
#define PROCESS_TARGET_DESCRIPTION_H
#define TD_REG(n,b,t) "<reg name=\"" #n "\" bitsize=\"" #b "\" type=\"" #t "\"/>"
static const char rsp_target_xml[] =
    "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
    "<target version=\"1.0\"><architecture>i386:x86-64</architecture><osabi>FreeBSD</osabi>"
    "<feature name=\"org.gnu.gdb.i386.core\">"
    TD_REG(rax,64,uint64) TD_REG(rbx,64,uint64) TD_REG(rcx,64,uint64) TD_REG(rdx,64,uint64)
    TD_REG(rsi,64,uint64) TD_REG(rdi,64,uint64) TD_REG(rbp,64,data_ptr) TD_REG(rsp,64,data_ptr)
    TD_REG(r8,64,uint64) TD_REG(r9,64,uint64) TD_REG(r10,64,uint64) TD_REG(r11,64,uint64)
    TD_REG(r12,64,uint64) TD_REG(r13,64,uint64) TD_REG(r14,64,uint64) TD_REG(r15,64,uint64)
    TD_REG(rip,64,code_ptr) TD_REG(eflags,32,uint32) TD_REG(cs,32,uint32) TD_REG(ss,32,uint32)
    TD_REG(ds,32,uint32) TD_REG(es,32,uint32) TD_REG(fs,32,uint32) TD_REG(gs,32,uint32)
    TD_REG(st0,80,i387_ext) TD_REG(st1,80,i387_ext) TD_REG(st2,80,i387_ext) TD_REG(st3,80,i387_ext)
    TD_REG(st4,80,i387_ext) TD_REG(st5,80,i387_ext) TD_REG(st6,80,i387_ext) TD_REG(st7,80,i387_ext)
    TD_REG(fctrl,32,uint32) TD_REG(fstat,32,uint32) TD_REG(ftag,32,uint32) TD_REG(fiseg,32,uint32)
    TD_REG(fioff,32,uint32) TD_REG(foseg,32,uint32) TD_REG(fooff,32,uint32) TD_REG(fop,32,uint32)
    "</feature><feature name=\"org.gnu.gdb.i386.sse\">"
    "<vector id=\"ps5_vec16\" type=\"uint8\" count=\"16\"/>"
    TD_REG(xmm0,128,ps5_vec16) TD_REG(xmm1,128,ps5_vec16) TD_REG(xmm2,128,ps5_vec16) TD_REG(xmm3,128,ps5_vec16)
    TD_REG(xmm4,128,ps5_vec16) TD_REG(xmm5,128,ps5_vec16) TD_REG(xmm6,128,ps5_vec16) TD_REG(xmm7,128,ps5_vec16)
    TD_REG(xmm8,128,ps5_vec16) TD_REG(xmm9,128,ps5_vec16) TD_REG(xmm10,128,ps5_vec16) TD_REG(xmm11,128,ps5_vec16)
    TD_REG(xmm12,128,ps5_vec16) TD_REG(xmm13,128,ps5_vec16) TD_REG(xmm14,128,ps5_vec16) TD_REG(xmm15,128,ps5_vec16)
    TD_REG(mxcsr,32,uint32)
    "</feature><feature name=\"org.ps5.legacy_padding\">"
    TD_REG(legacy_pad0,32,uint32) TD_REG(legacy_pad1,32,uint32) TD_REG(legacy_pad2,32,uint32)
    TD_REG(legacy_pad3,32,uint32) TD_REG(legacy_pad4,32,uint32) TD_REG(legacy_pad5,32,uint32)
    "</feature></target>";
#undef TD_REG
#endif
