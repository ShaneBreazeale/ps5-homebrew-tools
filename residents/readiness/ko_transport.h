/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef KO_TRANSPORT_H
#define KO_TRANSPORT_H
#include <stdint.h>
#define KO_KEK_SELECTOR UINT32_C(0x4b4f0001)
#define KO_KEK_COMMAND UINT64_C(0x4b4f000100000027)
/* getppid's intercepted frame includes RDI, RSI, RDX, R8, R9; not R10.
 * RDI=request, RSI=48, RDX=reply, R8=160, R9=0. */
struct ko_call_result { uint64_t value; unsigned char failed; };
#ifdef KO_TRANSPORT_TEST
struct ko_call_result ko_kstuff_call(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
#else
#if !defined(__x86_64__)
#error "kstuff readiness transport requires x86-64"
#endif
static inline struct ko_call_result ko_kstuff_call(uint64_t a, uint64_t b, uint64_t c,
        uint64_t d, uint64_t e, uint64_t f, uint64_t nr) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    unsigned char failed;
    __asm__ volatile("syscall" : "+a"(nr), "=@ccc"(failed), "+r"(r10), "+r"(r8), "+r"(r9)
                     : "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return (struct ko_call_result){nr, failed};
}
#endif
#endif
