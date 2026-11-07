/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "stage3_client.h"
#include "kp_stage2_config.h"
struct kp_s3_call_result { uint64_t value; unsigned char failed; };
#ifdef KPS3_TRANSPORT_TEST
struct kp_s3_call_result kp_s3_call(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
#else
static struct kp_s3_call_result kp_s3_call(uint64_t a,uint64_t b,uint64_t c,uint64_t m,uint64_t reserved,uint64_t nr) {
    register uint64_t r8 __asm__("r8")=m, r9 __asm__("r9")=reserved;
    unsigned char failed;
    __asm__ volatile("syscall" : "+a"(nr), "=@ccc"(failed), "+r"(r8), "+r"(r9)
        : "D"(a), "S"(b), "d"(c) : "rcx","r11","memory");
    return (struct kp_s3_call_result){nr,failed};
}
#endif
static int kp_s3_exchange(void *unused, uint32_t selector, const void *q, size_t n, void *r, size_t m) {
    (void)unused;
    if (selector != KP_STAGE3_QUERY_SELECTOR && selector != KP_STAGE3_EXERCISE_SELECTOR) return -1;
    struct kp_s3_call_result result=kp_s3_call((uint64_t)(uintptr_t)q,n,(uint64_t)(uintptr_t)r,m,0,
        ((uint64_t)selector<<32)|0x27);
    return result.failed || result.value ? -1 : 0;
}
const struct kp_stage3_provider kp_stage3_provider={NULL,kp_s3_exchange,KPS2_BUILD_BYTES,KPS2_TOKEN_BYTES};
