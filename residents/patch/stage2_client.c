/* SPDX-License-Identifier: GPL-3.0-or-later
 * Explicitly linked only with a private config from the pinned overlay builder.
 */
#include "stage2_client.h"
#include "kp_stage2_config.h"
struct kp_s2_call_result { uint64_t value; unsigned char failed; };
#ifdef KPS2_TRANSPORT_TEST
struct kp_s2_call_result kp_s2_call(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
#else
#if !defined(__x86_64__)
#error "stage 2 kstuff transport requires x86-64"
#endif
static struct kp_s2_call_result kp_s2_call(uint64_t a, uint64_t b, uint64_t c,
        uint64_t e, uint64_t f, uint64_t nr) {
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    unsigned char failed;
    /* The intercepted frame prefix contains RDI/RSI/RDX/R8/R9, not R10. */
    __asm__ volatile("syscall" : "+a"(nr), "=@ccc"(failed), "+r"(r8), "+r"(r9)
                     : "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return (struct kp_s2_call_result){nr, failed};
}
#endif
static int kp_s2_exchange(void *unused, const struct kp_bridge_request *request, struct kp_probe_reply *reply) {
    (void)unused;
    if (!request || !reply || request->abi != KP_ABI || request->size != sizeof(*request)
            || !kp_probe_request_valid(&request->query)) return -1;
    memset(reply, 0, sizeof(*reply));
    struct kp_s2_call_result result = kp_s2_call((uint64_t)(uintptr_t)request, sizeof(*request),
        (uint64_t)(uintptr_t)reply, sizeof(*reply), 0, KP_BRIDGE_COMMAND);
    /* Old residents may fall through to getppid. No return/error proves absence. */
    return result.failed || result.value ? -1 : 0;
}
const struct kp_stage2_provider kp_stage2_provider = {NULL, kp_s2_exchange, KPS2_BUILD_BYTES, KPS2_TOKEN_BYTES};
