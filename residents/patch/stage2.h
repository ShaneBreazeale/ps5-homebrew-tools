/* SPDX-License-Identifier: GPL-3.0-or-later
 * Shared, inspection-only publication for a newly installed pinned resident.
 * Fits the pinned kstuff shared-area allocation without changing its mappings.
 */
#ifndef KERNEL_PATCH_STAGE2_H
#define KERNEL_PATCH_STAGE2_H
#include "bridge.h"
struct kp_stage2_store {
    uint32_t gate, revoked;
    struct kp_identity identity;
    uint64_t pmap, pml4, cr3;
    uint32_t completed_cpus, expected_cpus;
    unsigned char token[32];
};
_Static_assert(sizeof(struct kp_stage2_store) == 176, "stage 2 resident storage");
typedef int (*kp_stage2_read)(void *, uint64_t, void *, size_t);
static inline int kp_stage2_metadata_valid(const struct kp_stage2_store *s) {
    return s && kp_identity_valid(&s->identity) && s->identity.capabilities == KP_CAP_INSPECT
        && s->expected_cpus == 0xffff && s->completed_cpus == s->expected_cpus
        && kp_kernel(s->pmap) && !(s->pmap & 7) && s->pmap <= UINT64_MAX - 0x30
        && kp_kernel(s->pml4) && !(s->pml4 & 4095)
        && s->cr3 && s->cr3 < (UINT64_C(1) << 36) && !(s->cr3 & 4095)
        && kp_nonzero(s->token, sizeof(s->token));
}
static inline int kp_stage2_valid(const struct kp_stage2_store *s) {
    return kp_stage2_metadata_valid(s) && !s->gate && !s->revoked;
}
/* Called with private immutable initialization storage before publication, and
 * under the service gate for observation. Reads never change kernel mappings. */
static inline int kp_stage2_live(const struct kp_stage2_store *s, kp_stage2_read read, void *ctx) {
    static const unsigned char signature[7] = {0x4c,0x8d,0x2d,0xf7,0xc6,0x58,0x03};
    uint64_t pml4 = 0, cr3 = 0;
    unsigned char bytes[7] = {0};
    if (!kp_stage2_metadata_valid(s) || !read
            || (s->identity.firmware & 0xffff0000u) != 0x13600000u || s->identity.soc != 0x840fd0u
            || s->identity.data_base - s->identity.text_base != 0xcc0000u
            || s->identity.text_base > UINT64_MAX - 0x38fc19u
            || s->completed_cpus != 0xffff || s->expected_cpus != 0xffff
            || read(ctx, s->pmap + 0x20, &pml4, 8) || read(ctx, s->pmap + 0x28, &cr3, 8)
            || pml4 != s->pml4 || cr3 != s->cr3
            || read(ctx, s->identity.text_base + 0x38fc12u, bytes, sizeof(bytes))
            || memcmp(bytes, signature, sizeof(bytes))) return 0;
    return 1;
}
/* Stage 2 has no write engine: no cached mutation, applied mask or write caps.
 * Stage 3 must explicitly integrate a real kp_engine rather than upgrade this
 * publication or report a fabricated command history. */
static inline int kp_stage2_probe(struct kp_stage2_store *s, const struct kp_probe_request *q,
        kp_stage2_read read, void *ctx, struct kp_probe_reply *out) {
    if (!s || !q || !out || !read || !kp_probe_request_valid(q)) return KP_INVALID;
    uint32_t expected_gate = 0;
    if (!__atomic_compare_exchange_n(&s->gate, &expected_gate, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return KP_BUSY;
    struct kp_probe_reply r = {.abi = KP_ABI, .size = sizeof(r)};
    memcpy(r.challenge, q->challenge, 16);
    if (!kp_identity_valid(&s->identity)) { r.status = KP_INVALID; goto done; }
    if (memcmp(q->build, s->identity.build, 32)) { r.status = KP_STALE; goto done; }
    r.identity = s->identity;
    if (s->revoked) r.status = KP_POISONED;
    else if (!kp_stage2_live(s, read, ctx) || !kp_stage2_live(s, read, ctx)) {
        s->revoked = 1;
        r.status = KP_STALE;
    } else r.flags = KP_PROBE_CHECKED;
    r.poisoned = s->revoked != 0;
done:
    *out = r;
    __atomic_store_n(&s->gate, 0, __ATOMIC_RELEASE);
    return KP_OK;
}
#endif
