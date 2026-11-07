/* SPDX-License-Identifier: GPL-3.0-or-later
 * Host-only memory backend. No addresses are dereferenced outside bytes[].
 * Its journal is an in-memory simulation, not durable console evidence.
 */
#ifndef KERNEL_PATCH_SIM_H
#define KERNEL_PATCH_SIM_H
#include "../residents/patch/patch.h"

enum kp_sim_fault { KS_NONE, KS_ORIGINAL, KS_PARTIAL, KS_WRITE, KS_READBACK,
    KS_RESTORE, KS_STALE_BEFORE, KS_STALE_AFTER, KS_PREPARE, KS_OUTCOME,
    KS_COMPLETE, KS_MAPPING, KS_SHORT_READ, KS_READ, KS_ACQUIRE, KS_RELEASE };
struct kp_sim {
    struct kp_identity identity;
    uint64_t address;
    unsigned char bytes[KP_MAX_BYTES];
    unsigned length, fault, held, quarantined, acquires, snapshots, mappings, reads, writes, saves, finishes;
    unsigned outcomes, stages[8], journal_count;
    struct kp_result journal[8];
    struct kp_engine *reenter;
    const struct kp_request *reenter_request;
};
static int ks_acquire(void *ctx, struct kp_identity *id) {
    struct kp_sim *s = ctx;
    ++s->acquires;
    if (s->held || s->fault == KS_ACQUIRE) return -71;
    s->held = 1;
    *id = s->identity;
    if (s->fault == KS_STALE_BEFORE) ++id->generation;
    return 0;
}
static int ks_snapshot(void *ctx, struct kp_identity *id) {
    struct kp_sim *s = ctx;
    ++s->snapshots;
    if (!s->held) return -72;
    *id = s->identity;
    if (s->fault == KS_STALE_AFTER && s->writes) ++id->generation;
    return 0;
}
static int ks_mapping(void *ctx, uint64_t address, uint32_t length, uint32_t kind, int mutating) {
    struct kp_sim *s = ctx;
    (void)kind; (void)mutating;
    ++s->mappings;
    if (!s->held || s->fault == KS_MAPPING || address != s->address || length != s->length) return -73;
    return 0;
}
static int ks_read(void *ctx, uint64_t address, void *out, size_t length, size_t *done) {
    struct kp_sim *s = ctx;
    ++s->reads;
    *done = 0;
    if (!s->held || address != s->address || length != s->length || s->fault == KS_READ) return -74;
    if (s->fault == KS_READBACK && s->reads == 2) s->bytes[0] ^= 0xff;
    *done = s->fault == KS_SHORT_READ && s->reads == 1 ? length - 1 : length;
    memcpy(out, s->bytes, *done);
    return 0;
}
static int ks_write(void *ctx, uint64_t address, const void *data, size_t length, size_t *done) {
    struct kp_sim *s = ctx;
    ++s->writes;
    *done = 0;
    if (!s->held || address != s->address || length != s->length) return -75;
    if (s->reenter) {
        struct kp_result untouched;
        memset(&untouched, 0xa5, sizeof(untouched));
        if (kp_execute(s->reenter, s->reenter_request, &untouched) != KP_BUSY
                || untouched.abi != UINT32_C(0xa5a5a5a5)) return -76;
    }
    if (s->fault == KS_RESTORE && s->writes == 2) return -81;
    if ((s->fault == KS_PARTIAL || s->fault == KS_RESTORE) && s->writes == 1) {
        *done = length / 2;
        memcpy(s->bytes, data, *done);
        return 0;
    }
    memcpy(s->bytes, data, length);
    *done = length;
    /* A failed setter may have already written every byte. Still restore. */
    return s->fault == KS_WRITE && s->writes == 1 ? -77 : 0;
}
static int ks_save(void *ctx, unsigned stage, const struct kp_request *q, const struct kp_result *r) {
    struct kp_sim *s = ctx;
    (void)q;
    ++s->saves;
    if (stage == KP_OUTCOME) ++s->outcomes;
    if (s->journal_count < 8) {
        s->stages[s->journal_count] = stage;
        s->journal[s->journal_count++] = *r;
    }
    if ((stage == KP_PREPARE && s->fault == KS_PREPARE)
            || (stage == KP_OUTCOME && s->fault == KS_OUTCOME && s->outcomes == 1)
            || (stage == KP_COMPLETE && s->fault == KS_COMPLETE)) return -78;
    return 0;
}
static int ks_finish(void *ctx, int quarantine) {
    struct kp_sim *s = ctx;
    ++s->finishes;
    s->quarantined = (unsigned)quarantine;
    s->held = 0; /* host service mutex only; quarantined models retained target protection */
    return s->fault == KS_RELEASE ? -79 : 0;
}
static inline struct kp_adapter ks_adapter(struct kp_sim *s) {
    return (struct kp_adapter){s, ks_acquire, ks_snapshot, ks_mapping, ks_read, ks_write, ks_save, ks_finish};
}
#endif
