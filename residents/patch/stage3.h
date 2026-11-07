/* SPDX-License-Identifier: GPL-3.0-or-later
 * One resident-owned test cell. All callers share publication->gate. No client
 * address/bytes are accepted except the one exact EXERCISE policy below.
 */
#ifndef KP_STAGE3_H
#define KP_STAGE3_H
#include "stage2.h"
#define KP_STAGE3_QUERY_SELECTOR UINT32_C(0x4b500002)
#define KP_STAGE3_EXERCISE_SELECTOR UINT32_C(0x4b500003)
#define KP_STAGE3_QUERY_COMMAND UINT64_C(0x4b50000200000027)
#define KP_STAGE3_EXERCISE_COMMAND UINT64_C(0x4b50000300000027)
#define KP_STAGE3_BEFORE UINT64_C(0x3154534554504b)
#define KP_STAGE3_AFTER UINT64_C(0x3254534554504b)
_Static_assert(__atomic_always_lock_free(8, 0), "owned-cell atomics must be lock-free");
struct kp_stage3_journal {
    uint32_t stage, valid;
    struct kp_request request;
    struct kp_result result;
};
struct kp_stage3_store {
    uint32_t abi, size, lease, quarantined;
    uint64_t value;
    struct kp_engine engine;
    struct kp_stage3_journal journal[3];
};
struct kp_stage3_context {
    struct kp_stage2_store *publication;
    struct kp_stage3_store *store;
    kp_stage2_read live_read;
    void *live_context;
    uint64_t address;
};
/* Callback pointers are installed only while the outer cross-CPU gate is held,
 * then erased. Per-CPU uelf code and stack addresses must never persist. */
static inline int kp_s3_snapshot(void *opaque, struct kp_identity *out) {
    struct kp_stage3_context *c = opaque;
    if (!c->store->lease || c->store->quarantined || c->publication->revoked
            || !kp_stage2_live(c->publication, c->live_read, c->live_context)) {
        c->publication->revoked = 1;
        return -1;
    }
    *out = c->publication->identity;
    out->capabilities = KP_CAP_INSPECT | KP_CAP_TEST_DATA;
    out->resident_base = c->address;
    return 0;
}
static inline int kp_s3_acquire(void *opaque, struct kp_identity *out) {
    struct kp_stage3_context *c = opaque;
    uint32_t zero = 0;
    if (c->store->quarantined || !__atomic_compare_exchange_n(&c->store->lease, &zero, 1,
                0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return -1;
    if (!kp_s3_snapshot(c, out)) return 0;
    __atomic_store_n(&c->store->lease, 0, __ATOMIC_RELEASE);
    return -1;
}
static inline int kp_s3_mapping(void *opaque, uint64_t address, uint32_t length, uint32_t kind, int writing) {
    struct kp_stage3_context *c = opaque;
    (void)writing;
    return !c->store->lease || c->store->quarantined || address != c->address
        || length != 8 || kind != KP_TEST_DATA ? -1 : 0;
}
static inline int kp_s3_read(void *opaque, uint64_t address, void *out, size_t length, size_t *done) {
    struct kp_stage3_context *c = opaque;
    *done = 0;
    if (kp_s3_mapping(c, address, (uint32_t)length, KP_TEST_DATA, 0) || length != 8) return -1;
    uint64_t value = __atomic_load_n(&c->store->value, __ATOMIC_RELAXED);
    memcpy(out, &value, 8); *done = 8;
    return 0;
}
static inline int kp_s3_write(void *opaque, uint64_t address, const void *in, size_t length, size_t *done) {
    struct kp_stage3_context *c = opaque;
    *done = 0;
    if (kp_s3_mapping(c, address, (uint32_t)length, KP_TEST_DATA, 1) || length != 8) return -1;
    uint64_t value; memcpy(&value, in, 8);
    __atomic_store_n(&c->store->value, value, __ATOMIC_RELAXED);
    *done = 8;
    return 0;
}
static inline int kp_s3_save(void *opaque, unsigned stage, const struct kp_request *q, const struct kp_result *r) {
    struct kp_stage3_context *c = opaque;
    if (stage < KP_PREPARE || stage > KP_COMPLETE || q->sequence != 1) return -1;
    struct kp_stage3_journal *j = &c->store->journal[stage - 1];
    __atomic_store_n(&j->valid, 0, __ATOMIC_RELAXED);
    j->stage = stage; j->request = *q; j->result = *r;
    __atomic_store_n(&j->valid, 1, __ATOMIC_RELEASE);
    return 0;
}
static inline int kp_s3_finish(void *opaque, int quarantine) {
    struct kp_stage3_context *c = opaque;
    if (!c->store->lease) return -1;
    if (quarantine) c->store->quarantined = 1;
    __atomic_store_n(&c->store->lease, 0, __ATOMIC_RELEASE);
    return 0;
}
static inline void kp_s3_request(const struct kp_identity *id, struct kp_request *q) {
    *q = (struct kp_request){.abi = KP_ABI, .size = sizeof(*q), .operation = KP_EXERCISE,
        .kind = KP_TEST_DATA, .sequence = 1, .generation = id->generation, .anchor = KP_RESIDENT, .length = 8};
    memcpy(q->session, id->session, 16); memcpy(q->build, id->build, 32); memcpy(q->image, id->build, 32);
    uint64_t before = KP_STAGE3_BEFORE, after = KP_STAGE3_AFTER;
    memcpy(q->expected, &before, 8); memcpy(q->undo, &before, 8); memcpy(q->replacement, &after, 8);
}
/* Service return values follow kp_probe/kp_execute. Invalid requests, wrong
 * build/session, unsupported operations and a busy service never write the cell.
 * The sole accepted sequence is 1; exact replay returns the cached result.
 */
static inline int kp_stage3_service(struct kp_stage3_context *c, const struct kp_probe_request *query,
        const struct kp_request *command, struct kp_probe_reply *probe, struct kp_result *result) {
    if (!c || !c->publication || !c->store || !c->live_read || (!!query == !!command)
            || (query && (!probe || !kp_probe_request_valid(query))) || (command && !result)) return KP_INVALID;
    uint32_t zero = 0;
    if (!__atomic_compare_exchange_n(&c->publication->gate, &zero, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return KP_BUSY;
    struct kp_stage3_store *s = c->store;
    struct kp_identity identity = c->publication->identity;
    identity.capabilities = KP_CAP_INSPECT | KP_CAP_TEST_DATA; identity.resident_base = c->address;
    int rc = KP_INVALID;
    if (s->abi != KP_ABI || s->size != sizeof(*s) || !kp_identity_valid(&identity)
            || (c->address & 7) || (c->address & 4095) > 4088 || s->engine.gate) goto done;
    const unsigned char *build = query ? query->build : command->build;
    if (memcmp(build, identity.build, 32)) {
        if (query) { *probe = (struct kp_probe_reply){.abi=KP_ABI,.size=sizeof(*probe),.status=KP_STALE}; memcpy(probe->challenge,query->challenge,16); }
        else *result = (struct kp_result){.abi=KP_ABI,.size=sizeof(*result),.status=KP_STALE,.sequence=command->sequence};
        rc = KP_OK; goto done;
    }
    if (command) {
        struct kp_request expected; kp_s3_request(&identity, &expected);
        if (memcmp(command, &expected, sizeof(expected))) {
            *result = (struct kp_result){.abi=KP_ABI,.size=sizeof(*result),.status=KP_POLICY,.sequence=command->sequence};
            rc = KP_OK; goto done;
        }
    }
    struct kp_adapter adapter = {c, kp_s3_acquire, kp_s3_snapshot, kp_s3_mapping,
        kp_s3_read, kp_s3_write, kp_s3_save, kp_s3_finish};
    if (!s->engine.initialized) {
        struct kp_request q; kp_s3_request(&identity, &q);
        struct kp_policy policy = {.kind=KP_TEST_DATA,.anchor=KP_RESIDENT,.length=8,.alignment=8};
        memcpy(policy.image, identity.build, 32);
        memcpy(policy.expected, q.expected, KP_MAX_BYTES); memcpy(policy.replacement, q.replacement, KP_MAX_BYTES);
        if (kp_init(&s->engine, &identity, &policy, 1, &adapter)) goto done;
    }
    s->engine.adapter = adapter;
    if (s->quarantined || c->publication->revoked) s->engine.poisoned = 1;
    rc = query ? kp_probe(&s->engine, query, probe) : kp_execute(&s->engine, command, result);
    memset(&s->engine.adapter, 0, sizeof(s->engine.adapter));
    /* A diagnostic query must never clear quarantine or reinitialize history. */
    if (s->engine.poisoned) s->quarantined = 1;
done:
    __atomic_store_n(&c->publication->gate, 0, __ATOMIC_RELEASE);
    return rc;
}
#endif
