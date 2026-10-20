/* SPDX-License-Identifier: GPL-3.0-or-later
 * Producer helpers, called under the resident's own appropriate lock.
 * No trap installation and no assumption that C atomics replace kernel locks.
 */
#ifndef KO_READINESS_PRODUCER_H
#define KO_READINESS_PRODUCER_H
#include "readiness.h"
struct ko_ready_producer { struct ko_ready_reply record; };
typedef int (*ko_cookie_write_fn)(void *, uint64_t);
/* The producer object must initially be zero-initialized.
 * Begin a new producer session. The caller supplies a fresh random session ID
 * and observed environment, with state/capabilities/completion initially zero.
 * Clear a legacy marker BEFORE starting initialization, if one is maintained.
 */
static inline int ko_producer_begin(struct ko_ready_producer *producer,
        const struct ko_ready_reply *identity, ko_cookie_write_fn legacy_write, void *ctx) {
    if (!producer || !identity || !ko_nonzero(identity->session, sizeof(identity->session))
        || !ko_nonzero(identity->build_id, sizeof(identity->build_id))
        || !identity->expected_cpus || (identity->expected_cpus & ~KO_CPU_MASK)
        || !memcmp(producer->record.session, identity->session, sizeof(identity->session))) return -1;
    struct ko_ready_reply next = *identity;
    if (legacy_write && legacy_write(ctx, 0)) return -1;
    memset(producer, 0, sizeof(*producer));
    producer->record = next;
    producer->record.abi_version = KO_READY_ABI;
    producer->record.record_size = sizeof(producer->record);
    memset(producer->record.challenge, 0, sizeof(producer->record.challenge));
    memset(producer->record.reserved, 0, sizeof(producer->record.reserved));
    producer->record.generation = 1;
    producer->record.capabilities = 0;
    producer->record.completed_cpus = 0;
    producer->record.state = KO_INITIALIZING;
    return 0;
}
static inline int ko_producer_cpu_complete(struct ko_ready_producer *producer, unsigned cpu) {
    if (!producer || producer->record.generation == UINT64_MAX
        || producer->record.state != KO_INITIALIZING || cpu >= 16
        || !(producer->record.expected_cpus & (UINT32_C(1) << cpu))
        || (producer->record.completed_cpus & (UINT32_C(1) << cpu))) return -1;
    producer->record.completed_cpus |= UINT32_C(1) << cpu;
    ++producer->record.generation;
    return 0;
}
/* Invoke only after actual prerequisites and hook cleanup have completed.
 * No readiness or cookie is published when a CPU or cleanup is incomplete.
 */
static inline int ko_producer_finish(struct ko_ready_producer *producer, uint32_t active_hooks,
        ko_cookie_write_fn legacy_write, void *ctx, uint64_t completion_cookie) {
    if (!producer) return -1;
    struct ko_ready_reply *r = &producer->record;
    if (r->state != KO_INITIALIZING || r->generation == UINT64_MAX || !r->expected_cpus
        || (legacy_write && !completion_cookie)
        || r->completed_cpus != r->expected_cpus || active_hooks) return -1;
    r->active_hooks = 0;
    if (legacy_write && legacy_write(ctx, completion_cookie)) {
        r->state = KO_FAILED;
        ++r->generation;
        return -1;
    }
    r->capabilities = KO_CAP_INSPECT;
    r->state = KO_READY;
    ++r->generation;
    return 0;
}
/* Invalidate under the same lock before changing any initialized state.
 * Failure to clear the legacy marker must abort that change, not proceed.
 */
static inline int ko_producer_invalidate(struct ko_ready_producer *producer,
        ko_cookie_write_fn legacy_write, void *ctx) {
    if (!producer) return -1;
    producer->record.state = KO_FAILED;
    producer->record.capabilities = 0;
    if (producer->record.generation != UINT64_MAX) ++producer->record.generation;
    return legacy_write ? legacy_write(ctx, 0) : 0;
}
static inline enum ko_query_result ko_producer_exchange(void *ctx,
        const struct ko_ready_request *request, struct ko_ready_reply *reply) {
    struct ko_ready_producer *producer = ctx;
    if (!producer || !request || !reply || request->abi_version != KO_READY_ABI
        || request->record_size != sizeof(*request)
        || !ko_nonzero(request->challenge, sizeof(request->challenge))) return KO_QUERY_ERROR;
    /* Return initializing/failed records too: they must not look unavailable. */
    *reply = producer->record;
    memcpy(reply->challenge, request->challenge, sizeof(reply->challenge));
    return KO_QUERY_OK;
}
#endif
