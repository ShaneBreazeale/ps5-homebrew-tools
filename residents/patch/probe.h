/* SPDX-License-Identifier: GPL-3.0-or-later
 * Read-only identity/state exchange for the patch service. Same service gate
 * as mutations; no guessed syscall, user pointer, transport or kernel entry.
 */
#ifndef KERNEL_PATCH_PROBE_H
#define KERNEL_PATCH_PROBE_H
#include "patch.h"
#define KP_PROBE_QUERY 1u
#define KP_PROBE_CHECKED 1u
#define KP_PROBE_HAS_LAST 2u
struct kp_probe_request {
    uint32_t abi, size, operation, reserved;
    unsigned char challenge[16], build[32];
};
struct kp_probe_reply {
    uint32_t abi, size, status, flags;
    unsigned char challenge[16];
    struct kp_identity identity;
    uint64_t sequence;
    uint32_t applied_mask, poisoned;
    struct kp_request last_request;
    struct kp_result last_result;
};
_Static_assert(sizeof(struct kp_probe_request) == 64, "patch probe request ABI");
_Static_assert(sizeof(struct kp_probe_reply) == 720, "patch probe reply ABI");

static inline int kp_probe_request_valid(const struct kp_probe_request *q) {
    return q && q->abi == KP_ABI && q->size == sizeof(*q)
        && q->operation == KP_PROBE_QUERY && !q->reserved
        && kp_nonzero(q->challenge, 16) && kp_nonzero(q->build, 32);
}
/* KP_BUSY leaves out untouched. All other replies have an operation status.
 * CHECKED is set only after real adapter identity checks and lease finish.
 * identity without CHECKED is the pinned, recorded identity, not live readiness.
 * A poisoned engine remains diagnosable without reacquiring its target lease.
 * Probing does not consume sequence numbers, save journals or replay commands.
 */
static inline int kp_probe(struct kp_engine *e, const struct kp_probe_request *input,
        struct kp_probe_reply *out) {
    if (!e || !input || !out) return KP_INVALID;
    uint32_t expected_gate = 0;
    if (!__atomic_compare_exchange_n(&e->gate, &expected_gate, 1, 0,
            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return KP_BUSY;
    struct kp_probe_request q = *input;
    struct kp_probe_reply r = {.abi = KP_ABI, .size = sizeof(r)};
    int held = 0;
    if (!kp_probe_request_valid(&q)) { r.status = KP_INVALID; goto done; }
    memcpy(r.challenge, q.challenge, sizeof(r.challenge));
    if (!e->initialized) { r.status = KP_INVALID; goto done; }
    /* Do not disclose a different build's cached memory to a mismatched client. */
    if (memcmp(q.build, e->identity.build, sizeof(q.build))) { r.status = KP_STALE; goto done; }
    r.identity = e->identity;
    r.sequence = e->sequence;
    r.applied_mask = e->applied_mask;
    if (e->sequence) {
        r.flags |= KP_PROBE_HAS_LAST;
        r.last_request = e->last_request;
        r.last_result = e->last_result;
    }
    if (e->poisoned) { r.status = KP_POISONED; goto state; }
    struct kp_identity observed = {0};
    if (e->adapter.acquire(e->adapter.context, &observed)) { r.status = KP_ACQUIRE; goto state; }
    held = 1;
    if (!kp_same_identity(e, &observed)) { r.status = KP_STALE; e->poisoned = 1; goto finish; }
    memset(&observed, 0, sizeof(observed));
    if (e->adapter.snapshot(e->adapter.context, &observed) || !kp_same_identity(e, &observed)) {
        r.status = KP_STALE;
        e->poisoned = 1;
    }
finish:
    if (held && e->adapter.finish(e->adapter.context, e->poisoned)) {
        r.status = KP_RELEASE;
        e->poisoned = 1;
    }
    if (!r.status && !e->poisoned) r.flags |= KP_PROBE_CHECKED;
state:
    r.poisoned = e->poisoned != 0;
done:
    *out = r;
    __atomic_store_n(&e->gate, 0, __ATOMIC_RELEASE);
    return KP_OK;
}
#endif
