/* SPDX-License-Identifier: GPL-3.0-or-later
 * Portable bounded kernel patch service. No kernel entry, I/O or SDK calls.
 * Adapter callbacks must be bounded and resident-safe. See KERNEL_PATCH_TOOLKIT.md.
 */
#ifndef KERNEL_PATCH_H
#define KERNEL_PATCH_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define KP_ABI 1u
#define KP_MAX_BYTES 64u
#define KP_MAX_POLICIES 16u
#define KP_CAP_INSPECT 1u
#define KP_CAP_TEST_DATA 2u
#define KP_CAP_DATA 4u
/* Code writes are deliberately unsupported until a hardware adapter is validated. */
enum kp_kind { KP_TEST_DATA = 1, KP_DATA = 2, KP_CODE = 3 };
enum kp_anchor { KP_TEXT = 1, KP_DATA_BASE = 2, KP_RESIDENT = 3 };
enum kp_operation { KP_VERIFY = 1, KP_APPLY = 2, KP_EXERCISE = 3, KP_REVERT = 4 };
enum kp_status { KP_OK, KP_INVALID, KP_SEQUENCE, KP_STALE, KP_UNSUPPORTED,
    KP_POLICY, KP_BUSY, KP_POISONED, KP_ACQUIRE, KP_MAPPING, KP_READ,
    KP_MISMATCH, KP_JOURNAL, KP_WRITE, KP_VERIFY_FAILED, KP_RESTORE,
    KP_RELEASE, KP_ADDRESS };
enum kp_state { KP_UNCHANGED, KP_COMMITTED, KP_RESTORED, KP_UNKNOWN };
enum kp_audit_stage { KP_PREPARE = 1, KP_OUTCOME = 2, KP_COMPLETE = 3 };
enum kp_flags {
    KP_PREIMAGE_VALID = 1u, KP_WRITE_ATTEMPTED = 2u, KP_OBSERVED_VALID = 4u,
    KP_APPLIED_VERIFIED = 8u, KP_RESTORE_ATTEMPTED = 16u,
    KP_FINAL_VALID = 32u, KP_RESTORED_VERIFIED = 64u,
    KP_LEASE_FINISHED = 128u, KP_PREPARE_SAVED = 256u,
    KP_OUTCOME_SAVED = 512u, KP_COMPLETE_SAVED = 1024u, KP_ENGINE_POISONED = 2048u
};
/* Native little-endian wire structures, no pointers or implicit padding. */
struct kp_identity {
    uint32_t abi, size, firmware, soc, capabilities, reserved;
    uint64_t generation, text_base, data_base, resident_base;
    unsigned char session[16], build[32];
};
struct kp_request {
    uint32_t abi, size, operation, kind;
    uint64_t sequence, generation;
    unsigned char session[16], build[32], image[32];
    uint32_t anchor, length;
    int64_t offset;
    unsigned char expected[KP_MAX_BYTES], replacement[KP_MAX_BYTES], undo[KP_MAX_BYTES];
};
struct kp_result {
    uint32_t abi, size, status, state, flags, length;
    uint64_t sequence, address;
    int32_t adapter_error, restore_error, journal_error, release_error;
    unsigned char preimage[KP_MAX_BYTES], observed[KP_MAX_BYTES], final[KP_MAX_BYTES];
};
_Static_assert(sizeof(struct kp_identity) == 104, "patch identity ABI");
_Static_assert(sizeof(struct kp_request) == 320, "patch request ABI");
_Static_assert(sizeof(struct kp_result) == 248, "patch result ABI");
_Static_assert(__atomic_always_lock_free(4, 0), "patch gate must be lock-free");

/* A resident-configured exact operation, never a policy accepted from a client.
 * image is the reviewed capture hash, not attestation of the whole live kernel.
 * Alignment, lifetime, semantics and callbacks belong to that reviewed policy. */
struct kp_policy {
    uint32_t kind, anchor, length, alignment;
    int64_t offset;
    unsigned char image[32], expected[KP_MAX_BYTES], replacement[KP_MAX_BYTES];
};
struct kp_adapter {
    void *context;
    int (*acquire)(void *, struct kp_identity *); /* success owns target lease */
    int (*snapshot)(void *, struct kp_identity *); /* under same target lease */
    int (*mapping)(void *, uint64_t, uint32_t, uint32_t, int); /* kind, mutating */
    int (*read)(void *, uint64_t, void *, size_t, size_t *);
    int (*write)(void *, uint64_t, const void *, size_t, size_t *);
    int (*save)(void *, unsigned, const struct kp_request *, const struct kp_result *);
    int (*finish)(void *, int); /* quarantine=1 must retain protection of unknown state */
};
struct kp_engine {
    uint32_t gate, initialized, poisoned, count, applied_mask;
    struct kp_identity identity;
    struct kp_policy policies[KP_MAX_POLICIES];
    struct kp_adapter adapter;
    uint64_t sequence;
    struct kp_request last_request;
    struct kp_result last_result;
};
static inline int kp_nonzero(const unsigned char *p, size_t n) {
    unsigned char v = 0;
    for (size_t i = 0; i < n; ++i) v |= p[i];
    return v != 0;
}
static inline int kp_kernel(uint64_t v) { return v >= UINT64_C(0xffff800000000000); }
static inline int kp_identity_valid(const struct kp_identity *id) {
    return id && id->abi == KP_ABI && id->size == sizeof(*id) && !id->reserved
        && id->generation && kp_nonzero(id->session, 16) && kp_nonzero(id->build, 32)
        && (id->capabilities & KP_CAP_INSPECT)
        && !(id->capabilities & ~(KP_CAP_INSPECT | KP_CAP_TEST_DATA | KP_CAP_DATA))
        && kp_kernel(id->text_base) && !(id->text_base & 4095)
        && kp_kernel(id->data_base) && !(id->data_base & 4095)
        && id->text_base < id->data_base && kp_kernel(id->resident_base);
}
static inline int kp_address(const struct kp_identity *id, uint32_t anchor,
        int64_t offset, uint32_t length, uint64_t *out) {
    uint64_t base = anchor == KP_TEXT ? id->text_base : anchor == KP_DATA_BASE
        ? id->data_base : anchor == KP_RESIDENT ? id->resident_base : 0;
    if (!base || !length || length > KP_MAX_BYTES) return 0;
    uint64_t magnitude = offset < 0 ? (uint64_t)(-(offset + 1)) + 1 : (uint64_t)offset;
    if ((offset < 0 && magnitude > base) || (offset >= 0 && magnitude > UINT64_MAX - base)) return 0;
    uint64_t address = offset < 0 ? base - magnitude : base + magnitude;
    if (!kp_kernel(address) || length - 1u > UINT64_MAX - address
            || (address & 4095u) + length > 4096u) return 0;
    *out = address;
    return 1;
}
static inline int kp_policy_valid(const struct kp_policy *p, const struct kp_identity *id) {
    uint64_t address;
    return p->kind >= KP_TEST_DATA && p->kind <= KP_CODE
        && (p->kind != KP_TEST_DATA || p->anchor == KP_RESIDENT) && p->alignment
        && p->alignment <= KP_MAX_BYTES && !(p->alignment & (p->alignment - 1u))
        && kp_nonzero(p->image, 32) && kp_address(id, p->anchor, p->offset, p->length, &address)
        && !(address & (p->alignment - 1u))
        && !kp_nonzero(p->expected + p->length, KP_MAX_BYTES - p->length)
        && !kp_nonzero(p->replacement + p->length, KP_MAX_BYTES - p->length)
        && memcmp(p->expected, p->replacement, p->length);
}
/* Initialization/reinitialization requires adapter quiescence, established recovery
 * and a fresh real session. Clearing this object is never timeout recovery. */
static inline int kp_init(struct kp_engine *e, const struct kp_identity *id,
        const struct kp_policy *policies, unsigned count, const struct kp_adapter *a) {
    if (!e || !kp_identity_valid(id) || !policies || !count || count > KP_MAX_POLICIES
            || !a || !a->acquire || !a->snapshot || !a->mapping || !a->read
            || !a->write || !a->save || !a->finish) return KP_INVALID;
    for (unsigned i = 0; i < count; ++i) {
        uint64_t start;
        if (!kp_policy_valid(policies + i, id)
                || !kp_address(id, policies[i].anchor, policies[i].offset, policies[i].length, &start)) return KP_INVALID;
        for (unsigned j = 0; j < i; ++j) {
            uint64_t other;
            if (!kp_address(id, policies[j].anchor, policies[j].offset, policies[j].length, &other)) return KP_INVALID;
            /* Also reject aliases through different anchors. */
            if (start <= other ? other - start < policies[i].length
                    : start - other < policies[j].length) return KP_INVALID;
        }
    }
    memset(e, 0, sizeof(*e));
    e->identity = *id;
    memcpy(e->policies, policies, count * sizeof(*policies));
    e->adapter = *a;
    e->count = count;
    e->initialized = 1;
    return KP_OK;
}
static inline int kp_request_valid(const struct kp_request *q) {
    return q && q->abi == KP_ABI && q->size == sizeof(*q) && q->sequence
        && q->operation >= KP_VERIFY && q->operation <= KP_REVERT
        && q->kind >= KP_TEST_DATA && q->kind <= KP_CODE
        && (q->kind != KP_TEST_DATA || q->anchor == KP_RESIDENT)
        && q->anchor >= KP_TEXT && q->anchor <= KP_RESIDENT
        && q->length && q->length <= KP_MAX_BYTES && q->generation
        && kp_nonzero(q->session, 16) && kp_nonzero(q->build, 32) && kp_nonzero(q->image, 32)
        && !kp_nonzero(q->expected + q->length, KP_MAX_BYTES - q->length)
        && !kp_nonzero(q->replacement + q->length, KP_MAX_BYTES - q->length)
        && !kp_nonzero(q->undo + q->length, KP_MAX_BYTES - q->length)
        && !memcmp(q->expected, q->undo, q->length)
        && memcmp(q->expected, q->replacement, q->length);
}
static inline int kp_same_identity(struct kp_engine *e, const struct kp_identity *id) {
    return kp_identity_valid(id) && !memcmp(&e->identity, id, sizeof(*id));
}
static inline int kp_snapshot(struct kp_engine *e, struct kp_result *r) {
    struct kp_identity observed = {0};
    int error = e->adapter.snapshot(e->adapter.context, &observed);
    if (!error && kp_same_identity(e, &observed)) return 1;
    if (!r->adapter_error) r->adapter_error = error;
    r->status = KP_STALE;
    e->poisoned = 1; /* sticky revocation: returning old metadata cannot rearm */
    return 0;
}
static inline int kp_read_exact(struct kp_engine *e, uint64_t address,
        unsigned char *out, uint32_t length) {
    size_t done = 0;
    memset(out, 0, KP_MAX_BYTES);
    int error = e->adapter.read(e->adapter.context, address, out, length, &done);
    if (!error && done == length) return 0;
    memset(out, 0, KP_MAX_BYTES); /* never publish partial/uninitialized evidence */
    return error ? error : -1;
}
static inline int kp_save(struct kp_engine *e, unsigned stage,
        const struct kp_request *q, struct kp_result *r, uint32_t flag) {
    int error = e->adapter.save(e->adapter.context, stage, q, r);
    if (error) {
        if (!r->journal_error) r->journal_error = error;
        return 0;
    }
    r->flags |= flag;
    return 1;
}
static inline void kp_restore(struct kp_engine *e, const struct kp_request *q, struct kp_result *r) {
    size_t done = 0;
    /* Never restore into a new lifetime/session or a changed/unowned mapping. */
    if (!kp_snapshot(e, r)) goto failed;
    r->restore_error = e->adapter.mapping(e->adapter.context, r->address, q->length, q->kind, 1);
    if (r->restore_error) goto failed;
    r->flags |= KP_RESTORE_ATTEMPTED;
    r->restore_error = e->adapter.write(e->adapter.context, r->address, r->preimage, q->length, &done);
    if (!r->restore_error && done != q->length) r->restore_error = -1;
    int read_error = kp_read_exact(e, r->address, r->final, q->length);
    if (!read_error) r->flags |= KP_FINAL_VALID;
    if (!r->restore_error) r->restore_error = read_error;
    if (!kp_snapshot(e, r) || r->restore_error || memcmp(r->preimage, r->final, q->length)) goto failed;
    r->flags |= KP_RESTORED_VERIFIED;
    r->state = KP_RESTORED;
    return;
failed:
    r->status = KP_RESTORE;
    r->state = KP_UNKNOWN;
    e->poisoned = 1;
}
/* Returns KP_BUSY without touching out when contended. Otherwise returns KP_OK
 * and puts operation status in out. Exact last-request replay has no callbacks.
 * Adapter calls run under this gate AND the separate adapter target lease.
 * This gate never spins; callbacks must not reenter or wait on this engine. */
static inline int kp_execute(struct kp_engine *e, const struct kp_request *input, struct kp_result *out) {
    if (!e || !input || !out) return KP_INVALID;
    uint32_t expected_gate = 0;
    if (!__atomic_compare_exchange_n(&e->gate, &expected_gate, 1, 0,
            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return KP_BUSY;
    struct kp_request q = *input; /* adapter must copy untrusted memory before entry */
    struct kp_result r = { .abi = KP_ABI, .size = sizeof(r), .sequence = q.sequence,
        .length = q.length <= KP_MAX_BYTES ? q.length : 0 };
    int consume = 0, held = 0;
    if (!e->initialized || !kp_request_valid(&q)) { r.status = KP_INVALID; goto done; }
    if (q.sequence == e->sequence && !memcmp(&q, &e->last_request, sizeof(q))) {
        r = e->last_result;
        goto done;
    }
    if (e->sequence == UINT64_MAX || q.sequence != e->sequence + 1) { r.status = KP_SEQUENCE; goto done; }
    consume = 1;
    if (e->poisoned) { r.status = KP_POISONED; r.state = KP_UNKNOWN; goto done; }
    if (q.generation != e->identity.generation || memcmp(q.session, e->identity.session, 16)
            || memcmp(q.build, e->identity.build, 32)) { r.status = KP_STALE; goto done; }
    /* Code is inspectable, but no code mutation is currently supported. */
    uint32_t cap = q.kind == KP_TEST_DATA ? KP_CAP_TEST_DATA : KP_CAP_DATA;
    if (q.operation != KP_VERIFY && (q.kind == KP_CODE
            || !(e->identity.capabilities & cap)
            || (q.operation == KP_EXERCISE && q.kind != KP_TEST_DATA))) {
        r.status = KP_UNSUPPORTED; goto done;
    }
    const struct kp_policy *policy = NULL;
    uint32_t policy_bit = 0;
    for (unsigned i = 0; i < e->count; ++i) {
        const struct kp_policy *p = e->policies + i;
        if (p->kind == q.kind && p->anchor == q.anchor && p->offset == q.offset
                && p->length == q.length && !memcmp(p->image, q.image, 32)
                && !memcmp(p->expected, q.expected, KP_MAX_BYTES)
                && !memcmp(p->replacement, q.replacement, KP_MAX_BYTES)) { policy = p; policy_bit = 1u << i; break; }
    }
    if (!policy || (q.operation == KP_REVERT && !(e->applied_mask & policy_bit))) {
        r.status = KP_POLICY; goto done;
    }
    if (!kp_address(&e->identity, q.anchor, q.offset, q.length, &r.address)
            || (r.address & (policy->alignment - 1u))) { r.status = KP_ADDRESS; goto done; }
    struct kp_identity observed = {0};
    r.adapter_error = e->adapter.acquire(e->adapter.context, &observed);
    if (r.adapter_error) { r.status = KP_ACQUIRE; goto done; }
    held = 1;
    if (!kp_same_identity(e, &observed)) { r.status = KP_STALE; e->poisoned = 1; goto finish; }
    r.adapter_error = e->adapter.mapping(e->adapter.context, r.address, q.length, q.kind, q.operation != KP_VERIFY);
    if (r.adapter_error) { r.status = KP_MAPPING; goto finish; }
    r.adapter_error = kp_read_exact(e, r.address, r.preimage, q.length);
    if (r.adapter_error) { r.status = KP_READ; goto finish; }
    r.flags |= KP_PREIMAGE_VALID;
    const unsigned char *before = q.operation == KP_REVERT ? q.replacement : q.expected;
    const unsigned char *desired = q.operation == KP_REVERT ? q.expected : q.replacement;
    if (memcmp(r.preimage, before, q.length)) { r.status = KP_MISMATCH; goto finish; }
    if (!kp_snapshot(e, &r) || q.operation == KP_VERIFY) goto finish;
    if (!kp_save(e, KP_PREPARE, &q, &r, KP_PREPARE_SAVED)) { r.status = KP_JOURNAL; goto finish; }
    if (!kp_snapshot(e, &r)) goto finish;
    size_t written = 0;
    r.flags |= KP_WRITE_ATTEMPTED;
    r.state = KP_UNKNOWN;
    r.adapter_error = e->adapter.write(e->adapter.context, r.address, desired, q.length, &written);
    if (!r.adapter_error && written != q.length) r.adapter_error = -1;
    int read_error = kp_read_exact(e, r.address, r.observed, q.length);
    if (!read_error) r.flags |= KP_OBSERVED_VALID;
    if (!kp_snapshot(e, &r)) goto outcome; /* no rollback into unknown identity */
    if (r.adapter_error) r.status = KP_WRITE;
    else if (read_error || memcmp(r.observed, desired, q.length)) {
        r.status = KP_VERIFY_FAILED;
        r.adapter_error = read_error;
    } else { r.flags |= KP_APPLIED_VERIFIED; r.state = KP_COMMITTED; }
    if (r.status || q.operation == KP_EXERCISE) kp_restore(e, &q, &r);
    /* A failed outcome journal on commit still permits rollback under the lease. */
outcome:
    if (!kp_save(e, KP_OUTCOME, &q, &r, KP_OUTCOME_SAVED)) {
        if (r.state == KP_COMMITTED) {
            r.status = KP_JOURNAL;
            kp_restore(e, &q, &r);
            if (!kp_save(e, KP_OUTCOME, &q, &r, KP_OUTCOME_SAVED)) e->poisoned = 1;
        } else { e->poisoned = 1; if (!r.status) r.status = KP_JOURNAL; }
    }
finish:
    if (r.state == KP_COMMITTED) {
        if (q.operation == KP_REVERT) e->applied_mask &= ~policy_bit;
        else e->applied_mask |= policy_bit;
    }
    if (held) {
        r.release_error = e->adapter.finish(e->adapter.context, e->poisoned || r.state == KP_UNKNOWN);
        if (r.release_error) { e->poisoned = 1; r.status = KP_RELEASE; r.state = KP_UNKNOWN; }
        else r.flags |= KP_LEASE_FINISHED;
    }
    if (e->poisoned) r.flags |= KP_ENGINE_POISONED;
    /* COMPLETE persistence is required before a successful acknowledgement.
     * Failure after lease release cannot safely trigger a fresh rollback. */
    if (!kp_save(e, KP_COMPLETE, &q, &r, KP_COMPLETE_SAVED)) {
        e->poisoned = 1;
        if (!r.status) r.status = KP_JOURNAL;
    }
done:
    if (e->poisoned) r.flags |= KP_ENGINE_POISONED;
    if (consume) { e->sequence = q.sequence; e->last_request = q; e->last_result = r; }
    *out = r;
    __atomic_store_n(&e->gate, 0, __ATOMIC_RELEASE);
    return KP_OK;
}
#endif
