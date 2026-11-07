/* SPDX-License-Identifier: GPL-3.0-or-later
 * Preallocated resident trace/panic storage and bounded polled export core.
 * No trap/panic installation, DR writes, scheduler, allocation or device driver.
 */
#ifndef PS5_RESIDENT_EVIDENCE_H
#define PS5_RESIDENT_EVIDENCE_H
#include "../../common/evidence.h"

#define RE_CPUS 16u
#define RE_RING 32u
#define RE_MAX_HITS 65535u
#define RE_MAX_POLLS 65536u
_Static_assert(__atomic_always_lock_free(4, 0), "resident evidence needs lock-free 32-bit atomics");
enum re_result { RE_OK, RE_BUSY, RE_INVALID, RE_FULL, RE_BUDGET, RE_EMPTY, RE_IO, RE_TIMEOUT };
struct re_cpu {
    uint32_t writer, head, tail, rejected, panic_state;
    uint32_t hits;
    unsigned char ring[RE_RING][PE_SIZE], panic[PE_SIZE];
};
struct re_store {
    uint64_t session[2], groups;
    unsigned char build_id[32];
    uint32_t cpu_mask, hit_budget, initialized;
    struct re_cpu cpu[RE_CPUS];
};
struct re_export {
    uint32_t gate, failed, polls, poll_budget, offset, active, cpu, panic, next_cpu, panic_only;
    uint64_t deadline, last_ticks;
    unsigned char record[PE_SIZE];
};
/* Try to transfer at most n bytes without waiting. Return accepted byte count,
 * 0 for backpressure or -1 for failure. Adapter MUST bound device operations,
 * remain usable with interrupts/scheduling disabled, and preserve byte order.
 * Success is device acceptance, NOT host persistence or end-to-end receipt.
 */
typedef int (*re_try_write)(void *ctx, const unsigned char *bytes, unsigned n);

/* Initialization/reconfiguration only while all producers/exporters quiesce.
 * Storage must be wired/resident and zeroed outside trap/panic context.
 */
static inline int re_init(struct re_store *s, const uint64_t session[2],
        const unsigned char build_id[32], uint32_t cpu_mask, uint64_t groups, uint32_t budget) {
    if (!s || !session || !build_id || !(session[0]|session[1]) || !cpu_mask
        || (cpu_mask & ~UINT32_C(0xffff)) || !budget || budget > RE_MAX_HITS) return RE_INVALID;
    unsigned any = 0;
    for (unsigned i = 0; i < 32; ++i) any |= build_id[i];
    if (!any) return RE_INVALID;
    pe_zero(s, sizeof(*s));
    s->session[0] = session[0]; s->session[1] = session[1];
    for (unsigned i = 0; i < 32; ++i) s->build_id[i] = build_id[i];
    s->groups = groups; s->cpu_mask = cpu_mask; s->hit_budget = budget; s->initialized = 1;
    return RE_OK;
}
static inline void re_base(struct pe_record *r, const struct re_store *s,
        uint32_t kind, unsigned cpu, uint32_t thread, uint32_t site, uint64_t ticks) {
    pe_zero(r, sizeof(*r)); r->kind = kind; r->cpu = cpu;
    r->thread = thread; r->site = site; r->ticks = ticks;
    r->session[0] = s->session[0]; r->session[1] = s->session[1];
    for (unsigned i = 0; i < 32; ++i) r->build_id[i] = s->build_id[i];
}
/* One CAS attempt: nested/concurrent producers are rejected rather than wait.
 * Rings are SPSC with a serialized producer and one exporter. Full preserves
 * committed events, records loss, and still spends the finite hit budget.
 * rejected is a modulo-2^32 diagnostic counter (including nested rejection).
 */
static inline int re_trace_context(struct re_store *s, unsigned cpu, unsigned group,
        uint32_t subject_pid, uint32_t thread, uint32_t site, uint32_t phase, uint64_t ticks,
        const uint64_t arguments[4], const uint64_t registers[18]) {
    if (!s || !s->initialized || cpu >= RE_CPUS || !(s->cpu_mask & (1u<<cpu))
        || group >= 64 || !site || phase > PE_AFTER) return RE_INVALID;
    if (!(s->groups & (UINT64_C(1)<<group))) return RE_OK;
    struct re_cpu *c = &s->cpu[cpu];
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&c->writer, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        __atomic_fetch_add(&c->rejected, 1, __ATOMIC_RELAXED); return RE_BUSY;
    }
    int result = RE_OK;
    if (c->hits == s->hit_budget) result = RE_BUDGET;
    else {
        ++c->hits;
        uint32_t head = __atomic_load_n(&c->head, __ATOMIC_ACQUIRE);
        uint32_t tail = __atomic_load_n(&c->tail, __ATOMIC_RELAXED);
        if (tail-head >= RE_RING) {
            __atomic_fetch_add(&c->rejected, 1, __ATOMIC_RELAXED); result = RE_FULL;
        } else {
            struct pe_record record;
            re_base(&record, s, PE_TRACE, cpu, thread, site, ticks);
            record.sequence = c->hits; record.phase = phase;
            record.subject_pid = subject_pid;
            record.flags = registers ? PE_REGISTERS_VALID : 0;
            record.dropped = __atomic_load_n(&c->rejected, __ATOMIC_RELAXED);
            for (unsigned i = 0; i < 4; ++i) record.arguments[i] = arguments ? arguments[i] : 0;
            for (unsigned i = 0; i < 18; ++i) record.registers[i] = registers ? registers[i] : 0;
            pe_encode(&record, c->ring[tail % RE_RING]);
            __atomic_store_n(&c->tail, tail+1, __ATOMIC_RELEASE);
        }
    }
    __atomic_store_n(&c->writer, 0, __ATOMIC_RELEASE);
    return result;
}
static inline int re_trace(struct re_store *s, unsigned cpu, unsigned group,
        uint32_t thread, uint32_t site, uint32_t phase, uint64_t ticks,
        const uint64_t arguments[4]) {
    return re_trace_context(s, cpu, group, 0, thread, site, phase, ticks, arguments, NULL);
}
/* First panic record per CPU wins, in a SEPARATE slot so a nested panic never
 * waits on an interrupted trace producer. Only adapter-provided safe values are
 * copied; no stack walking, pointer dereference, formatting or peer rendezvous.
 * site identifies the panic entry; args can hold code/fault VA/etc. Register
 * order is common/evidence.h (RAX..R15,RIP,RFLAGS), not a native trap frame.
 */
static inline int re_panic(struct re_store *s, unsigned cpu, uint32_t subject_pid, uint32_t thread,
        uint32_t site, uint64_t ticks, const uint64_t arguments[4], const uint64_t registers[18]) {
    if (!s || !s->initialized || cpu >= RE_CPUS || !(s->cpu_mask & (1u<<cpu)) || !site) return RE_INVALID;
    struct re_cpu *c = &s->cpu[cpu];
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&c->panic_state, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return RE_BUSY;
    struct pe_record record;
    re_base(&record, s, PE_PANIC, cpu, thread, site, ticks);
    record.sequence = 1; record.flags = registers ? PE_REGISTERS_VALID : 0;
    record.subject_pid = subject_pid;
    record.dropped = __atomic_load_n(&c->rejected, __ATOMIC_RELAXED);
    for (unsigned i = 0; i < 4; ++i) record.arguments[i] = arguments ? arguments[i] : 0;
    for (unsigned i = 0; i < 18; ++i) record.registers[i] = registers ? registers[i] : 0;
    pe_encode(&record, c->panic);
    __atomic_store_n(&c->panic_state, 2, __ATOMIC_RELEASE);
    return RE_OK;
}
static inline int re_export_init(struct re_export *e, unsigned panic_only,
        uint32_t poll_budget, uint64_t now, uint64_t deadline) {
    if (!e || panic_only > 1 || !poll_budget || poll_budget > RE_MAX_POLLS || deadline <= now) return RE_INVALID;
    pe_zero(e, sizeof(*e)); e->poll_budget = poll_budget; e->deadline = deadline; e->last_ticks = now;
    e->panic_only = panic_only;
    return RE_OK;
}
/* Call from a dedicated, adapter-owned exporter context. One bounded callback
 * per invocation; no spinning. Do NOT enter this exporter from a nested panic
 * if its owner was interrupted inside a device callback. Per-CPU panic storage
 * remains available; a preinitialized panic-only exporter can use an independent
 * physical channel even if the normal trace exporter was interrupted. Exactly
 * ONE exporter per mode per store; channels must not interleave physical bytes.
 * Once a physical stream partially fails, failure is sticky: no replay/reset
 * into that stream. A new exporter requires adapter quiescence and a new stream.
 */
static inline int re_export_poll(struct re_store *s, struct re_export *e,
        uint64_t now, re_try_write write, void *ctx) {
    if (!s || !s->initialized || !e || !write || !e->poll_budget) return RE_INVALID;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&e->gate, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return RE_BUSY;
    int result = RE_OK;
    if (e->failed) { result = (int)e->failed; goto done; }
    if (now < e->last_ticks || now >= e->deadline) { e->failed = RE_TIMEOUT; result = RE_TIMEOUT; goto done; }
    e->last_ticks = now;
    if (!e->active) {
        /* Panic mode never touches the normal exporter's ring or device state.
         * Never wait on WRITING slots or on a peer that did not record a panic. */
        if (e->panic_only) for (unsigned cpu = 0; cpu < RE_CPUS; ++cpu) {
            if (!(s->cpu_mask & (1u<<cpu))) continue;
            if (__atomic_load_n(&s->cpu[cpu].panic_state, __ATOMIC_ACQUIRE) == 2) {
                e->cpu = cpu; e->panic = 1; e->active = 1;
                for (unsigned i = 0; i < PE_SIZE; ++i) e->record[i] = s->cpu[cpu].panic[i];
                break;
            }
        }
        if (!e->panic_only && !e->active) for (unsigned n = 0; n < RE_CPUS; ++n) {
            unsigned cpu = (e->next_cpu+n) % RE_CPUS;
            if (!(s->cpu_mask & (1u<<cpu))) continue;
            struct re_cpu *c = &s->cpu[cpu];
            uint32_t head = __atomic_load_n(&c->head, __ATOMIC_RELAXED);
            uint32_t tail = __atomic_load_n(&c->tail, __ATOMIC_ACQUIRE);
            if (head == tail) continue;
            e->cpu = cpu; e->panic = 0; e->active = 1;
            for (unsigned i = 0; i < PE_SIZE; ++i) e->record[i] = c->ring[head % RE_RING][i];
            break;
        }
        if (!e->active) { result = RE_EMPTY; goto done; }
        e->offset = 0;
    }
    if (e->polls == e->poll_budget) { e->failed = RE_BUDGET; result = RE_BUDGET; goto done; }
    ++e->polls;
    int accepted = write(ctx, e->record+e->offset, PE_SIZE-e->offset);
    if (accepted < 0 || (unsigned)accepted > PE_SIZE-e->offset) { e->failed = RE_IO; result = RE_IO; goto done; }
    if (!accepted) { result = RE_BUSY; goto done; }
    e->offset += (unsigned)accepted;
    if (e->offset == PE_SIZE) {
        struct re_cpu *c = &s->cpu[e->cpu];
        if (e->panic) __atomic_store_n(&c->panic_state, 3, __ATOMIC_RELEASE);
        else {
            uint32_t head = __atomic_load_n(&c->head, __ATOMIC_RELAXED);
            __atomic_store_n(&c->head, head+1, __ATOMIC_RELEASE);
        }
        e->next_cpu = (e->cpu+1) % RE_CPUS; e->active = 0;
    }
done:
    __atomic_store_n(&e->gate, 0, __ATOMIC_RELEASE);
    return result;
}
#endif
