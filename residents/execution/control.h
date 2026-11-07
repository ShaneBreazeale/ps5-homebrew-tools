/* SPDX-License-Identifier: GPL-3.0-or-later
 * Cooperative SMP execution protocol. No IPI, trap-frame, DR, IDT or TSS writes.
 * Every concurrent entry makes ONE lock-free CAS attempt, never spins or waits.
 * Hardware operations run outside this gate and require ticketed acknowledgements.
 */
#ifndef KERNEL_EXECUTION_CONTROL_H
#define KERNEL_EXECUTION_CONTROL_H
#include <stddef.h>
#include "../capture/capture.h"

#define KD_ABI 1u
#define KD_CPU_NONE KC_CPU_LIMIT
#define KD_CAP_ALL 15u /* rendezvous, bounded step, polled transport, verified restore */
enum kd_error { KD_OK, KD_BUSY, KD_INVALID, KD_STALE, KD_STATE, KD_UNSUPPORTED,
    KD_IO, KD_TIMEOUT, KD_UNEXPECTED, KD_LIMIT, KD_CANCELED };
enum kd_state { KD_IDLE, KD_STOPPING, KD_STOPPED, KD_STEP_PREPARING,
    KD_STEPPING, KD_STEP_CLEANUP, KD_RESTORING, KD_RELEASING, KD_COMPLETE, KD_FAILED };
enum kd_phase { KD_CPU_RUNNING, KD_CPU_PARKED, KD_CPU_STEPPING, KD_CPU_RESTORED, KD_CPU_RELEASED };
enum kd_operation { KD_STATUS = 1, KD_STOP, KD_REGISTERS, KD_STEP, KD_RESTORE, KD_ABORT };
enum kd_action_type { KD_WAIT, KD_PREPARE_STEP, KD_CLEAN_STEP, KD_RESTORE_CPU, KD_RELEASE_CPU };
enum kd_entry_reason { KD_RENDEZVOUS, KD_TRACE, KD_OTHER_TRAP };

struct kd_identity {
    unsigned char build_id[32];
    uint64_t session[2], generation, max_hold_ticks;
    uint32_t cpu_mask, capabilities;
};
/* Adapter cookie pins the FULL architecture context, including state absent
 * from these observation registers. The core never treats this as a pointer. */
struct kd_frame { struct kc_registers registers; uint64_t cookie; };
struct kd_action {
    uint32_t type, cpu;
    uint64_t epoch, ticket, frame_cookie, original_cookie, step_ticket;
};
struct kd_request {
    uint32_t abi, size, operation, cpu;
    uint64_t session[2], sequence, epoch, deadline, argument;
};
struct kd_reply {
    uint32_t abi, size, result, state;
    uint64_t session[2], sequence, epoch;
    uint32_t cpu_mask, parked_mask, restored_mask, released_mask;
    uint32_t need_stop_mask, fault, step_cpu, registers_valid;
    uint64_t step_ticket;
    uint32_t steps, step_limit;
    struct kc_registers registers;
};
_Static_assert(sizeof(struct kd_request) == 64, "execution request ABI");
_Static_assert(sizeof(struct kd_reply) == 240, "execution reply ABI");
_Static_assert(__atomic_always_lock_free(sizeof(uint32_t), 0), "nonblocking gate required");
struct kd_control {
    uint32_t gate, initialized;
    struct kd_identity identity;
    uint32_t state, fault, parked_mask, restored_mask, released_mask;
    uint32_t step_cpu, steps, step_limit, cleanup_needed;
    uint64_t epoch, ticket, step_ticket, deadline, last_tick;
    uint32_t phase[KC_CPU_LIMIT];
    struct kd_frame initial[KC_CPU_LIMIT], current[KC_CPU_LIMIT];
    struct kd_action pending[KC_CPU_LIMIT];
    struct kd_request last_request;
    struct kd_reply last_reply;
};

/* Init/retirement require platform quiescence; never reinitialize a live core. */
static inline int kd_init(struct kd_control *c, const struct kd_identity *identity) {
    unsigned char build = 0;
    if (!c || !identity || !identity->cpu_mask || (identity->cpu_mask & ~UINT32_C(0xffff))
        || !identity->generation || !(identity->session[0] | identity->session[1])
        || !identity->max_hold_ticks || identity->capabilities != KD_CAP_ALL) return KD_INVALID;
    for (unsigned i = 0; i < 32; ++i) build |= identity->build_id[i];
    if (!build) return KD_INVALID;
    struct kd_identity copy = *identity;
    memset(c, 0, sizeof(*c));
    c->identity = copy;
    c->step_cpu = KD_CPU_NONE;
    c->initialized = 1;
    return KD_OK;
}
static inline int kd_lock(struct kd_control *c) {
    if (!c || !c->initialized) return KD_INVALID;
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&c->gate, &expected, 1, 0,
        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED) ? KD_OK : KD_BUSY;
}
static inline void kd_unlock(struct kd_control *c) {
    __atomic_store_n(&c->gate, 0, __ATOMIC_RELEASE);
}
static inline void kd_fail_locked(struct kd_control *c, unsigned fault) {
    if (!c->fault) c->fault = fault;
    c->state = KD_FAILED;
}
static inline void kd_tick_locked(struct kd_control *c, uint64_t now) {
    if (c->state == KD_IDLE || c->state == KD_COMPLETE || c->state == KD_RELEASING) return;
    if (now < c->last_tick) kd_fail_locked(c, KD_INVALID);
    else if (now >= c->deadline) kd_fail_locked(c, KD_TIMEOUT);
    if (now > c->last_tick) c->last_tick = now;
}
static inline int kd_deadline_valid(const struct kd_control *c, uint64_t now, uint64_t deadline) {
    return deadline > now && deadline - now <= c->identity.max_hold_ticks;
}
static inline uint32_t kd_pending_mask(const struct kd_control *c) {
    uint32_t mask = 0;
    for (unsigned cpu = 0; cpu < KC_CPU_LIMIT; ++cpu)
        if (c->pending[cpu].type != KD_WAIT) mask |= 1u << cpu;
    return mask;
}
static inline void kd_reply_locked(const struct kd_control *c, struct kd_reply *r) {
    memset(r, 0, sizeof(*r));
    r->abi = KD_ABI; r->size = sizeof(*r);
    memcpy(r->session, c->identity.session, sizeof(r->session));
    r->epoch = c->epoch; r->state = c->state; r->fault = c->fault;
    r->cpu_mask = c->identity.cpu_mask; r->parked_mask = c->parked_mask;
    r->restored_mask = c->restored_mask; r->released_mask = c->released_mask;
    if (c->state != KD_IDLE && c->state != KD_COMPLETE && c->state != KD_RELEASING)
        r->need_stop_mask = c->identity.cpu_mask & ~c->parked_mask;
    r->step_cpu = c->step_cpu; r->step_ticket = c->step_ticket;
    r->steps = c->steps; r->step_limit = c->step_limit;
}
static inline int kd_inspect(struct kd_control *c, uint64_t now, struct kd_reply *out) {
    if (!out) return KD_INVALID;
    int error = kd_lock(c);
    if (error) return error;
    kd_tick_locked(c, now);
    kd_reply_locked(c, out);
    kd_unlock(c);
    return KD_OK;
}
/* Watchdog/ownership/transport failures can be reported without a client
 * command. A failure never manufactures a parked CPU or releases another CPU. */
static inline int kd_fault(struct kd_control *c, uint64_t epoch, unsigned fault, uint64_t now) {
    if (fault != KD_STALE && fault != KD_IO && fault != KD_TIMEOUT
        && fault != KD_UNEXPECTED && fault != KD_CANCELED) return KD_INVALID;
    int error = kd_lock(c);
    if (error) return error;
    kd_tick_locked(c, now);
    if (epoch != c->epoch || !epoch) error = KD_STALE;
    else if (c->state == KD_IDLE || c->state == KD_COMPLETE) error = KD_STATE;
    else kd_fail_locked(c, fault);
    kd_unlock(c);
    return error;
}
/* Commands are single-client, monotonically sequenced. Exact replay returns
 * the cached reply without repeating an action, even after the state changes. */
static inline int kd_command(struct kd_control *c, const struct kd_request *q,
        uint64_t now, struct kd_reply *out) {
    if (!q || !out) return KD_INVALID;
    int error = kd_lock(c);
    if (error) return error; /* Caller retains the request; it was not consumed. */
    kd_tick_locked(c, now);
    kd_reply_locked(c, out);
    if (q->abi != KD_ABI || q->size != sizeof(*q) || !q->sequence
        || memcmp(q->session, c->identity.session, sizeof(q->session))) error = KD_INVALID;
    else if (q->sequence == c->last_request.sequence) {
        if (memcmp(q, &c->last_request, sizeof(*q))) error = KD_STALE;
        else { *out = c->last_reply; kd_unlock(c); return KD_OK; }
    } else if (c->last_request.sequence == UINT64_MAX
        || q->sequence != c->last_request.sequence + 1 || q->epoch != c->epoch) error = KD_STALE;
    else {
        error = KD_OK;
        if ((q->operation != KD_STEP && q->operation != KD_REGISTERS && q->cpu)
            || (q->operation != KD_STOP && q->argument)
            || (q->operation != KD_STOP && q->operation != KD_STEP && q->operation != KD_RESTORE && q->deadline))
            error = KD_INVALID;
        else switch (q->operation) {
        case KD_STATUS: break;
        case KD_STOP:
            if (c->state != KD_IDLE) error = KD_STATE;
            else if (!q->argument || q->argument > KC_MAX_CPU_HITS
                || !kd_deadline_valid(c, now, q->deadline)) error = KD_INVALID;
            else if (c->epoch == UINT64_MAX) error = KD_LIMIT;
            else {
                ++c->epoch;
                c->state = KD_STOPPING; c->fault = 0;
                c->parked_mask = c->restored_mask = c->released_mask = 0;
                c->step_cpu = KD_CPU_NONE; c->step_ticket = 0;
                c->steps = c->cleanup_needed = 0; c->step_limit = (uint32_t)q->argument;
                c->deadline = q->deadline; c->last_tick = now;
                memset(c->phase, 0, sizeof(c->phase));
                memset(c->pending, 0, sizeof(c->pending));
                memset(c->initial, 0, sizeof(c->initial));
                memset(c->current, 0, sizeof(c->current));
            }
            break;
        case KD_REGISTERS:
            if (c->state != KD_STOPPED) error = KD_STATE;
            else if (q->cpu >= KC_CPU_LIMIT || !(c->parked_mask & (1u << q->cpu))) error = KD_INVALID;
            break;
        case KD_STEP:
            if (c->state != KD_STOPPED) error = KD_STATE;
            else if (q->cpu >= KC_CPU_LIMIT || !(c->parked_mask & (1u << q->cpu))
                || !kd_deadline_valid(c, now, q->deadline) || q->deadline > c->deadline) error = KD_INVALID;
            else if (c->steps == c->step_limit) error = KD_LIMIT;
            else {
                c->step_cpu = q->cpu; c->step_ticket = 0;
                ++c->steps; c->deadline = q->deadline; c->state = KD_STEP_PREPARING;
            }
            break;
        case KD_RESTORE:
            if (c->state != KD_STOPPED && c->state != KD_FAILED && c->state != KD_STEP_PREPARING) error = KD_STATE;
            else if (c->parked_mask != c->identity.cpu_mask || kd_pending_mask(c) || c->released_mask) error = KD_BUSY;
            else if (!kd_deadline_valid(c, now, q->deadline) || now < c->last_tick) error = KD_INVALID;
            else {
                c->state = KD_RESTORING; c->deadline = q->deadline; c->last_tick = now;
                c->restored_mask = c->cleanup_needed = 0;
                for (unsigned cpu = 0; cpu < KC_CPU_LIMIT; ++cpu) c->phase[cpu] = KD_CPU_PARKED;
            }
            break;
        case KD_ABORT:
            if (c->state == KD_IDLE || c->state == KD_COMPLETE || c->state == KD_RELEASING) error = KD_STATE;
            else kd_fail_locked(c, KD_CANCELED);
            break;
        default: error = KD_UNSUPPORTED; break;
        }
        kd_reply_locked(c, out);
        if (!error && q->operation == KD_REGISTERS) {
            out->registers = c->current[q->cpu].registers;
            out->registers_valid = 1;
        }
        out->result = (uint32_t)error; out->sequence = q->sequence;
        c->last_request = *q; c->last_reply = *out;
        kd_unlock(c);
        return KD_OK;
    }
    out->sequence = q->sequence; out->result = (uint32_t)error;
    kd_unlock(c);
    return KD_OK;
}
/* Arrival means this CPU surrendered its target context to the adapter's
 * park loop. No target execution may occur until a successful STEP/RELEASE ack.
 * An unproven/stale trace does not establish arrival; request a real recapture. */
static inline int kd_enter(struct kd_control *c, uint64_t epoch, unsigned cpu,
        const struct kd_frame *frame, unsigned reason, uint64_t step_ticket, uint64_t now) {
    if (!frame || !frame->cookie || !kc_pointer(frame->registers.rip)
        || !kc_pointer(frame->registers.rsp) || cpu >= KC_CPU_LIMIT) return KD_INVALID;
    int error = kd_lock(c);
    if (error) return error;
    kd_tick_locked(c, now);
    if (epoch != c->epoch || !epoch) error = KD_STALE;
    else if (!(c->identity.cpu_mask & (1u << cpu))) error = KD_INVALID;
    else if (c->pending[cpu].type) error = KD_BUSY;
    else if (c->phase[cpu] == KD_CPU_RUNNING && (c->state == KD_STOPPING || c->state == KD_FAILED)
        && reason == KD_RENDEZVOUS && !step_ticket) {
        c->initial[cpu] = c->current[cpu] = *frame;
        c->phase[cpu] = KD_CPU_PARKED; c->parked_mask |= 1u << cpu;
        if (c->state == KD_STOPPING && c->parked_mask == c->identity.cpu_mask) c->state = KD_STOPPED;
    } else if (c->phase[cpu] == KD_CPU_STEPPING && cpu == c->step_cpu
        && ((reason == KD_TRACE && step_ticket == c->step_ticket)
            || (reason == KD_OTHER_TRAP && step_ticket == c->step_ticket)
            || (c->state == KD_FAILED && reason == KD_RENDEZVOUS && !step_ticket))) {
        c->current[cpu] = *frame; c->phase[cpu] = KD_CPU_PARKED; c->parked_mask |= 1u << cpu;
        if (reason == KD_TRACE && c->state == KD_STEPPING) {
            c->cleanup_needed = 1; c->state = KD_STEP_CLEANUP;
        } else kd_fail_locked(c, reason == KD_OTHER_TRAP ? KD_UNEXPECTED : KD_CANCELED);
    } else error = KD_STATE;
    kd_unlock(c);
    return error;
}
/* No callbacks under the gate. Actions are issued once and remain pending until
 * acked; nested polls return WAIT rather than running the mutation twice. */
static inline int kd_cpu_poll(struct kd_control *c, uint64_t epoch, unsigned cpu,
        uint64_t now, struct kd_action *out) {
    if (!out || cpu >= KC_CPU_LIMIT) return KD_INVALID;
    memset(out, 0, sizeof(*out));
    int error = kd_lock(c);
    if (error) return error;
    kd_tick_locked(c, now);
    if (!epoch || epoch != c->epoch) error = KD_STALE;
    else if (!(c->identity.cpu_mask & (1u << cpu))) error = KD_INVALID;
    else if (!c->pending[cpu].type) {
        unsigned type = KD_WAIT;
        if (c->state == KD_STEP_PREPARING && cpu == c->step_cpu) type = KD_PREPARE_STEP;
        else if (c->state == KD_STEP_CLEANUP && cpu == c->step_cpu && c->cleanup_needed) type = KD_CLEAN_STEP;
        else if (c->state == KD_RESTORING && c->phase[cpu] == KD_CPU_PARKED) type = KD_RESTORE_CPU;
        else if (c->state == KD_RELEASING && c->phase[cpu] == KD_CPU_RESTORED) type = KD_RELEASE_CPU;
        if (type) {
            if (c->ticket == UINT64_MAX) { kd_fail_locked(c, KD_LIMIT); error = KD_LIMIT; }
            else {
                out->type = type; out->cpu = cpu; out->epoch = epoch; out->ticket = ++c->ticket;
                if (type == KD_PREPARE_STEP) c->step_ticket = out->ticket;
                out->step_ticket = cpu == c->step_cpu ? c->step_ticket : 0;
                out->frame_cookie = c->current[cpu].cookie;
                out->original_cookie = c->initial[cpu].cookie;
                c->pending[cpu] = *out;
            }
        }
    }
    kd_unlock(c);
    return error;
}
/* verified=1 asserts the adapter completed the exact action and its readback.
 * Success on PREPARE_STEP alone authorizes ONE target instruction. Restoration
 * must preserve the instruction's post-step results, not rewind GP registers.
 * Successful CLEAN_STEP additionally requires the cleaned frame's readback. */
static inline int kd_cpu_ack(struct kd_control *c, const struct kd_action *action,
        int verified, const struct kd_frame *observed, uint64_t now) {
    if (!action || action->cpu >= KC_CPU_LIMIT || !action->type || (verified != 0 && verified != 1)) return KD_INVALID;
    int error = kd_lock(c);
    if (error) return error;
    kd_tick_locked(c, now);
    unsigned cpu = action->cpu;
    if (action->epoch != c->epoch || memcmp(action, &c->pending[cpu], sizeof(*action))) error = KD_STALE;
    else if ((verified && action->type == KD_CLEAN_STEP && !observed)
        || (observed && action->type != KD_CLEAN_STEP)) error = KD_INVALID;
    else {
        memset(&c->pending[cpu], 0, sizeof(c->pending[cpu]));
        if (!verified || (action->type == KD_CLEAN_STEP
            && (observed->cookie != action->frame_cookie
                || memcmp(&observed->registers, &c->current[cpu].registers,
                    offsetof(struct kc_registers, rflags))))) {
            kd_fail_locked(c, KD_IO); error = KD_IO;
            c->phase[cpu] = KD_CPU_PARKED;
        } else switch (action->type) {
        case KD_PREPARE_STEP:
            if (c->state != KD_STEP_PREPARING) error = KD_CANCELED;
            else {
                c->state = KD_STEPPING; c->phase[cpu] = KD_CPU_STEPPING;
                c->parked_mask &= ~(1u << cpu);
            }
            break;
        case KD_CLEAN_STEP:
            c->current[cpu] = *observed;
            c->cleanup_needed = 0;
            if (c->state == KD_STEP_CLEANUP) c->state = KD_STOPPED;
            else error = KD_CANCELED;
            break;
        case KD_RESTORE_CPU:
            c->phase[cpu] = KD_CPU_RESTORED; c->restored_mask |= 1u << cpu;
            if (c->state == KD_RESTORING && c->restored_mask == c->identity.cpu_mask) c->state = KD_RELEASING;
            break;
        case KD_RELEASE_CPU:
            if (c->state != KD_RELEASING) error = KD_CANCELED;
            else {
                c->phase[cpu] = KD_CPU_RELEASED; c->released_mask |= 1u << cpu;
                c->parked_mask &= ~(1u << cpu);
                if (c->released_mask == c->identity.cpu_mask) c->state = KD_COMPLETE;
            }
            break;
        default: kd_fail_locked(c, KD_INVALID); error = KD_INVALID; break;
        }
    }
    kd_unlock(c);
    return error;
}
/* The adapter calls this ONLY after release returns/handlers and transport are
 * independently quiescent. COMPLETE alone proves acknowledgements, not IRET. */
static inline int kd_retire(struct kd_control *c, uint64_t epoch) {
    int error = kd_lock(c);
    if (error) return error;
    if (epoch != c->epoch) error = KD_STALE;
    else if (c->state != KD_COMPLETE || kd_pending_mask(c)) error = KD_STATE;
    else c->state = KD_IDLE;
    kd_unlock(c);
    return error;
}
#endif
