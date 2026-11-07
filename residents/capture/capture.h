/* SPDX-License-Identifier: GPL-3.0-or-later
 * Cooperative resident capture core. No DR writes, trap installation or resume.
 * Caller serializes operations without waiting in an exception handler, and
 * supplies synchronized ownership snapshots from its reviewed resident adapter.
 */
#ifndef KERNEL_EVENT_CAPTURE_H
#define KERNEL_EVENT_CAPTURE_H
#include <errno.h>
#include <stdint.h>
#include <string.h>

#define KC_SLOT_LIMIT 4u
#define KC_CPU_LIMIT 16u
#define KC_RING_SIZE 16u
#define KC_MAX_CPU_HITS 4096u
#define KC_EVENT_SCHEMA 1u

struct kc_cpu_slots {
    uint64_t address[KC_SLOT_LIMIT], dr7;
    /* Explicit permission to observe existing resident-owned execution traps.
     * An enabled DR7 bit alone is never a grant. */
    uint32_t granted_mask;
};
struct kc_snapshot {
    unsigned char build_id[32];
    uint64_t session[2], generation;
    uint32_t cpu_mask;
    struct kc_cpu_slots cpu[KC_CPU_LIMIT];
};
struct kc_registers {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15, rip, rflags;
};
struct kc_event {
    uint32_t schema, cpu, slot, frame_value_valid;
    uint64_t generation, sequence, frame_address, frame_value;
    struct kc_registers registers;
};
_Static_assert(sizeof(struct kc_registers) == 144, "capture register layout");
_Static_assert(sizeof(struct kc_event) == 192, "capture schema-1 event layout");
struct kc_ring {
    uint64_t hits, dropped;
    uint32_t head, count;
    struct kc_event events[KC_RING_SIZE];
};
struct kc_capture {
    struct kc_snapshot owner;
    uint32_t initialized, armed, revoked, bound_mask, cpu_hit_limit;
    struct kc_ring cpu[KC_CPU_LIMIT];
};
/* Optional, bounded, fault-contained eight-byte read. It must not fault into
 * this handler, block, allocate or invoke network/scheduler-dependent code. */
typedef int (*kc_safe_read)(void *, uint64_t, uint64_t *);

static inline int kc_pointer(uint64_t address) {
    return address >= UINT64_C(0xffff800000000000);
}
static inline uint64_t kc_slot_mask(unsigned slot) {
    return (UINT64_C(3) << (2 * slot)) | (UINT64_C(15) << (16 + 4 * slot));
}
static inline int kc_snapshot_valid(const struct kc_snapshot *s) {
    unsigned char build = 0;
    if (!s || !s->generation || !(s->session[0] | s->session[1])
        || !s->cpu_mask || (s->cpu_mask & ~UINT32_C(0xffff))) return 0;
    for (unsigned i = 0; i < sizeof(s->build_id); ++i) build |= s->build_id[i];
    if (!build) return 0;
    for (unsigned cpu = 0; cpu < KC_CPU_LIMIT; ++cpu) {
        const struct kc_cpu_slots *c = &s->cpu[cpu];
        if (c->granted_mask & ~UINT32_C(0xf)) return 0;
        if (!(s->cpu_mask & (1u << cpu))) {
            if (c->granted_mask) return 0;
            continue;
        }
        for (unsigned slot = 0; slot < KC_SLOT_LIMIT; ++slot) {
            if (!(c->granted_mask & (1u << slot))) continue;
            /* Existing enabled execution breakpoint, LEN=1 (RW/LEN=0000).
             * Data watchpoints and user addresses are outside this core. */
            if (!kc_pointer(c->address[slot]) || !(c->dr7 & (UINT64_C(3) << (2 * slot)))
                || (c->dr7 & (UINT64_C(15) << (16 + 4 * slot)))) return 0;
        }
    }
    return 1;
}
/* Zero-initialize storage before first use. Starting a new capture requires
 * disarm plus adapter quiescence; a fresh session/generation is adapter-owned. */
static inline int kc_begin(struct kc_capture *c, const struct kc_snapshot *s, unsigned cpu_hit_limit) {
    if (!c || !kc_snapshot_valid(s) || !cpu_hit_limit || cpu_hit_limit > KC_MAX_CPU_HITS) return EINVAL;
    if (c->armed) return EBUSY;
    if (c->initialized) {
        if (c->revoked && !memcmp(c->owner.session, s->session, sizeof(s->session))
            && s->generation <= c->owner.generation) return ESTALE;
        for (unsigned cpu = 0; cpu < KC_CPU_LIMIT; ++cpu)
            if (c->cpu[cpu].count) return EBUSY;
    }
    struct kc_snapshot owner = *s;
    memset(c, 0, sizeof(*c));
    c->owner = owner;
    c->initialized = 1;
    c->cpu_hit_limit = cpu_hit_limit;
    return 0;
}
/* Bind one address on one consistently assigned hardware slot across the CPU
 * scope. Returns ENOSPC when grants/addresses differ or all four are bound.
 * An identical binding is idempotent. No slot is programmed or displaced. */
static inline int kc_bind(struct kc_capture *c, uint64_t address, unsigned *slot_out) {
    if (!c || !c->initialized || !slot_out || !kc_pointer(address)) return EINVAL;
    if (c->armed) return EBUSY;
    if (c->revoked) return ESTALE;
    for (unsigned slot = 0; slot < KC_SLOT_LIMIT; ++slot) {
        int common = 1;
        for (unsigned cpu = 0; cpu < KC_CPU_LIMIT; ++cpu) {
            if (!(c->owner.cpu_mask & (1u << cpu))) continue;
            const struct kc_cpu_slots *s = &c->owner.cpu[cpu];
            if (!(s->granted_mask & (1u << slot)) || s->address[slot] != address) common = 0;
        }
        if (common) {
            c->bound_mask |= 1u << slot;
            *slot_out = slot;
            return 0;
        }
    }
    return ENOSPC;
}
static inline int kc_owner_matches(const struct kc_capture *c, const struct kc_snapshot *s) {
    if (!kc_snapshot_valid(s) || memcmp(c->owner.build_id, s->build_id, 32)
        || memcmp(c->owner.session, s->session, sizeof(s->session))
        || c->owner.generation != s->generation || c->owner.cpu_mask != s->cpu_mask) return 0;
    for (unsigned cpu = 0; cpu < KC_CPU_LIMIT; ++cpu) {
        if (!(s->cpu_mask & (1u << cpu))) continue;
        for (unsigned slot = 0; slot < KC_SLOT_LIMIT; ++slot) {
            if (!(c->bound_mask & (1u << slot))) continue;
            if (!(s->cpu[cpu].granted_mask & (1u << slot))
                || c->owner.cpu[cpu].address[slot] != s->cpu[cpu].address[slot]
                || ((c->owner.cpu[cpu].dr7 ^ s->cpu[cpu].dr7) & kc_slot_mask(slot))) return 0;
        }
    }
    return 1;
}
static inline int kc_verify(struct kc_capture *c, const struct kc_snapshot *s) {
    if (c->revoked) return ESTALE;
    if (!kc_owner_matches(c, s)) {
        c->armed = 0;
        c->revoked = 1;
        return ESTALE;
    }
    return 0;
}
static inline int kc_arm(struct kc_capture *c, const struct kc_snapshot *s) {
    if (!c || !c->initialized || !c->bound_mask) return EINVAL;
    int error = kc_verify(c, s);
    if (error) return error;
    c->armed = 1;
    return 0;
}
/* Call only for an execution trap whose slot the resident already proved.
 * DR6 alone is insufficient. The resident retains instruction emulation,
 * exception chaining and resume ownership, including after any error here. */
static inline int kc_record(struct kc_capture *c, const struct kc_snapshot *s,
        unsigned cpu, unsigned slot, const struct kc_registers *registers,
        kc_safe_read read, void *ctx) {
    if (!c || !c->initialized || !registers || cpu >= KC_CPU_LIMIT || slot >= KC_SLOT_LIMIT) return EINVAL;
    if (c->revoked) return ESTALE;
    if (!c->armed) return EBUSY;
    int error = kc_verify(c, s);
    if (error) return error;
    if (!(c->owner.cpu_mask & (1u << cpu)) || !(c->bound_mask & (1u << slot))
        || registers->rip != c->owner.cpu[cpu].address[slot]) return ENOENT;
    struct kc_ring *ring = &c->cpu[cpu];
    if (ring->hits == c->cpu_hit_limit) return EAGAIN;
    ++ring->hits;
    if (ring->count == KC_RING_SIZE) {
        ++ring->dropped;
        return ENOBUFS;
    }
    struct kc_event *event = &ring->events[(ring->head + ring->count) % KC_RING_SIZE];
    memset(event, 0, sizeof(*event));
    event->schema = KC_EVENT_SCHEMA;
    event->cpu = cpu;
    event->slot = slot;
    event->generation = c->owner.generation;
    event->sequence = ring->hits;
    event->registers = *registers;
    if (registers->rbp >= UINT64_C(0xffff800000000068)) {
        event->frame_address = registers->rbp - 0x68;
        uint64_t value = 0;
        if (read && !read(ctx, event->frame_address, &value)) {
            event->frame_value = value;
            event->frame_value_valid = 1;
        }
    }
    ++ring->count;
    return 0;
}
/* Disarm logging only. The adapter must quiesce in-flight callbacks before
 * draining/reinitializing and independently complete any hardware cleanup. */
static inline int kc_disarm(struct kc_capture *c) {
    if (!c || !c->initialized) return EINVAL;
    c->armed = 0;
    return 0;
}
static inline int kc_drain(struct kc_capture *c, unsigned cpu, struct kc_event *out) {
    if (!c || !c->initialized || !out || cpu >= KC_CPU_LIMIT
        || !(c->owner.cpu_mask & (1u << cpu))) return EINVAL;
    if (c->armed) return EBUSY;
    struct kc_ring *ring = &c->cpu[cpu];
    if (!ring->count) return ENOENT;
    *out = ring->events[ring->head];
    ring->head = (ring->head + 1) % KC_RING_SIZE;
    --ring->count;
    return 0;
}
#endif
