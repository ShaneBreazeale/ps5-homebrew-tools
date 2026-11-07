/* Real capture core with simulated resident ownership; no console or DR writes. */
#include <assert.h>
#include <stdio.h>
#include "../residents/capture/capture.h"

static const uint64_t base = UINT64_C(0xffffffff90000000);
static struct kc_capture capture;
static unsigned reads;
static int read_error;

static int safe_read(void *ctx, uint64_t address, uint64_t *out) {
    assert(ctx == &reads);
    assert(address == base + 0x1000 - 0x68);
    ++reads;
    *out = UINT64_MAX; /* Must not leak even partial output on failure. */
    if (read_error) return -1;
    *out = UINT64_C(0x123456789abcdef0);
    return 0;
}
static struct kc_snapshot snapshot(void) {
    struct kc_snapshot s = {.build_id = {0x5a}, .session = {1, 2}, .generation = 3, .cpu_mask = 3};
    for (unsigned cpu = 0; cpu < 2; ++cpu) {
        s.cpu[cpu].granted_mask = 15;
        s.cpu[cpu].dr7 = 0x55;
        for (unsigned slot = 0; slot < KC_SLOT_LIMIT; ++slot) s.cpu[cpu].address[slot] = base + slot;
    }
    return s;
}
static void start(struct kc_snapshot *s, unsigned limit) {
    assert(kc_disarm(&capture) == (capture.initialized ? 0 : EINVAL));
    /* Each scenario owns separate fixture storage, with no real events. */
    memset(&capture, 0, sizeof(capture));
    assert(kc_begin(&capture, s, limit) == 0);
    reads = 0;
    read_error = 0;
}
static void bind_all(void) {
    for (unsigned i = 0; i < KC_SLOT_LIMIT; ++i) {
        unsigned slot = 99;
        assert(kc_bind(&capture, base + i, &slot) == 0 && slot == i);
    }
}
static struct kc_registers registers(unsigned slot) {
    struct kc_registers r = {.rip = base + slot, .rbp = base + 0x1000,
        .rax = UINT64_C(0xabcdef0187654321), .r15 = UINT64_C(0xfedcba9876543210)};
    return r;
}
static void capacity_and_ownership(void) {
    struct kc_snapshot s = snapshot(), original = s;
    start(&s, 32);
    bind_all();
    unsigned slot = 99;
    assert(capture.bound_mask == 15);
    assert(kc_bind(&capture, base + 4, &slot) == ENOSPC && slot == 99);
    assert(kc_bind(&capture, base, &slot) == 0 && slot == 0); /* Idempotent. */
    assert(kc_arm(&capture, &s) == 0);
    assert(kc_bind(&capture, base, &slot) == EBUSY);
    assert(kc_begin(&capture, &s, 32) == EBUSY);
    assert(memcmp(&original, &s, sizeof(s)) == 0);
    assert(kc_disarm(&capture) == 0);

    /* All DRs enabled by another owner: no grants, no borrowed slot. */
    s.cpu[0].granted_mask = s.cpu[1].granted_mask = 0;
    start(&s, 32);
    assert(kc_bind(&capture, base, &slot) == ENOSPC);
    assert(kc_arm(&capture, &s) == EINVAL);
    s = snapshot();
    s.cpu[1].granted_mask &= ~1u;
    start(&s, 32);
    assert(kc_bind(&capture, base, &slot) == ENOSPC);
    s = snapshot();
    s.cpu[1].address[0] += 8;
    start(&s, 32);
    assert(kc_bind(&capture, base, &slot) == ENOSPC);
}
static void events_and_limits(void) {
    struct kc_snapshot s = snapshot();
    struct kc_event event;
    start(&s, KC_RING_SIZE + 2);
    bind_all();
    assert(kc_arm(&capture, &s) == 0);
    assert(kc_drain(&capture, 0, &event) == EBUSY);
    for (unsigned i = 0; i < KC_RING_SIZE; ++i) {
        struct kc_registers r = registers(i % KC_SLOT_LIMIT);
        assert(kc_record(&capture, &s, 0, i % KC_SLOT_LIMIT, &r, safe_read, &reads) == 0);
    }
    struct kc_registers r = registers(0);
    assert(kc_record(&capture, &s, 0, 0, &r, safe_read, &reads) == ENOBUFS);
    assert(kc_record(&capture, &s, 0, 0, &r, safe_read, &reads) == ENOBUFS);
    assert(kc_record(&capture, &s, 0, 0, &r, safe_read, &reads) == EAGAIN);
    assert(capture.cpu[0].hits == KC_RING_SIZE + 2 && capture.cpu[0].dropped == 2);
    assert(reads == KC_RING_SIZE); /* Overflow/budget exhaustion do no reads. */
    assert(kc_record(&capture, &s, 1, 0, &r, safe_read, &reads) == 0);
    assert(capture.cpu[1].hits == 1 && capture.cpu[1].dropped == 0);
    assert(kc_disarm(&capture) == 0);
    assert(kc_begin(&capture, &s, 4) == EBUSY); /* Retain undrained evidence. */
    assert(kc_record(&capture, &s, 0, 0, &r, safe_read, &reads) == EBUSY);
    for (unsigned i = 0; i < KC_RING_SIZE; ++i) {
        assert(kc_drain(&capture, 0, &event) == 0);
        assert(event.schema == KC_EVENT_SCHEMA && event.cpu == 0 && event.slot == i % KC_SLOT_LIMIT);
        assert(event.sequence == i + 1 && event.generation == s.generation);
        assert(event.registers.rax == r.rax && event.registers.r15 == r.r15);
        assert(event.registers.rip == base + i % KC_SLOT_LIMIT);
        assert(event.frame_address == r.rbp - 0x68 && event.frame_value_valid == 1);
        assert(event.frame_value == UINT64_C(0x123456789abcdef0));
    }
    assert(kc_drain(&capture, 0, &event) == ENOENT);
    assert(kc_drain(&capture, 1, &event) == 0 && event.sequence == 1);
    /* Draining does not renew the finite hit budget. */
    assert(kc_arm(&capture, &s) == 0);
    assert(kc_record(&capture, &s, 0, 0, &r, safe_read, &reads) == EAGAIN);
}
static void revocation(void) {
    for (unsigned mode = 0; mode < 9; ++mode) {
        struct kc_snapshot s = snapshot();
        start(&s, 4);
        bind_all();
        assert(kc_arm(&capture, &s) == 0);
        struct kc_registers r = registers(0);
        assert(kc_record(&capture, &s, 0, 0, &r, safe_read, &reads) == 0);
        struct kc_snapshot changed = s;
        switch (mode) {
        case 0: ++changed.generation; break;
        case 1: ++changed.session[0]; break;
        case 2: ++changed.build_id[0]; break;
        case 3: changed.cpu_mask = 1; break;
        case 4: changed.cpu[1].granted_mask &= ~1u; break;
        case 5: ++changed.cpu[1].address[0]; break;
        case 6: changed.cpu[1].dr7 &= ~UINT64_C(1); break;
        case 7: changed.cpu[1].dr7 |= UINT64_C(1) << 16; break;
        case 8: changed.cpu[1].dr7 ^= 3; break;
        }
        assert(kc_record(&capture, &changed, 0, 0, &r, safe_read, &reads) == ESTALE);
        assert(capture.revoked && !capture.armed && reads == 1);
        assert(kc_arm(&capture, &s) == ESTALE); /* Restoring old snapshot cannot revive. */
        assert(kc_record(&capture, &s, 0, 0, &r, safe_read, &reads) == ESTALE);
        assert(kc_begin(&capture, &s, 4) == ESTALE);
        ++s.generation;
        assert(kc_begin(&capture, &s, 4) == EBUSY);
        struct kc_event event;
        assert(kc_drain(&capture, 0, &event) == 0);
        assert(event.generation == s.generation - 1 && event.registers.r15 == r.r15);
        assert(kc_begin(&capture, &s, 4) == 0);
    }
}
static void refusals_and_optional_read(void) {
    struct kc_snapshot s = snapshot();
    start(&s, 4);
    unsigned slot;
    assert(kc_bind(&capture, base, &slot) == 0);
    assert(kc_arm(&capture, &s) == 0);
    struct kc_registers r = registers(0);
    assert(kc_record(&capture, &s, 16, 0, &r, safe_read, &reads) == EINVAL);
    assert(kc_record(&capture, &s, 0, 4, &r, safe_read, &reads) == EINVAL);
    assert(kc_record(&capture, &s, 2, 0, &r, safe_read, &reads) == ENOENT);
    assert(kc_record(&capture, &s, 0, 1, &r, safe_read, &reads) == ENOENT);
    ++r.rip;
    assert(kc_record(&capture, &s, 0, 0, &r, safe_read, &reads) == ENOENT);
    assert(!reads && !capture.cpu[0].hits);
    --r.rip;
    read_error = 1;
    assert(kc_record(&capture, &s, 0, 0, &r, safe_read, &reads) == 0);
    read_error = 0;
    r.rbp = 0x68; /* Never dereference user/noncanonical/underflow candidates. */
    assert(kc_record(&capture, &s, 0, 0, &r, safe_read, &reads) == 0);
    r.rbp = UINT64_C(0xffff800000000000);
    assert(kc_record(&capture, &s, 0, 0, &r, safe_read, &reads) == 0);
    r.rbp = base + 0x1000;
    assert(kc_record(&capture, &s, 0, 0, &r, NULL, NULL) == 0);
    assert(reads == 1);
    assert(kc_disarm(&capture) == 0);
    for (unsigned i = 0; i < 4; ++i) {
        struct kc_event e;
        assert(kc_drain(&capture, 0, &e) == 0);
        assert(!e.frame_value_valid && !e.frame_value);
    }
    assert(kc_begin(&capture, &s, 0) == EINVAL);
    assert(kc_begin(&capture, &s, KC_MAX_CPU_HITS + 1) == EINVAL);
    for (unsigned mode = 0; mode < 8; ++mode) {
        struct kc_snapshot invalid = s;
        switch (mode) {
        case 0: invalid.cpu[0].granted_mask = 16; break;
        case 1: invalid.cpu_mask = 0x10000; break;
        case 2: invalid.cpu[0].address[0] = 0xffff000000000000; break;
        case 3: invalid.cpu[0].dr7 |= UINT64_C(1) << 16; break;
        case 4: invalid.cpu[0].dr7 = 0; break;
        case 5: invalid.generation = 0; break;
        case 6: memset(invalid.build_id, 0, 32); break;
        case 7: memset(invalid.session, 0, sizeof(invalid.session)); break;
        }
        assert(kc_begin(&capture, &invalid, 4) == EINVAL);
    }
}
int main(void) {
    capacity_and_ownership();
    events_and_limits();
    revocation();
    refusals_and_optional_read();
    puts("kernel capture core: four-slot ownership, event bounds and revocation passed");
    return 0;
}
