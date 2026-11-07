/* Concurrent native simulation of the real core; no kernel APIs or console. */
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include "../residents/execution/mailbox.h"

static struct kd_control control;
static uint64_t sequence, epoch;
static struct kd_frame frame(unsigned cpu) {
    struct kd_frame f = {.cookie = cpu + 1};
    f.registers.rip = UINT64_C(0xffffffff90001000) + cpu;
    f.registers.rsp = UINT64_C(0xffff800000001000) + cpu * 4096;
    f.registers.rax = UINT64_C(0xabcdef0012345678);
    f.registers.r15 = UINT64_C(0xfedcba9876543210);
    f.registers.rflags = 0x202;
    return f;
}
static struct kd_identity identity(uint32_t mask) {
    struct kd_identity id = {.build_id = {0x5a}, .session = {11, 22}, .generation = 7,
        .cpu_mask = mask, .max_hold_ticks = 10000, .capabilities = KD_CAP_ALL};
    return id;
}
static void setup(uint32_t mask) {
    struct kd_identity id = identity(mask);
    assert(kd_init(&control, &id) == KD_OK);
    sequence = epoch = 0;
}
static struct kd_request request(unsigned op, unsigned cpu, uint64_t deadline, uint64_t argument) {
    struct kd_request q = {.abi = KD_ABI, .size = sizeof(q), .operation = op, .cpu = cpu,
        .session = {11, 22}, .sequence = ++sequence, .epoch = epoch,
        .deadline = deadline, .argument = argument};
    return q;
}
static struct kd_reply command(unsigned op, unsigned cpu, uint64_t deadline, uint64_t argument,
        uint64_t now, unsigned expected) {
    struct kd_request q = request(op, cpu, deadline, argument);
    struct kd_reply r;
    assert(kd_command(&control, &q, now, &r) == KD_OK);
    assert(r.result == expected);
    epoch = r.epoch;
    return r;
}
static struct kd_reply inspect(uint64_t now) {
    struct kd_reply r;
    assert(kd_inspect(&control, now, &r) == KD_OK);
    return r;
}
static void arrive(unsigned cpu, uint64_t now) {
    struct kd_frame f = frame(cpu);
    assert(kd_enter(&control, epoch, cpu, &f, KD_RENDEZVOUS, 0, now) == KD_OK);
}
static void stop_two(unsigned limit) {
    setup(3);
    command(KD_STOP, 0, 1000, limit, 10, KD_OK);
    arrive(1, 10); arrive(0, 10);
    assert(inspect(10).state == KD_STOPPED);
}
static struct kd_action poll(unsigned cpu, uint64_t now, unsigned type) {
    struct kd_action a;
    assert(kd_cpu_poll(&control, epoch, cpu, now, &a) == KD_OK);
    assert(a.type == type);
    return a;
}
static void stopped(void) {
    setup(0x8005);
    struct kd_reply r = command(KD_STOP, 0, 1000, 2, 10, KD_OK);
    assert(r.state == KD_STOPPING && r.need_stop_mask == 0x8005 && epoch == 1);
    command(KD_STEP, 0, 500, 0, 10, KD_STATE);
    command(KD_REGISTERS, 0, 0, 0, 10, KD_STATE);
    arrive(2, 10); arrive(15, 10);
    r = inspect(10);
    assert(r.state == KD_STOPPING && r.parked_mask == 0x8004 && r.need_stop_mask == 1);
    struct kd_frame f = frame(0);
    assert(kd_enter(&control, epoch - 1, 0, &f, KD_RENDEZVOUS, 0, 10) == KD_STALE);
    assert(kd_enter(&control, epoch, 1, &f, KD_RENDEZVOUS, 0, 10) == KD_INVALID);
    f.cookie = 0;
    assert(kd_enter(&control, epoch, 0, &f, KD_RENDEZVOUS, 0, 10) == KD_INVALID);
    arrive(0, 10);
    r = inspect(10);
    assert(r.state == KD_STOPPED && r.parked_mask == r.cpu_mask && !r.need_stop_mask);
    f = frame(0); ++f.registers.rax;
    assert(kd_enter(&control, epoch, 0, &f, KD_RENDEZVOUS, 0, 10) == KD_STATE);
    r = command(KD_REGISTERS, 0, 0, 0, 10, KD_OK);
    assert(r.registers_valid && r.registers.rax == frame(0).registers.rax);
    assert(r.registers.r15 == frame(0).registers.r15);
    command(KD_REGISTERS, 16, 0, 0, 10, KD_INVALID);
    command(999, 0, 0, 0, 10, KD_UNSUPPORTED);
    assert(kd_retire(&control, epoch) == KD_STATE);
}
static void stepping(void) {
    stop_two(1);
    command(KD_STEP, 0, 500, 0, 10, KD_OK);
    poll(1, 10, KD_WAIT);
    struct kd_action a = poll(0, 10, KD_PREPARE_STEP);
    assert(a.frame_cookie == frame(0).cookie && a.step_ticket == a.ticket);
    poll(0, 10, KD_WAIT); /* No duplicate hardware mutation on a nested poll. */
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10) == KD_OK);
    struct kd_reply r = inspect(10);
    assert(r.state == KD_STEPPING && r.parked_mask == 2 && r.need_stop_mask == 1);
    command(KD_REGISTERS, 0, 0, 0, 10, KD_STATE);
    command(KD_STEP, 1, 400, 0, 10, KD_STATE);
    struct kd_frame after = frame(0);
    after.cookie = 99; /* A new trap frame must retain the original undo ledger. */
    ++after.registers.rip; ++after.registers.rax;
    after.registers.rflags |= 0x100; /* Simulated instrumentation flag. */
    assert(kd_enter(&control, epoch, 0, &after, KD_TRACE, a.ticket + 1, 10) == KD_STATE);
    assert(inspect(10).state == KD_STEPPING);
    assert(kd_enter(&control, epoch, 0, &after, KD_TRACE, a.ticket, 10) == KD_OK);
    assert(inspect(10).state == KD_STEP_CLEANUP);
    command(KD_STEP, 1, 400, 0, 10, KD_STATE);
    a = poll(0, 10, KD_CLEAN_STEP);
    assert(a.frame_cookie == 99 && a.original_cookie == frame(0).cookie);
    struct kd_action stale = a; ++stale.ticket;
    assert(kd_cpu_ack(&control, &stale, 1, NULL, 10) == KD_STALE);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10) == KD_INVALID);
    struct kd_frame cleaned = after;
    cleaned.registers.rflags &= ~UINT64_C(0x100);
    assert(kd_cpu_ack(&control, &a, 1, &cleaned, 10) == KD_OK);
    r = command(KD_REGISTERS, 0, 0, 0, 10, KD_OK);
    assert(r.state == KD_STOPPED && r.registers.rax == after.registers.rax);
    assert(r.registers.rflags == cleaned.registers.rflags);
    command(KD_STEP, 0, 400, 0, 10, KD_LIMIT);

    stop_two(2);
    command(KD_STEP, 1, 500, 0, 10, KD_OK);
    a = poll(1, 10, KD_PREPARE_STEP);
    command(KD_ABORT, 0, 0, 0, 10, KD_OK);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10) == KD_CANCELED); /* Never IRET/step. */
    assert(inspect(10).parked_mask == 3);
    command(KD_RESTORE, 0, 500, 0, 10, KD_OK);

    stop_two(2);
    command(KD_STEP, 0, 500, 0, 10, KD_OK);
    a = poll(0, 10, KD_PREPARE_STEP);
    assert(kd_cpu_ack(&control, &a, 0, NULL, 10) == KD_IO);
    assert(inspect(10).state == KD_FAILED && inspect(10).parked_mask == 3);

    stop_two(2);
    command(KD_STEP, 0, 500, 0, 10, KD_OK);
    a = poll(0, 10, KD_PREPARE_STEP);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10) == KD_OK);
    assert(kd_enter(&control, epoch, 0, &after, KD_OTHER_TRAP, a.ticket, 10) == KD_OK);
    r = inspect(10);
    assert(r.state == KD_FAILED && r.fault == KD_UNEXPECTED && r.parked_mask == 3);
    poll(0, 10, KD_WAIT);

    stop_two(2);
    command(KD_STEP, 0, 500, 0, 10, KD_OK);
    a = poll(0, 10, KD_PREPARE_STEP);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10) == KD_OK);
    assert(kd_enter(&control, epoch, 0, &after, KD_TRACE, a.ticket, 10) == KD_OK);
    a = poll(0, 10, KD_CLEAN_STEP);
    assert(kd_cpu_ack(&control, &a, 0, NULL, 10) == KD_IO);
    assert(inspect(10).state == KD_FAILED && inspect(10).parked_mask == 3);
    command(KD_STEP, 0, 400, 0, 10, KD_STATE);
    command(KD_RESTORE, 0, 400, 0, 10, KD_OK);

    stop_two(2);
    command(KD_STEP, 0, 500, 0, 10, KD_OK);
    a = poll(0, 10, KD_PREPARE_STEP);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10) == KD_OK);
    assert(kd_enter(&control, epoch, 0, &after, KD_TRACE, a.ticket, 10) == KD_OK);
    a = poll(0, 10, KD_CLEAN_STEP);
    cleaned.registers.rax = frame(0).registers.rax; /* Incorrect whole-frame rewind. */
    assert(kd_cpu_ack(&control, &a, 1, &cleaned, 10) == KD_IO);
    assert(inspect(10).state == KD_FAILED && inspect(10).parked_mask == 3);
}
static void restoration(void) {
    stop_two(2);
    command(KD_RESTORE, 0, 500, 0, 10, KD_OK);
    struct kd_action a = poll(0, 10, KD_RESTORE_CPU);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10) == KD_OK);
    poll(0, 10, KD_WAIT); /* All-CPU readback barrier before any release. */
    struct kd_action b = poll(1, 10, KD_RESTORE_CPU);
    assert(kd_cpu_ack(&control, &b, 0, NULL, 10) == KD_IO);
    struct kd_reply r = inspect(10);
    assert(r.state == KD_FAILED && r.restored_mask == 1 && !r.released_mask);
    poll(0, 10, KD_WAIT);
    command(KD_RESTORE, 0, 500, 0, 10, KD_OK);
    a = poll(0, 10, KD_RESTORE_CPU); b = poll(1, 10, KD_RESTORE_CPU);
    assert(kd_cpu_ack(&control, &b, 1, NULL, 10) == KD_OK);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10) == KD_OK);
    r = inspect(10);
    assert(r.state == KD_RELEASING && r.restored_mask == 3 && !r.released_mask);
    a = poll(0, 10000, KD_RELEASE_CPU); /* Lease expiry cannot split a release commit. */
    b = poll(1, 10000, KD_RELEASE_CPU);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10000) == KD_OK);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10000) == KD_STALE);
    assert(inspect(10000).state == KD_RELEASING);
    assert(kd_cpu_ack(&control, &b, 1, NULL, 10000) == KD_OK);
    r = inspect(10000);
    assert(r.state == KD_COMPLETE && r.released_mask == 3 && !r.parked_mask && r.fault == KD_IO);
    assert(kd_retire(&control, epoch + 1) == KD_STALE);
    assert(kd_retire(&control, epoch) == KD_OK);
    command(KD_STOP, 0, 11000, 1, 10000, KD_OK);
    assert(epoch == 2);
    assert(kd_cpu_ack(&control, &b, 1, NULL, 10000) == KD_STALE);
    assert(inspect(10000).state == KD_STOPPING);

    stop_two(1);
    command(KD_RESTORE, 0, 500, 0, 10, KD_OK);
    a = poll(0, 10, KD_RESTORE_CPU); b = poll(1, 10, KD_RESTORE_CPU);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10) == KD_OK);
    assert(kd_cpu_ack(&control, &b, 1, NULL, 10) == KD_OK);
    a = poll(0, 10, KD_RELEASE_CPU); b = poll(1, 10, KD_RELEASE_CPU);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10) == KD_OK);
    assert(kd_cpu_ack(&control, &b, 0, NULL, 10) == KD_IO);
    r = inspect(10);
    assert(r.state == KD_FAILED && r.released_mask == 1 && r.parked_mask == 2);
    command(KD_RESTORE, 0, 500, 0, 10, KD_BUSY);
    assert(kd_retire(&control, epoch) == KD_STATE);
    poll(1, 10, KD_WAIT); /* Partial release is not a completed recovery. */
}
static void timeouts(void) {
    setup(3);
    command(KD_STOP, 0, 100, 2, 10, KD_OK);
    arrive(0, 10);
    struct kd_reply r = inspect(100);
    assert(r.state == KD_FAILED && r.fault == KD_TIMEOUT && r.parked_mask == 1 && r.need_stop_mask == 2);
    poll(0, 100, KD_WAIT);
    command(KD_RESTORE, 0, 200, 0, 100, KD_BUSY);
    arrive(1, 100);
    command(KD_RESTORE, 0, 200, 0, 100, KD_OK);
    struct kd_action a = poll(0, 100, KD_RESTORE_CPU);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 200) == KD_OK);
    assert(inspect(200).state == KD_FAILED && !inspect(200).released_mask);

    stop_two(2);
    command(KD_STEP, 0, 100, 0, 10, KD_OK);
    a = poll(0, 10, KD_PREPARE_STEP);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 100) == KD_CANCELED);
    assert(inspect(100).state == KD_FAILED && inspect(100).parked_mask == 3);

    stop_two(2);
    command(KD_STEP, 0, 100, 0, 10, KD_OK);
    a = poll(0, 10, KD_PREPARE_STEP);
    assert(kd_cpu_ack(&control, &a, 1, NULL, 10) == KD_OK);
    r = inspect(100);
    assert(r.state == KD_FAILED && r.need_stop_mask == 1);
    command(KD_RESTORE, 0, 200, 0, 100, KD_BUSY);
    struct kd_frame f = frame(0);
    assert(kd_enter(&control, epoch, 0, &f, KD_RENDEZVOUS, 0, 100) == KD_OK);
    command(KD_RESTORE, 0, 200, 0, 100, KD_OK);

    stop_two(2);
    assert(inspect(9).state == KD_FAILED); /* A backwards hardware clock is refused. */
    command(KD_RESTORE, 0, 200, 0, 9, KD_INVALID);

    stop_two(2);
    assert(kd_fault(&control, epoch, KD_STALE, 10) == KD_OK);
    r = inspect(10);
    assert(r.state == KD_FAILED && r.fault == KD_STALE && r.parked_mask == 3);
    poll(0, 10, KD_WAIT);
}
static void mailbox(void) {
    setup(1);
    struct kd_mailbox m = {0};
    struct kd_request q = request(KD_STOP, 0, 1000, 1);
    struct kd_reply r, first;
    assert(kd_mail_submit(&m, &q) == KD_OK);
    assert(kd_mail_submit(&m, &q) == KD_BUSY);
    __atomic_store_n(&control.gate, 1, __ATOMIC_RELAXED);
    assert(kd_mail_service(&m, &control, 10) == KD_BUSY);
    assert(kd_mail_receive(&m, &r) == KD_BUSY);
    __atomic_store_n(&control.gate, 0, __ATOMIC_RELEASE);
    assert(kd_mail_service(&m, &control, 10) == KD_OK);
    assert(kd_mail_service(&m, &control, 10) == KD_BUSY);
    assert(kd_mail_receive(&m, &first) == KD_OK && first.result == KD_OK);
    assert(kd_mail_receive(&m, &r) == KD_BUSY);
    epoch = first.epoch;
    arrive(0, 10);
    assert(kd_mail_submit(&m, &q) == KD_OK); /* Exact replay returns cached STOPPING. */
    assert(kd_mail_service(&m, &control, 10) == KD_OK);
    assert(kd_mail_receive(&m, &r) == KD_OK && !memcmp(&r, &first, sizeof(r)));
    assert(inspect(10).state == KD_STOPPED); /* Replay did not re-stop/reset. */
    ++q.argument;
    assert(kd_command(&control, &q, 10, &r) == KD_OK && r.result == KD_STALE);
    command(KD_STATUS, 0, 0, 0, 10, KD_OK);
    q = request(KD_STATUS, 0, 0, 0);
    ++q.sequence;
    assert(kd_command(&control, &q, 10, &r) == KD_OK && r.result == KD_STALE);
    --q.sequence;
    assert(kd_command(&control, &q, 10, &r) == KD_OK && r.result == KD_OK);
}

struct simulation {
    struct kd_mailbox mail;
    unsigned executed[KC_CPU_LIMIT], restored[KC_CPU_LIMIT];
};
struct worker { struct simulation *simulation; unsigned cpu; };
static void *cpu_worker(void *opaque) {
    struct worker *w = opaque;
    struct simulation *s = w->simulation;
    unsigned cpu = w->cpu;
    struct kd_frame f = frame(cpu);
    int arrived = 0;
    for (unsigned attempts = 0; attempts < 10000000; ++attempts) {
        int error = kd_mail_service(&s->mail, &control, 10);
        assert(error == KD_OK || error == KD_BUSY);
        struct kd_reply r;
        if (kd_inspect(&control, 10, &r) == KD_BUSY) { sched_yield(); continue; }
        assert(r.state != KD_FAILED);
        if (!arrived && r.state == KD_STOPPING) {
            error = kd_enter(&control, r.epoch, cpu, &f, KD_RENDEZVOUS, 0, 10);
            assert(error == KD_OK || error == KD_BUSY);
            if (!error) arrived = 1;
        }
        if (!arrived) { sched_yield(); continue; }
        struct kd_action a;
        error = kd_cpu_poll(&control, r.epoch, cpu, 10, &a);
        assert(error == KD_OK || error == KD_BUSY);
        if (error || !a.type) { sched_yield(); continue; }
        if (a.type == KD_RELEASE_CPU) {
            do { error = kd_inspect(&control, 10, &r); } while (error == KD_BUSY);
            assert(!error && r.restored_mask == r.cpu_mask && s->restored[cpu]);
        }
        do { error = kd_cpu_ack(&control, &a, 1, a.type == KD_CLEAN_STEP ? &f : NULL, 10); } while (error == KD_BUSY);
        assert(error == KD_OK);
        if (a.type == KD_PREPARE_STEP) {
            do { error = kd_inspect(&control, 10, &r); } while (error == KD_BUSY);
            assert(!error && r.state == KD_STEPPING && r.parked_mask == (r.cpu_mask & ~(1u << cpu)));
            ++s->executed[cpu]; ++f.registers.rip; ++f.registers.rax;
            do { error = kd_enter(&control, a.epoch, cpu, &f, KD_TRACE, a.ticket, 10); } while (error == KD_BUSY);
            assert(error == KD_OK);
        } else if (a.type == KD_RESTORE_CPU) ++s->restored[cpu];
        else if (a.type == KD_RELEASE_CPU) return NULL;
    }
    assert(!"simulation failed to progress within bounded host attempts");
    return NULL;
}
static struct kd_reply transact(struct simulation *s, struct kd_request q) {
    assert(kd_mail_submit(&s->mail, &q) == KD_OK);
    for (unsigned attempts = 0; attempts < 10000000; ++attempts) {
        struct kd_reply r;
        int error = kd_mail_receive(&s->mail, &r);
        if (!error) { assert(!r.result && r.sequence == q.sequence); epoch = r.epoch; return r; }
        assert(error == KD_BUSY);
        sched_yield();
    }
    assert(!"mailbox reply deadline");
    abort();
}
static struct kd_reply await_state(unsigned state) {
    for (unsigned attempts = 0; attempts < 10000000; ++attempts) {
        struct kd_reply r;
        if (!kd_inspect(&control, 10, &r)) {
            assert(r.state != KD_FAILED);
            if (r.state == state) return r;
        }
        sched_yield();
    }
    assert(!"state deadline");
    abort();
}
static void concurrent(void) {
    setup(0xffff);
    struct simulation s = {0};
    struct worker workers[KC_CPU_LIMIT];
    pthread_t threads[KC_CPU_LIMIT];
    for (unsigned i = 0; i < KC_CPU_LIMIT; ++i) {
        workers[i] = (struct worker){&s, i};
        assert(!pthread_create(&threads[i], NULL, cpu_worker, &workers[i]));
    }
    transact(&s, request(KD_STOP, 0, 1000, 32));
    await_state(KD_STOPPED);
    for (unsigned i = 0; i < 32; ++i) {
        transact(&s, request(KD_STEP, i % KC_CPU_LIMIT, 1000, 0));
        struct kd_reply r = await_state(KD_STOPPED);
        assert(r.steps == i + 1 && r.parked_mask == 0xffff);
        r = transact(&s, request(KD_REGISTERS, i % KC_CPU_LIMIT, 0, 0));
        assert(r.registers_valid && r.registers.rax == frame(0).registers.rax + 1 + i / KC_CPU_LIMIT);
    }
    transact(&s, request(KD_RESTORE, 0, 1000, 0));
    struct kd_reply r = await_state(KD_COMPLETE);
    assert(r.restored_mask == 0xffff && r.released_mask == 0xffff && !r.fault);
    for (unsigned i = 0; i < KC_CPU_LIMIT; ++i) {
        assert(!pthread_join(threads[i], NULL));
        assert(s.executed[i] == 2 && s.restored[i] == 1);
    }
    assert(kd_retire(&control, epoch) == KD_OK);
}

/* Integration model only: adapter quiescence, persistence and release progress
 * are simulated. No hardware adapter or live trap is supplied by these tests. */
static struct kc_capture reusable_capture;
static struct kc_snapshot capture_owner(uint32_t mask) {
    struct kd_identity id = identity(mask);
    struct kc_snapshot s = {.session={11,22}, .generation=7, .cpu_mask=mask};
    memcpy(s.build_id, id.build_id, sizeof(s.build_id));
    for (unsigned cpu=0; cpu<KC_CPU_LIMIT; ++cpu) if (mask & (1u<<cpu)) {
        s.cpu[cpu].granted_mask=15; s.cpu[cpu].dr7=0x55;
        for (unsigned slot=0; slot<KC_SLOT_LIMIT; ++slot)
            s.cpu[cpu].address[slot]=UINT64_C(0xffffffff90001000)+slot;
    }
    return s;
}
static void capture_window(struct kc_snapshot *s, unsigned window) {
    assert(kc_begin(&reusable_capture, s, KC_RING_SIZE+1) == 0);
    for (unsigned slot=0; slot<KC_SLOT_LIMIT; ++slot) {
        unsigned assigned=99;
        assert(kc_bind(&reusable_capture, s->cpu[0].address[slot], &assigned) == 0 && assigned == slot);
    }
    assert(kc_arm(&reusable_capture, s) == 0);
    for (unsigned cpu=0; cpu<KC_CPU_LIMIT; ++cpu) if (s->cpu_mask & (1u<<cpu)) {
        struct kc_registers regs=frame(cpu).registers;
        regs.rax=((uint64_t)window<<32)|cpu;
        for (unsigned event=0; event<KC_RING_SIZE; ++event) {
            unsigned slot=event % KC_SLOT_LIMIT;
            regs.rip=s->cpu[cpu].address[slot];
            assert(kc_record(&reusable_capture,s,cpu,slot,&regs,NULL,NULL) == 0);
        }
        regs.rip=s->cpu[cpu].address[0];
        assert(kc_record(&reusable_capture,s,cpu,0,&regs,NULL,NULL) == ENOBUFS);
        assert(reusable_capture.cpu[cpu].dropped == 1);
        assert(kc_record(&reusable_capture,s,cpu,0,&regs,NULL,NULL) == EAGAIN);
    }
    assert(kc_begin(&reusable_capture,s,KC_RING_SIZE+1) == EBUSY);
    assert(kc_disarm(&reusable_capture) == 0);
    assert(kc_begin(&reusable_capture,s,KC_RING_SIZE+1) == EBUSY); /* Evidence retained. */
}
static unsigned drain_window(const struct kc_snapshot *s, unsigned window) {
    unsigned drained=0;
    for (unsigned cpu=0; cpu<KC_CPU_LIMIT; ++cpu) if (s->cpu_mask & (1u<<cpu)) {
        struct kc_event event;
        for (unsigned index=0; index<KC_RING_SIZE; ++index) {
            assert(kc_drain(&reusable_capture,cpu,&event) == 0);
            assert(event.cpu == cpu && event.sequence == index+1);
            assert(event.registers.rax == (((uint64_t)window<<32)|cpu));
            assert(event.registers.r15 == frame(cpu).registers.r15);
            ++drained;
        }
        assert(kc_drain(&reusable_capture,cpu,&event) == ENOENT);
        assert(reusable_capture.cpu[cpu].hits == KC_RING_SIZE+1);
    }
    return drained;
}
static void reusable_windows(void) {
    setup(0xffff); /* One coordinator initialization for the entire experiment. */
    struct kc_snapshot s=capture_owner(0xffff), original=s;
    unsigned events=0;
    for (unsigned window=1; window<=100; ++window) {
        uint64_t now=window*10;
        assert(inspect(now).state == KD_IDLE);
        capture_window(&s,window);
        command(KD_STOP,0,now+1000,1,now,KD_OK);
        for (unsigned cpu=0; cpu<KC_CPU_LIMIT; ++cpu) arrive(cpu,now);
        assert(inspect(now).state == KD_STOPPED);
        events+=drain_window(&s,window); /* Simulated export, not host durability. */
        assert(inspect(now).state == KD_STOPPED); /* Draining never resumes execution. */
        assert(kd_retire(&control,epoch) == KD_STATE);
        command(KD_RESTORE,0,now+1000,0,now,KD_OK);
        for (unsigned cpu=0; cpu<KC_CPU_LIMIT; ++cpu) {
            struct kd_action action=poll(cpu,now,KD_RESTORE_CPU);
            assert(kd_cpu_ack(&control,&action,1,NULL,now) == KD_OK);
            if (cpu+1<KC_CPU_LIMIT) {
                assert(inspect(now).state == KD_RESTORING);
                poll(cpu,now,KD_WAIT); /* No release before all restore readbacks. */
            }
        }
        for (unsigned cpu=0; cpu<KC_CPU_LIMIT; ++cpu) {
            struct kd_action action=poll(cpu,now,KD_RELEASE_CPU);
            assert(kd_cpu_ack(&control,&action,1,NULL,now) == KD_OK);
        }
        struct kd_reply r=inspect(now);
        assert(r.state == KD_COMPLETE && r.restored_mask == 0xffff && r.released_mask == 0xffff);
        assert(!r.parked_mask && !r.fault);
        /* Only the simulated adapter can assert post-return quiescence here. */
        assert(kd_retire(&control,epoch) == KD_OK);
        assert(!memcmp(&s,&original,sizeof(s)) && epoch == window);
    }
    assert(events == 25600);
    puts("100 windows, 16 simulated CPUs, 25600 drained events, 1 coordinator initialization");
}
static void drain_is_not_recovery(int missing_cpu) {
    setup(3);
    struct kc_snapshot s=capture_owner(3);
    capture_window(&s,1);
    command(KD_STOP,0,1000,1,10,KD_OK);
    arrive(0,10);
    if (!missing_cpu) {
        arrive(1,10);
        command(KD_RESTORE,0,500,0,10,KD_OK);
        struct kd_action action=poll(0,10,KD_RESTORE_CPU);
        assert(kd_cpu_ack(&control,&action,1,NULL,10) == KD_OK);
        action=poll(1,10,KD_RESTORE_CPU);
        assert(kd_cpu_ack(&control,&action,0,NULL,10) == KD_IO);
    }
    assert(drain_window(&s,1) == 32);
    struct kd_reply r=inspect(10);
    assert(r.state == (missing_cpu ? KD_STOPPING : KD_FAILED));
    assert(!r.released_mask && r.parked_mask == (missing_cpu ? 1u : 3u));
    assert(kd_retire(&control,epoch) == KD_STATE);
    poll(0,10,KD_WAIT); poll(1,10,KD_WAIT);
    if (missing_cpu) {
        r=inspect(1000);
        assert(r.state == KD_FAILED && r.fault == KD_TIMEOUT && r.need_stop_mask == 2);
    }
    puts("Drained buffers did not release an incomplete or failed kernel stop");
}
int main(int argc, char **argv) {
    assert(argc == 2);
    if (!strcmp(argv[1], "wire")) {
        setup(1);
        struct kd_request q;
        struct kd_reply r;
        assert(fread(&q, 1, sizeof(q), stdin) == sizeof(q) && getchar() == EOF);
        assert(kd_command(&control, &q, 10, &r) == KD_OK);
        assert(fwrite(&r, 1, sizeof(r), stdout) == sizeof(r));
        return 0;
    } else if (!strcmp(argv[1], "stop")) stopped();
    else if (!strcmp(argv[1], "step")) stepping();
    else if (!strcmp(argv[1], "restore")) restoration();
    else if (!strcmp(argv[1], "timeout")) timeouts();
    else if (!strcmp(argv[1], "mailbox")) mailbox();
    else if (!strcmp(argv[1], "concurrent")) concurrent();
    else if (!strcmp(argv[1], "reuse")) reusable_windows();
    else if (!strcmp(argv[1], "drain-failed-restore")) drain_is_not_recovery(0);
    else if (!strcmp(argv[1], "drain-missing-cpu")) drain_is_not_recovery(1);
    else return 2;
    printf("kernel execution %s: passed (host simulation only)\n", argv[1]);
    return 0;
}
