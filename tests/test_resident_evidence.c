/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "../residents/evidence/evidence.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

static struct re_store store;
static const uint64_t session[2] = {1, 2};
static const unsigned char build[32] = {0x22};
struct sink { unsigned char bytes[5000000]; unsigned count, chunk, calls; int fail, busy; };
static struct sink normal, panic_sink;
static int output(void *ctx, const unsigned char *p, unsigned n) {
    struct sink *s = ctx; ++s->calls;
    if (s->fail) return -1;
    if (s->busy) return 0;
    if (s->chunk && n > s->chunk) n = s->chunk;
    assert(s->count+n <= sizeof(s->bytes));
    memcpy(s->bytes+s->count, p, n); s->count += n; return (int)n;
}
static void init(unsigned budget) {
    assert(re_init(&store, session, build, 0xffff, 1, budget) == RE_OK);
    memset(&normal, 0, sizeof(normal)); memset(&panic_sink, 0, sizeof(panic_sink));
}
static void validate(const struct sink *s, unsigned kind) {
    assert(s->count % PE_SIZE == 0);
    for (unsigned off = 0; off < s->count; off += PE_SIZE) {
        const unsigned char *p = s->bytes+off;
        assert(!memcmp(p, "PS5EVID1", 8)); assert(p[12] == kind);
        assert(pe_crc32(p, 284) == (uint32_t)(pe_get64(p+280)>>32));
    }
}
static void basics(void) {
    struct re_export e, p;
    init(40);
    assert(re_trace(&store, 16, 0, 1, 100, 0, 1, NULL) == RE_INVALID);
    assert(re_trace(&store, 0, 1, 1, 100, 0, 1, NULL) == RE_OK); /* disabled */
    assert(store.cpu[0].hits == 0);
    for (unsigned i = 0; i < RE_RING; ++i)
        assert(re_trace(&store, 0, 0, 1, 100, PE_BEFORE, i, NULL) == RE_OK);
    assert(re_trace(&store, 0, 0, 1, 100, PE_AFTER, 40, NULL) == RE_FULL);
    assert(store.cpu[0].rejected == 1);
    store.cpu[0].writer = 1; /* interrupted producer */
    assert(re_trace(&store, 0, 0, 1, 100, 0, 1, NULL) == RE_BUSY);
    uint64_t regs[18] = {0}; regs[16] = UINT64_C(0xffffffff8d9cfc12);
    assert(re_panic(&store, 0, 77, 1, 200, 42, NULL, regs) == RE_OK);
    assert(re_panic(&store, 0, 77, 1, 200, 42, NULL, regs) == RE_BUSY);
    assert(re_export_init(&e, 0, 4096, 1, 10000) == RE_OK);
    e.gate = 1; /* interrupted normal exporter/device callback */
    assert(re_export_poll(&store, &e, 2, output, &normal) == RE_BUSY);
    assert(re_export_init(&p, 1, 4096, 1, 10000) == RE_OK);
    panic_sink.chunk = 7;
    while (re_export_poll(&store, &p, 2, output, &panic_sink) != RE_EMPTY) {}
    assert(panic_sink.count == PE_SIZE);
    validate(&panic_sink, PE_PANIC);
    assert(pe_get64(panic_sink.bytes+128+16*8) == regs[16]);
    assert(store.cpu[0].head == 0); /* panic export never touches trace ring */
    e.gate = 0; store.cpu[0].writer = 0; normal.chunk = 13;
    while (re_export_poll(&store, &e, 3, output, &normal) != RE_EMPTY) {}
    assert(normal.count == RE_RING*PE_SIZE); validate(&normal, PE_TRACE);
    assert(re_trace(&store, 0, 0, 1, 100, PE_AFTER, 43, NULL) == RE_OK);
    normal.chunk = 0;
    assert(re_export_poll(&store, &e, 4, output, &normal) == RE_OK);
    const unsigned char *last = normal.bytes+RE_RING*PE_SIZE;
    assert(pe_get64(last+32) == 34 && last[276] == 2);
    for (unsigned i = 34; i < 40; ++i) assert(re_trace(&store, 0, 0, 1, 100, 0, 1, NULL) == RE_OK);
    assert(re_trace(&store, 0, 0, 1, 100, 0, 1, NULL) == RE_BUDGET);
}
static void faults(void) {
    struct re_export e;
    init(3);
    assert(re_trace(&store, 0, 0, 1, 100, 0, 1, NULL) == RE_OK);
    assert(re_export_init(&e, 0, 2, 1, 10) == RE_OK);
    normal.busy = 1;
    assert(re_export_poll(&store, &e, 2, output, &normal) == RE_BUSY);
    assert(re_export_poll(&store, &e, 2, output, &normal) == RE_BUSY);
    assert(re_export_poll(&store, &e, 2, output, &normal) == RE_BUDGET);
    normal.busy = 0;
    assert(re_export_poll(&store, &e, 2, output, &normal) == RE_BUDGET);
    assert(normal.calls == 2 && store.cpu[0].head == 0);
    assert(re_export_init(&e, 0, 10, 1, 10) == RE_OK); /* fresh fake stream */
    normal.chunk = 10;
    assert(re_export_poll(&store, &e, 2, output, &normal) == RE_OK);
    normal.fail = 1;
    assert(re_export_poll(&store, &e, 3, output, &normal) == RE_IO);
    assert(normal.count == 10 && store.cpu[0].head == 0);
    normal.fail = 0;
    assert(re_export_poll(&store, &e, 4, output, &normal) == RE_IO);
    assert(re_export_init(&e, 0, 10, 1, 10) == RE_OK);
    assert(re_export_poll(&store, &e, 10, output, &normal) == RE_TIMEOUT);
    assert(re_export_poll(&store, &e, 2, output, &normal) == RE_TIMEOUT);
    assert(re_export_init(&e, 0, 10, 2, 10) == RE_OK);
    assert(re_export_poll(&store, &e, 1, output, &normal) == RE_TIMEOUT);
    assert(re_export_init(&e, 2, 10, 1, 10) == RE_INVALID);
}
static uint32_t done;
static void *producer(void *arg) {
    unsigned cpu = (unsigned)(uintptr_t)arg;
    for (unsigned i = 0; i < 1000; ++i) {
        uint64_t args[4] = {cpu, i, 0, 0};
        int r = re_trace(&store, cpu, 0, cpu+100, 100, PE_POINT, i, args);
        assert(r == RE_OK || r == RE_FULL);
        if (!(i % 10)) sched_yield();
    }
    __atomic_fetch_add(&done, 1, __ATOMIC_RELEASE);
    return NULL;
}
static void concurrent(void) {
    struct re_export e;
    pthread_t threads[16];
    init(1000); done = 0;
    assert(re_export_init(&e, 0, RE_MAX_POLLS, 1, UINT64_MAX) == RE_OK);
    for (unsigned cpu = 0; cpu < 16; ++cpu) assert(!pthread_create(&threads[cpu], NULL, producer, (void *)(uintptr_t)cpu));
    for (;;) {
        int r = re_export_poll(&store, &e, 2, output, &normal);
        assert(r == RE_OK || r == RE_EMPTY);
        if (r == RE_EMPTY && __atomic_load_n(&done, __ATOMIC_ACQUIRE) == 16) break;
        if (r == RE_EMPTY) sched_yield();
    }
    for (unsigned cpu = 0; cpu < 16; ++cpu) {
        assert(!pthread_join(threads[cpu], NULL));
        assert(store.cpu[cpu].head == store.cpu[cpu].tail);
        assert(store.cpu[cpu].hits == 1000);
    }
    validate(&normal, PE_TRACE);
    uint64_t sequence[16] = {0};
    for (unsigned off = 0; off < normal.count; off += PE_SIZE) {
        unsigned cpu = normal.bytes[off+48];
        uint64_t seq = pe_get64(normal.bytes+off+32);
        assert(seq > sequence[cpu]); sequence[cpu] = seq;
        assert(pe_get64(normal.bytes+off+96) == cpu);
        assert(pe_get64(normal.bytes+off+104) == seq-1);
    }
}
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "stream")) {
        struct re_export e;
        init(3);
        uint64_t args[4] = {0x100, 0x244, 0, 0};
        uint64_t regs[18] = {0}; regs[15] = UINT64_C(0xfedcba9876543210);
        assert(re_trace_context(&store, 1, 0, 77, 123, 100, PE_BEFORE, 42, args, regs) == RE_OK);
        assert(re_panic(&store, 1, 77, 123, 200, 43, args, NULL) == RE_OK);
        assert(re_export_init(&e, 0, 100, 1, 100) == RE_OK);
        while (re_export_poll(&store, &e, 2, output, &normal) != RE_EMPTY) {}
        assert(re_export_init(&e, 1, 100, 1, 100) == RE_OK);
        while (re_export_poll(&store, &e, 2, output, &normal) != RE_EMPTY) {}
        assert(fwrite(normal.bytes, 1, normal.count, stdout) == normal.count);
        return 0;
    }
    basics(); faults(); concurrent(); return 0;
}
