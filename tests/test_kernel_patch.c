/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include "../tooling/kernel_patch_sim.h"
#include "../residents/patch/probe.h"
struct fixture { struct kp_sim sim; struct kp_engine engine; struct kp_request q; struct kp_policy policy; };
static void setup(struct fixture *f, unsigned fault, unsigned operation) {
    memset(f, 0, sizeof(*f));
    struct kp_identity *id = &f->sim.identity;
    *id = (struct kp_identity){.abi = KP_ABI, .size = sizeof(*id), .firmware = 0x13600000,
        .soc = 0x840fd0, .capabilities = KP_CAP_INSPECT | KP_CAP_TEST_DATA | KP_CAP_DATA,
        .generation = 1, .text_base = UINT64_C(0xffffffff80000000),
        .data_base = UINT64_C(0xffffffff81000000), .resident_base = UINT64_C(0xffffffff82000000),
        .session = {1}, .build = {2}};
    f->sim.fault = fault;
    f->sim.address = id->resident_base;
    f->sim.length = 8;
    memcpy(f->sim.bytes, "original", 8);
    f->q = (struct kp_request){.abi = KP_ABI, .size = sizeof(f->q), .operation = operation,
        .kind = KP_TEST_DATA, .sequence = 1, .generation = 1, .anchor = KP_RESIDENT,
        .length = 8, .session = {1}, .build = {2}, .image = {3},
        .expected = "original", .replacement = "modified", .undo = "original"};
    f->policy = (struct kp_policy){.kind = KP_TEST_DATA, .anchor = KP_RESIDENT,
        .length = 8, .alignment = 8, .image = {3}, .expected = "original", .replacement = "modified"};
    struct kp_adapter adapter = ks_adapter(&f->sim);
    assert(kp_init(&f->engine, id, &f->policy, 1, &adapter) == KP_OK);
    if (fault == KS_ORIGINAL) f->sim.bytes[0] ^= 0xff;
}
static struct kp_result execute(struct fixture *f) {
    struct kp_result r;
    assert(kp_execute(&f->engine, &f->q, &r) == KP_OK);
    return r;
}
static void replay(struct fixture *f, struct kp_result r) {
    unsigned calls = f->sim.acquires + f->sim.writes + f->sim.saves;
    struct kp_result again = execute(f);
    assert(!memcmp(&r, &again, sizeof(r)));
    assert(calls == f->sim.acquires + f->sim.writes + f->sim.saves);
}
static void success(void) {
    struct fixture f;
    setup(&f, KS_NONE, KP_APPLY);
    struct kp_result r = execute(&f);
    assert(!r.status && r.state == KP_COMMITTED && !f.engine.poisoned && f.sim.writes == 1);
    assert(!memcmp(f.sim.bytes, "modified", 8));
    assert(!memcmp(r.preimage, "original", 8) && !memcmp(r.observed, "modified", 8));
    assert(r.flags & KP_COMPLETE_SAVED);
    assert(f.sim.stages[0] == KP_PREPARE);
    assert(!(f.sim.journal[0].flags & KP_WRITE_ATTEMPTED));
    assert(!memcmp(f.sim.journal[0].preimage, "original", 8));
    replay(&f, r);
    ++f.q.sequence;
    r = execute(&f);
    assert(r.status == KP_MISMATCH && f.sim.writes == 1);
    setup(&f, KS_NONE, KP_APPLY);
    r = execute(&f);
    assert(f.engine.applied_mask == 1);
    f.q.operation = KP_REVERT;
    f.q.sequence++;
    r = execute(&f);
    assert(!r.status && r.state == KP_COMMITTED && !f.engine.applied_mask);
    assert(!memcmp(r.preimage, "modified", 8) && !memcmp(r.observed, "original", 8));
    replay(&f, r);
    f.q.sequence++;
    assert(execute(&f).status == KP_POLICY);
    setup(&f, KS_NONE, KP_APPLY);
    assert(!execute(&f).status);
    f.q.operation = KP_REVERT;
    f.q.sequence++;
    f.sim.fault = KS_WRITE;
    f.sim.writes = 0;
    r = execute(&f);
    assert(r.status == KP_WRITE && r.state == KP_RESTORED && f.engine.applied_mask == 1);
    assert(!memcmp(f.sim.bytes, "modified", 8));
    setup(&f, KS_NONE, KP_EXERCISE);
    r = execute(&f);
    assert(!r.status && r.state == KP_RESTORED && !f.engine.poisoned && f.sim.writes == 2);
    assert(!memcmp(f.sim.bytes, "original", 8) && !memcmp(r.final, "original", 8));
    replay(&f, r);
    setup(&f, KS_NONE, KP_VERIFY);
    r = execute(&f);
    assert(!r.status && r.state == KP_UNCHANGED && !f.sim.writes);
    assert(f.sim.saves == 1 && f.sim.stages[0] == KP_COMPLETE);
    puts("success");
}
static void failures(void) {
    struct fixture f;
    unsigned cases[][3] = {
        {KS_ORIGINAL, KP_MISMATCH, KP_UNCHANGED}, {KS_PARTIAL, KP_WRITE, KP_RESTORED},
        {KS_WRITE, KP_WRITE, KP_RESTORED}, {KS_READBACK, KP_VERIFY_FAILED, KP_RESTORED},
        {KS_RESTORE, KP_RESTORE, KP_UNKNOWN}, {KS_STALE_BEFORE, KP_STALE, KP_UNCHANGED},
        {KS_STALE_AFTER, KP_STALE, KP_UNKNOWN}, {KS_PREPARE, KP_JOURNAL, KP_UNCHANGED},
        {KS_OUTCOME, KP_JOURNAL, KP_RESTORED}, {KS_COMPLETE, KP_JOURNAL, KP_COMMITTED},
        {KS_MAPPING, KP_MAPPING, KP_UNCHANGED}, {KS_SHORT_READ, KP_READ, KP_UNCHANGED},
        {KS_READ, KP_READ, KP_UNCHANGED}, {KS_ACQUIRE, KP_ACQUIRE, KP_UNCHANGED},
        {KS_RELEASE, KP_RELEASE, KP_UNKNOWN}};
    for (unsigned i = 0; i < sizeof(cases)/sizeof(*cases); ++i) {
        setup(&f, cases[i][0], KP_APPLY);
        struct kp_result r = execute(&f);
        assert(r.status == cases[i][1] && r.state == cases[i][2]);
        assert(!f.sim.held);
        if (r.state == KP_RESTORED) assert(!memcmp(f.sim.bytes, "original", 8));
        if (!(r.flags & KP_PREIMAGE_VALID)) assert(!kp_nonzero(r.preimage, KP_MAX_BYTES));
        if (r.state == KP_UNKNOWN || cases[i][0] == KS_STALE_BEFORE || cases[i][0] == KS_COMPLETE) {
            assert(f.engine.poisoned);
            unsigned writes = f.sim.writes;
            replay(&f, r);
            ++f.q.sequence;
            assert(execute(&f).status == KP_POISONED && f.sim.writes == writes);
        }
        if (cases[i][0] == KS_STALE_AFTER) assert(f.sim.writes == 1 && f.sim.quarantined);
        if (cases[i][0] == KS_ACQUIRE) assert(!f.sim.finishes && !f.sim.writes);
        if (cases[i][0] == KS_PREPARE) assert(!f.sim.writes);
    }
    puts("failures");
}
static void policy(void) {
    struct fixture f;
    setup(&f, KS_NONE, KP_APPLY);
    f.q.replacement[0] ^= 1;
    assert(execute(&f).status == KP_POLICY && !f.sim.acquires);
    setup(&f, KS_NONE, KP_APPLY);
    ++f.q.generation;
    assert(execute(&f).status == KP_STALE && !f.sim.acquires);
    setup(&f, KS_NONE, KP_APPLY);
    f.engine.identity.capabilities = KP_CAP_INSPECT;
    assert(execute(&f).status == KP_UNSUPPORTED && !f.sim.acquires);
    setup(&f, KS_NONE, KP_APPLY);
    f.q.kind = f.engine.policies[0].kind = KP_CODE;
    assert(execute(&f).status == KP_UNSUPPORTED && !f.sim.acquires);
    f.q.sequence++;
    f.q.operation = KP_VERIFY;
    assert(!execute(&f).status && !f.sim.writes);
    setup(&f, KS_NONE, KP_EXERCISE);
    f.q.kind = f.engine.policies[0].kind = KP_DATA;
    assert(execute(&f).status == KP_UNSUPPORTED);
    setup(&f, KS_NONE, KP_APPLY);
    f.q.kind = f.engine.policies[0].kind = KP_DATA;
    assert(!execute(&f).status);
    setup(&f, KS_NONE, KP_APPLY);
    f.q.undo[0] ^= 1;
    assert(execute(&f).status == KP_INVALID && !f.sim.writes);
    setup(&f, KS_NONE, KP_APPLY);
    f.q.expected[63] = 1;
    assert(execute(&f).status == KP_INVALID);
    setup(&f, KS_NONE, KP_APPLY);
    struct kp_policy policies[] = {f.policy, f.policy};
    policies[1].anchor = KP_DATA_BASE;
    policies[1].offset = (int64_t)(f.sim.identity.resident_base - f.sim.identity.data_base);
    struct kp_adapter adapter = ks_adapter(&f.sim);
    assert(kp_init(&f.engine, &f.sim.identity, policies, 2, &adapter) == KP_INVALID);
    uint64_t address;
    assert(!kp_address(&f.sim.identity, KP_RESIDENT, INT64_MIN, 8, &address));
    assert(!kp_address(&f.sim.identity, KP_RESIDENT, INT64_MAX, 8, &address));
    f.sim.identity.resident_base = UINT64_MAX - 3;
    assert(!kp_address(&f.sim.identity, KP_RESIDENT, 0, 8, &address));
    f.sim.identity.resident_base = UINT64_C(0xffffffff82000ffc);
    assert(!kp_address(&f.sim.identity, KP_RESIDENT, 0, 8, &address));
    puts("policy");
}
static void sequencing(void) {
    struct fixture f;
    setup(&f, KS_NONE, KP_APPLY);
    f.q.sequence = 2;
    assert(execute(&f).status == KP_SEQUENCE && !f.sim.acquires);
    f.q.sequence = 1;
    f.sim.reenter = &f.engine;
    f.sim.reenter_request = &f.q;
    struct kp_result r = execute(&f);
    assert(!r.status);
    replay(&f, r);
    f.q.operation = KP_VERIFY;
    assert(execute(&f).status == KP_SEQUENCE && f.sim.writes == 1);
    f.engine.sequence = UINT64_MAX;
    f.q.sequence = 1;
    assert(execute(&f).status == KP_SEQUENCE);
    puts("sequencing");
}
struct race {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned ready, go;
    struct fixture *fixture;
};
static void *racer(void *context) {
    struct race *race = context;
    assert(!pthread_mutex_lock(&race->mutex));
    ++race->ready;
    assert(!pthread_cond_broadcast(&race->condition));
    while (!race->go) assert(!pthread_cond_wait(&race->condition, &race->mutex));
    assert(!pthread_mutex_unlock(&race->mutex));
    struct kp_result result;
    int status = kp_execute(&race->fixture->engine, &race->fixture->q, &result);
    assert(status == KP_BUSY || (status == KP_OK && result.status == KP_OK));
    return NULL;
}
static void concurrent(void) {
    struct fixture f;
    setup(&f, KS_NONE, KP_APPLY);
    struct race race = { .mutex = PTHREAD_MUTEX_INITIALIZER,
        .condition = PTHREAD_COND_INITIALIZER, .fixture = &f };
    pthread_t threads[16];
    for (unsigned i = 0; i < 16; ++i) assert(!pthread_create(threads + i, NULL, racer, &race));
    assert(!pthread_mutex_lock(&race.mutex));
    while (race.ready != 16) assert(!pthread_cond_wait(&race.condition, &race.mutex));
    race.go = 1;
    assert(!pthread_cond_broadcast(&race.condition));
    assert(!pthread_mutex_unlock(&race.mutex));
    for (unsigned i = 0; i < 16; ++i) assert(!pthread_join(threads[i], NULL));
    assert(f.sim.writes == 1 && f.sim.acquires == 1 && f.engine.sequence == 1);
    assert(!pthread_cond_destroy(&race.condition));
    assert(!pthread_mutex_destroy(&race.mutex));
    puts("concurrent");
}
static void probe(void) {
    struct fixture f;
    setup(&f, KS_NONE, KP_APPLY);
    struct kp_probe_request q = {.abi = KP_ABI, .size = sizeof(q), .operation = KP_PROBE_QUERY,
        .challenge = {4}, .build = {2}};
    struct kp_probe_reply r;
    assert(kp_probe(&f.engine, &q, &r) == KP_OK && r.status == KP_OK);
    assert(r.flags == KP_PROBE_CHECKED && !r.sequence && !r.applied_mask && !r.poisoned);
    assert(!memcmp(&r.identity, &f.sim.identity, sizeof(r.identity)));
    assert(!memcmp(r.challenge, q.challenge, 16) && !f.sim.writes && !f.sim.reads && !f.sim.saves);
    struct kp_result applied = execute(&f);
    unsigned writes = f.sim.writes, saves = f.sim.saves;
    assert(kp_probe(&f.engine, &q, &r) == KP_OK && r.status == KP_OK);
    assert(r.flags == (KP_PROBE_CHECKED | KP_PROBE_HAS_LAST) && r.sequence == 1 && r.applied_mask == 1);
    assert(!memcmp(&r.last_request, &f.q, sizeof(f.q)));
    assert(!memcmp(&r.last_result, &applied, sizeof(applied)));
    assert(f.sim.writes == writes && f.sim.saves == saves);
    replay(&f, applied); /* diagnostics did not consume or repeat the command */
    q.build[0] ^= 1;
    unsigned acquires = f.sim.acquires;
    assert(kp_probe(&f.engine, &q, &r) == KP_OK && r.status == KP_STALE);
    assert(!r.flags && !r.sequence && !kp_nonzero((unsigned char *)&r.identity, sizeof(r.identity)));
    assert(!kp_nonzero((unsigned char *)&r.last_request, sizeof(r.last_request)));
    assert(!kp_nonzero((unsigned char *)&r.last_result, sizeof(r.last_result)));
    assert(f.sim.acquires == acquires);
    q.build[0] ^= 1;
    f.sim.fault = KS_STALE_AFTER;
    assert(kp_probe(&f.engine, &q, &r) == KP_OK && r.status == KP_STALE && r.poisoned);
    assert(r.flags == KP_PROBE_HAS_LAST && f.sim.quarantined);
    acquires = f.sim.acquires;
    f.sim.fault = KS_NONE;
    assert(kp_probe(&f.engine, &q, &r) == KP_OK && r.status == KP_POISONED);
    assert(f.sim.acquires == acquires && r.flags == KP_PROBE_HAS_LAST);
    assert(!memcmp(&r.last_result, &applied, sizeof(applied)));
    assert(f.sim.writes == writes && f.sim.saves == saves);
    memset(&r, 0xa5, sizeof(r));
    __atomic_store_n(&f.engine.gate, 1, __ATOMIC_RELEASE);
    assert(kp_probe(&f.engine, &q, &r) == KP_BUSY && r.abi == UINT32_C(0xa5a5a5a5));
    __atomic_store_n(&f.engine.gate, 0, __ATOMIC_RELEASE);
    setup(&f, KS_RELEASE, KP_APPLY);
    assert(kp_probe(&f.engine, &q, &r) == KP_OK && r.status == KP_RELEASE && r.poisoned && !r.flags);
    assert(!f.sim.writes && !f.sim.saves);
    setup(&f, KS_ACQUIRE, KP_APPLY);
    assert(kp_probe(&f.engine, &q, &r) == KP_OK && r.status == KP_ACQUIRE && !r.poisoned);
    assert(!f.sim.finishes && !f.sim.writes && !f.sim.saves);
    q.reserved = 1;
    acquires = f.sim.acquires;
    assert(kp_probe(&f.engine, &q, &r) == KP_OK && r.status == KP_INVALID);
    assert(f.sim.acquires == acquires);
    puts("probe");
}
int main(int argc, char **argv) {
    if (argc == 2) {
        struct fixture f;
        setup(&f, KS_NONE, KP_APPLY);
        if (!strcmp(argv[1], "probe-last") || !strcmp(argv[1], "probe-poisoned")) {
            (void)execute(&f);
            if (!strcmp(argv[1], "probe-poisoned")) f.engine.poisoned = 1;
        } else if (strcmp(argv[1], "probe-empty")) return 2;
        struct kp_probe_request q;
        struct kp_probe_reply r;
        if (fread(&q, sizeof(q), 1, stdin) != 1 || fgetc(stdin) != EOF) return 2;
        if (kp_probe(&f.engine, &q, &r)) return 2;
        return fwrite(&r, sizeof(r), 1, stdout) == 1 && !fflush(stdout) ? 0 : 2;
    }
    success(); failures(); policy(); sequencing(); concurrent(); probe(); return 0;
}
