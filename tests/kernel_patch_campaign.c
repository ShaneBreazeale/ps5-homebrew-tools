/* SPDX-License-Identifier: GPL-3.0-or-later
 * Deterministic host experiment: actual patch core, private simulated memory.
 * No console, SDK, real kernel address dereference or resident installation.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "../tooling/kernel_patch_sim.h"
#include "../residents/patch/probe.h"

enum scenario { CONTROL, PRIMARY_SHORT, PRIMARY_ERROR, RESTORE_SHORT,
    RESTORE_ERROR, PREIMAGE_SHORT, READBACK_SHORT, RESTORE_CHECK_SHORT, SCENARIOS };
static const char *names[] = {"control", "primary_short", "primary_error",
    "restore_short", "restore_error", "preimage_short", "readback_short", "restore_check_short"};
struct transfer { unsigned active, copied, reported; int error; };
struct fixture {
    unsigned char left[16];
    struct kp_sim sim;
    unsigned char right[16];
    struct kp_engine engine;
    struct kp_request request;
    struct transfer write[2];
    unsigned short_read, read_count, scenario, cut, operation, length;
    unsigned char before[KP_MAX_BYTES];
};
static void require(int ok, const struct fixture *f, unsigned line) {
    if (ok) return;
    fprintf(stderr, "counterexample: scenario=%s operation=%u length=%u cut=%u line=%u\n",
            names[f->scenario], f->operation, f->length, f->cut, line);
    exit(1);
}
#define CHECK(f, condition) require(!!(condition), (f), __LINE__)
static struct fixture *fixture(void *context) {
    return (struct fixture *)((unsigned char *)context - offsetof(struct fixture, sim));
}
static int fault_write(void *context, uint64_t address, const void *in, size_t length, size_t *done) {
    struct fixture *f = fixture(context);
    struct kp_sim *s = &f->sim;
    CHECK(f, s->held && address == s->address && length == s->length && s->writes < 2);
    CHECK(f, s->journal_count && s->stages[0] == KP_PREPARE);
    CHECK(f, !(s->journal[0].flags & KP_WRITE_ATTEMPTED));
    CHECK(f, !memcmp(s->journal[0].preimage, f->before, length));
    struct transfer *fault = f->write + s->writes;
    if (!fault->active) return ks_write(context, address, in, length, done);
    ++s->writes;
    CHECK(f, fault->copied <= length && fault->reported <= length);
    memcpy(s->bytes, in, fault->copied);
    *done = fault->reported;
    return fault->error;
}
static int fault_read(void *context, uint64_t address, void *out, size_t length, size_t *done) {
    struct fixture *f = fixture(context);
    struct kp_sim *s = &f->sim;
    if (s->reads + 1 != f->short_read) return ks_read(context, address, out, length, done);
    CHECK(f, s->held && address == s->address && length == s->length && f->read_count < length);
    ++s->reads;
    memcpy(out, s->bytes, f->read_count);
    *done = f->read_count;
    return 0;
}
static unsigned calls(const struct kp_sim *s) {
    return s->acquires + s->snapshots + s->mappings + s->reads + s->writes + s->saves + s->finishes;
}
static void setup(struct fixture *f, unsigned length, unsigned operation) {
    memset(f, 0, sizeof(*f));
    memset(f->left, 0x5a, sizeof(f->left));
    memset(f->right, 0x5a, sizeof(f->right));
    memset(f->sim.bytes, 0xa5, sizeof(f->sim.bytes));
    f->operation = operation; f->length = length;
    f->sim.identity = (struct kp_identity){.abi=KP_ABI, .size=sizeof(struct kp_identity),
        .firmware=0x13600000, .soc=0x840fd0, .capabilities=KP_CAP_INSPECT|KP_CAP_TEST_DATA,
        .generation=1, .text_base=UINT64_C(0xffffffff80000000),
        .data_base=UINT64_C(0xffffffff81000000), .resident_base=UINT64_C(0xffffffff82000000),
        .session={1}, .build={2}};
    f->sim.address = f->sim.identity.resident_base;
    f->sim.length = length;
    f->request = (struct kp_request){.abi=KP_ABI, .size=sizeof(struct kp_request),
        .operation=operation, .kind=KP_TEST_DATA, .sequence=1, .generation=1,
        .anchor=KP_RESIDENT, .length=length, .session={1}, .build={2}, .image={3}};
    for (unsigned i=0; i<length; ++i) {
        f->sim.bytes[i] = f->request.expected[i] = f->request.undo[i] = (unsigned char)(i+1);
        f->request.replacement[i] = (unsigned char)(0x80+i);
    }
    struct kp_policy policy = {.kind=KP_TEST_DATA, .anchor=KP_RESIDENT, .length=length, .alignment=1, .image={3}};
    memcpy(policy.expected, f->request.expected, KP_MAX_BYTES);
    memcpy(policy.replacement, f->request.replacement, KP_MAX_BYTES);
    struct kp_adapter adapter = ks_adapter(&f->sim);
    adapter.read = fault_read; adapter.write = fault_write;
    CHECK(f, kp_init(&f->engine, &f->sim.identity, &policy, 1, &adapter) == KP_OK);
    memcpy(f->before, f->sim.bytes, length);
    if (operation == KP_REVERT) {
        /* Establish real applied state before testing REVERT. Its rollback
         * preimage must be the replacement, not the original expected bytes. */
        f->request.operation = KP_APPLY;
        struct kp_result applied;
        CHECK(f, kp_execute(&f->engine, &f->request, &applied) == KP_OK && applied.status == KP_OK);
        CHECK(f, applied.state == KP_COMMITTED && f->engine.applied_mask == 1);
        f->request.operation = KP_REVERT; f->request.sequence = 2;
        f->sim.acquires=f->sim.snapshots=f->sim.mappings=f->sim.reads=f->sim.writes=0;
        f->sim.saves=f->sim.finishes=f->sim.outcomes=f->sim.journal_count=0;
        memset(f->sim.journal, 0, sizeof(f->sim.journal));
        memcpy(f->before, f->sim.bytes, length);
    }
}
static void run_case(unsigned length, unsigned operation, unsigned scenario, unsigned cut) {
    struct fixture f;
    setup(&f, length, operation);
    f.scenario=scenario; f.cut=cut;
    if (scenario == PRIMARY_SHORT) f.write[0]=(struct transfer){1,cut,cut,0};
    if (scenario == PRIMARY_ERROR) f.write[0]=(struct transfer){1,cut,0,-97};
    if (scenario == RESTORE_SHORT) f.write[1]=(struct transfer){1,cut,cut,0};
    if (scenario == RESTORE_ERROR) f.write[1]=(struct transfer){1,cut,0,-98};
    if (scenario == PREIMAGE_SHORT) f.short_read=1;
    if (scenario == READBACK_SHORT) f.short_read=2;
    if (scenario == RESTORE_CHECK_SHORT) f.short_read=3;
    f.read_count=cut;
    if (operation != KP_EXERCISE && (scenario == RESTORE_SHORT || scenario == RESTORE_ERROR || scenario == RESTORE_CHECK_SHORT))
        f.write[0]=(struct transfer){1,length,0,-97}; /* trigger restoration */
    struct kp_result r;
    CHECK(&f, kp_execute(&f.engine, &f.request, &r) == KP_OK);
    CHECK(&f, !f.sim.held && f.sim.finishes == 1);
    CHECK(&f, r.flags & KP_COMPLETE_SAVED);
    CHECK(&f, r.flags & KP_LEASE_FINISHED);
    int uncertain = scenario == RESTORE_SHORT || scenario == RESTORE_ERROR || scenario == RESTORE_CHECK_SHORT;
    if (scenario == CONTROL) {
        const unsigned char *desired = operation == KP_APPLY ? f.request.replacement : f.request.expected;
        CHECK(&f, r.status == KP_OK && !f.engine.poisoned && !f.sim.quarantined);
        CHECK(&f, r.state == (operation == KP_EXERCISE ? KP_RESTORED : KP_COMMITTED));
        CHECK(&f, !memcmp(f.sim.bytes, desired, length));
        CHECK(&f, f.engine.applied_mask == (operation == KP_APPLY ? 1u : 0u));
    } else if (scenario == PREIMAGE_SHORT) {
        CHECK(&f, r.status == KP_READ && r.state == KP_UNCHANGED && !f.sim.writes);
        CHECK(&f, !(r.flags & KP_PREIMAGE_VALID) && !kp_nonzero(r.preimage, KP_MAX_BYTES));
        CHECK(&f, !memcmp(f.sim.bytes, f.before, length));
    } else if (uncertain) {
        CHECK(&f, r.status == KP_RESTORE && r.state == KP_UNKNOWN);
        CHECK(&f, f.engine.poisoned && f.sim.quarantined && (r.flags & KP_ENGINE_POISONED));
        CHECK(&f, !(r.flags & KP_RESTORED_VERIFIED));
    } else {
        CHECK(&f, r.status == (scenario == READBACK_SHORT ? KP_VERIFY_FAILED : KP_WRITE));
        CHECK(&f, r.state == KP_RESTORED && !f.engine.poisoned && !f.sim.quarantined);
        CHECK(&f, (r.flags & (KP_FINAL_VALID|KP_RESTORED_VERIFIED)) == (KP_FINAL_VALID|KP_RESTORED_VERIFIED));
        CHECK(&f, !memcmp(f.sim.bytes, f.before, length) && !memcmp(r.final, f.before, length));
        CHECK(&f, f.engine.applied_mask == (operation == KP_REVERT ? 1u : 0u));
    }
    for (unsigned i=length; i<KP_MAX_BYTES; ++i) CHECK(&f, f.sim.bytes[i] == 0xa5);
    for (unsigned i=0; i<sizeof(f.left); ++i) CHECK(&f, f.left[i] == 0x5a && f.right[i] == 0x5a);
    /* Exact replay must return the cached result without any adapter callback. */
    unsigned before=calls(&f.sim);
    struct kp_result replay;
    CHECK(&f, kp_execute(&f.engine, &f.request, &replay) == KP_OK);
    CHECK(&f, !memcmp(&r, &replay, sizeof(r)) && calls(&f.sim) == before);
    if (uncertain) {
        struct kp_probe_request q={.abi=KP_ABI,.size=sizeof(q),.operation=KP_PROBE_QUERY,.challenge={4},.build={2}};
        struct kp_probe_reply report;
        CHECK(&f, kp_probe(&f.engine, &q, &report) == KP_OK && report.status == KP_POISONED);
        CHECK(&f, report.poisoned && !memcmp(&r, &report.last_result, sizeof(r)) && calls(&f.sim) == before);
        ++f.request.sequence;
        CHECK(&f, kp_execute(&f.engine, &f.request, &replay) == KP_OK && replay.status == KP_POISONED);
        CHECK(&f, calls(&f.sim) == before);
    }
}
int main(void) {
    unsigned counts[SCENARIOS]={0}, total=0;
    const unsigned operations[]={KP_APPLY,KP_EXERCISE,KP_REVERT};
    for (unsigned length=1; length<=KP_MAX_BYTES; ++length)
        for (unsigned op=0; op<3; ++op)
            for (unsigned scenario=0; scenario<SCENARIOS; ++scenario) {
                unsigned limit=scenario == CONTROL ? 1 : length + (scenario == PRIMARY_ERROR || scenario == RESTORE_ERROR);
                for (unsigned cut=0; cut<limit; ++cut) {
                    run_case(length, operations[op], scenario, cut);
                    ++counts[scenario]; ++total;
                }
            }
    printf("{\"schema\":1,\"lengths\":%u,\"operations\":3,\"cases\":%u,\"scenarios\":{", KP_MAX_BYTES,total);
    for (unsigned i=0; i<SCENARIOS; ++i) printf("%s\"%s\":%u",i?",":"",names[i],counts[i]);
    puts("},\"counterexamples\":0}");
    return 0;
}
