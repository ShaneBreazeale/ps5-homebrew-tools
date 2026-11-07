/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdio.h>
#include "kernel_patch_sim.h"
int main(int argc, char **argv) {
    const char *faults[] = {"none", "original-mismatch", "partial-write", "write-error",
        "readback-mismatch", "restore-failure", "stale-before", "stale-after",
        "prepare-journal", "outcome-journal", "complete-journal", "mapping-refused",
        "short-read", "read-error", "acquire-error", "release-error"};
    if (argc != 2) return 2;
    unsigned fault;
    for (fault = 0; fault < sizeof(faults)/sizeof(*faults); ++fault)
        if (!strcmp(argv[1], faults[fault])) break;
    if (fault == sizeof(faults)/sizeof(*faults)) return 2;
    struct kp_request q;
    struct kp_sim sim = { .fault = fault };
    if (fread(&q, sizeof(q), 1, stdin) != 1 || fread(&sim.identity, sizeof(sim.identity), 1, stdin) != 1
            || fread(sim.bytes, sizeof(sim.bytes), 1, stdin) != 1 || fgetc(stdin) != EOF
            || !kp_request_valid(&q) || !kp_identity_valid(&sim.identity)) return 2;
    sim.length = q.length;
    if (!kp_address(&sim.identity, q.anchor, q.offset, q.length, &sim.address)) return 2;
    if (fault == KS_ORIGINAL) sim.bytes[0] ^= 0xff;
    /* SIMULATION ONLY: a live integration must configure this policy from its
     * reviewed build, never mirror an untrusted request as done in this fixture. */
    struct kp_policy policy = { .kind = q.kind, .anchor = q.anchor, .length = q.length,
        .alignment = 1, .offset = q.offset };
    memcpy(policy.image, q.image, 32);
    memcpy(policy.expected, q.expected, KP_MAX_BYTES);
    memcpy(policy.replacement, q.replacement, KP_MAX_BYTES);
    struct kp_adapter adapter = ks_adapter(&sim);
    struct kp_engine engine = {0};
    if (kp_init(&engine, &sim.identity, &policy, 1, &adapter)) return 2;
    struct kp_result result;
    if (kp_execute(&engine, &q, &result)) return 2;
    return fwrite(&result, sizeof(result), 1, stdout) == 1 && !fflush(stdout) ? 0 : 2;
}
