/* Exercise actual consumer and producer helpers; no SDK or kernel access. */
#include <assert.h>
#include <stdio.h>
#include "../payloads/kernel-offset/backend.h"
#include "../payloads/kernel-offset/readiness_producer.h"
static const uint64_t text = UINT64_C(0xffffffff8d640000);
static const uint64_t dmap = UINT64_C(0xffff800000000000);
static uint64_t tables[4][512];
static int calls, code_reads, cookie_reads, fail_at, mismatch, mutation, queries, query_fault;
static uint64_t cookie, hook, mock_cr3, mock_pml4;
static struct ko_ready_producer producer;
static struct ko_provider provider;
static struct ko_policy policy;
static int read_mock(void *ctx, uint64_t va, void *out, size_t length) {
    (void)ctx;
    if (++calls == fail_at) return -1;
    uint64_t data = text + TEXT_LENGTH, value = 0;
    if (va == text + KO_TEXT_OFFSET) {
        ++code_reads;
        assert(length == sizeof(ko_expected));
        memcpy(out, ko_expected, length);
        if (mismatch) ((unsigned char *)out)[0] ^= 1;
        if (mutation == 1) cookie = 0;
        if (mutation == 2) hook = 1;
        if (mutation == 3) mock_cr3 += 4096;
        if (mutation == 4) tables[3][((text+KO_TEXT_OFFSET)>>12)&511] |= CAP_XOTEXT;
        if (mutation == 5) ++producer.record.generation;
        if (mutation == 6) ++producer.record.session[0];
        return 0;
    }
    assert(length == 8);
    if (va == data + PMAP_OFFSET + PMAP_PML4_OFFSET) value = mock_pml4;
    else if (va == data + PMAP_OFFSET + PMAP_CR3_OFFSET) value = mock_cr3;
    else if (va == data + CAVE_OFFSET + COOKIE_OFFSET) { ++cookie_reads; value = cookie; }
    else if (va == data + CAVE_OFFSET + HOOK_STATE_OFFSET) { ++cookie_reads; value = hook; }
    else {
        assert(va >= dmap + 4096 && va < dmap + 5*4096 && !(va & 7));
        value = ((uint64_t *)tables)[(va - dmap - 4096) / 8];
    }
    memcpy(out, &value, length);
    return 0;
}
static enum ko_query_result query_mock(void *ctx, const struct ko_ready_request *request, struct ko_ready_reply *reply) {
    (void)ctx;
    ++queries;
    if (query_fault == 1 || (query_fault >= 23 && queries == 1)) return KO_QUERY_UNAVAILABLE;
    if (query_fault == 24 && queries == 2) return KO_QUERY_ERROR;
    if (query_fault == 2) return KO_QUERY_ERROR;
    if (query_fault == 3) return (enum ko_query_result)99;
    if (query_fault == 4 && queries == 2) return KO_QUERY_UNAVAILABLE;
    assert(ko_producer_exchange(&producer, request, reply) == KO_QUERY_OK);
    switch (query_fault) {
    case 5: ++reply->abi_version; break;
    case 6: --reply->record_size; break;
    case 7: ++reply->challenge[0]; break;
    case 8: memset(reply->session, 0, sizeof(reply->session)); break;
    case 9: reply->generation = 0; break;
    case 10: reply->capabilities = 3; break;
    case 11: ++reply->text; break;
    case 12: ++reply->data; break;
    case 13: ++reply->cr3; break;
    case 14: ++reply->firmware; break;
    case 15: ++reply->soc; break;
    case 16: reply->state = KO_INITIALIZING; break;
    case 17: reply->active_hooks = 1; break;
    case 18: reply->expected_cpus = 0; break;
    case 19: reply->completed_cpus = 1; break;
    case 20: reply->build_id[0] ^= 1; break;
    case 21: reply->reserved[0] = 1; break;
    case 22: if (queries == 2) reply->challenge[0] ^= UINT64_MAX; break;
    }
    return KO_QUERY_OK;
}
static void setup(void) {
    memset(tables, 0, sizeof(tables));
    for (int level = 0; level < 4; ++level) {
        unsigned index = ((text + KO_TEXT_OFFSET) >> (39 - level*9)) & 511;
        tables[level][index] = (uint64_t)(level+2)*4096 | 1;
    }
    calls = code_reads = cookie_reads = fail_at = mismatch = mutation = queries = query_fault = 0;
    cookie = RESUME_COOKIE; hook = 0; mock_cr3 = 4096; mock_pml4 = dmap + 4096;
    memset(&producer, 0, sizeof(producer));
    struct ko_ready_reply identity = {0};
    identity.session[0] = 11; identity.session[1] = 12;
    identity.text = text; identity.data = text + TEXT_LENGTH; identity.cr3 = mock_cr3;
    identity.firmware = PROFILE_FIRMWARE; identity.soc = PROFILE_SOC; identity.expected_cpus = 3;
    memset(identity.build_id, 0x5a, sizeof(identity.build_id));
    assert(ko_producer_begin(&producer, &identity, NULL, NULL) == 0);
    assert(ko_producer_cpu_complete(&producer, 0) == 0);
    assert(ko_producer_cpu_complete(&producer, 1) == 0);
    assert(ko_producer_finish(&producer, 0, NULL, NULL, 0) == 0);
    provider.exchange = query_mock; provider.ctx = NULL;
    memset(provider.expected_build_id, 0x5a, sizeof(provider.expected_build_id));
    policy = (struct ko_policy){&provider, {123, 456}, 1};
}
static enum ko_status probe(struct ko_result *r) {
    return ko_probe(PROFILE_FIRMWARE, PROFILE_SOC, text, text+TEXT_LENGTH, read_mock, NULL, &policy, r);
}
static int writes, write_fail;
static uint64_t published_cookie;
static int write_cookie(void *ctx, uint64_t value) {
    (void)ctx;
    ++writes;
    if (write_fail) return -1;
    published_cookie = value;
    return 0;
}
static void producer_tests(void) {
    setup();
    struct ko_ready_reply identity = producer.record;
    struct ko_ready_producer p = {0};
    writes = write_fail = 0; published_cookie = RESUME_COOKIE;
    assert(ko_producer_begin(&p, &identity, write_cookie, NULL) == 0);
    assert(writes == 1 && !published_cookie && p.record.state == KO_INITIALIZING && !p.record.capabilities);
    assert(ko_producer_finish(&p, 0, write_cookie, NULL, RESUME_COOKIE) < 0 && writes == 1);
    assert(ko_producer_cpu_complete(&p, 0) == 0);
    assert(ko_producer_finish(&p, 0, write_cookie, NULL, RESUME_COOKIE) < 0 && writes == 1);
    assert(ko_producer_cpu_complete(&p, 1) == 0);
    assert(ko_producer_finish(&p, 1, write_cookie, NULL, RESUME_COOKIE) < 0 && writes == 1);
    assert(ko_producer_finish(&p, 0, write_cookie, NULL, RESUME_COOKIE) == 0);
    assert(writes == 2 && published_cookie == RESUME_COOKIE && p.record.state == KO_READY);
    assert(ko_producer_cpu_complete(&p, 1) < 0);
    assert(ko_producer_begin(&p, &identity, write_cookie, NULL) < 0); /* No session reuse/reset. */
    assert(ko_producer_invalidate(&p, write_cookie, NULL) == 0);
    assert(!published_cookie && !p.record.capabilities && p.record.state == KO_FAILED);
    write_fail = 1;
    ++identity.session[0];
    assert(ko_producer_begin(&p, &identity, write_cookie, NULL) < 0 && p.record.state == KO_FAILED);
    write_fail = 0;
    assert(ko_producer_begin(&p, &identity, write_cookie, NULL) == 0);
    assert(ko_producer_cpu_complete(&p, 0) == 0 && ko_producer_cpu_complete(&p, 1) == 0);
    p.record.generation = UINT64_MAX;
    assert(ko_producer_finish(&p, 0, write_cookie, NULL, RESUME_COOKIE) < 0 && !published_cookie);
    p.record.generation = 4;
    write_fail = 1;
    assert(ko_producer_finish(&p, 0, write_cookie, NULL, RESUME_COOKIE) < 0 && p.record.state == KO_FAILED && !p.record.capabilities);
}
int main(void) {
    struct ko_result r;
    setup(); assert(probe(&r) == KO_MATCH && calls == 13 && queries == 2 && code_reads == 1 && !cookie_reads);
    assert(r.source == KO_SOURCE_HANDSHAKE && r.readiness.generation && r.bytes_read == 7);
    assert(memcmp(r.first_challenge, r.final_challenge, sizeof(r.first_challenge)));
    assert(r.address == UINT64_C(0xffffffff8d9cfc12));
    assert(!strcmp(ko_source_name(r.source), "versioned_handshake"));
    assert(!strcmp(ko_status_name(KO_MATCH), "site_signature_match"));
    assert(KO_EXEC_ANCHOR + KO_SHORT_OFFSET == KO_TEXT_OFFSET);
    assert((KO_TEXT_OFFSET & 4095) + sizeof(ko_expected) <= 4096);
    setup(); policy.challenge[0] = UINT64_MAX; policy.challenge[1] = 0;
    assert(probe(&r) == KO_MATCH); /* Final challenge must never become zero. */
    setup(); policy.provider = NULL; policy.allow_legacy = 0;
    assert(probe(&r) == KO_NO_PROVIDER && !code_reads && !cookie_reads);
    setup(); policy.provider = NULL;
    assert(probe(&r) == KO_MATCH && r.source == KO_SOURCE_LEGACY && calls == 17 && cookie_reads == 4 && !queries);
    setup(); query_fault = 1;
    assert(probe(&r) == KO_MATCH && r.source == KO_SOURCE_LEGACY && queries == 2);
    setup(); query_fault = 1; policy.allow_legacy = 0;
    assert(probe(&r) == KO_NO_PROVIDER && !cookie_reads);
    /* Existing cookie is valid in every case: errors must never downgrade. */
    for (int fault = 2; fault <= 22; ++fault) {
        setup(); query_fault = fault;
        assert(probe(&r) != KO_MATCH && !r.bytes_read && !cookie_reads);
        if (fault != 4 && fault != 22) assert(!code_reads);
    }
    for (int fault = 23; fault <= 24; ++fault) {
        setup(); query_fault = fault;
        assert(probe(&r) == KO_READINESS_CHANGED && !r.bytes_read && code_reads == 1 && queries == 2);
    }
    setup(); memset(provider.expected_build_id, 0, sizeof(provider.expected_build_id));
    assert(probe(&r) == KO_BAD_READINESS && !code_reads && !cookie_reads);
    setup(); memset(policy.challenge, 0, sizeof(policy.challenge));
    assert(probe(&r) == KO_NONCE_ERROR && !queries && !cookie_reads);
    setup(); assert(ko_probe(0x12000000, PROFILE_SOC, text, text+TEXT_LENGTH, read_mock, NULL, &policy, &r) == KO_UNSUPPORTED && !calls);
    setup(); assert(ko_probe(PROFILE_FIRMWARE, 0, text, text+TEXT_LENGTH, read_mock, NULL, &policy, &r) == KO_UNSUPPORTED && !calls);
    const uint64_t bad[][2] = {{0, TEXT_LENGTH}, {UINT64_C(0xffff000000000000), UINT64_C(0xffff000000cc0000)},
        {text+1, text+TEXT_LENGTH+1}, {text, text+TEXT_LENGTH-4096}, {UINT64_MAX-TEXT_LENGTH, UINT64_MAX}};
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i) {
        setup(); assert(ko_probe(PROFILE_FIRMWARE, PROFILE_SOC, bad[i][0], bad[i][1], read_mock, NULL, &policy, &r) == KO_BAD_BASES && !calls);
    }
    setup(); mock_cr3 = 0; assert(probe(&r) == KO_BAD_PMAP && !code_reads);
    setup(); mock_pml4 = UINT64_MAX-4095; assert(probe(&r) == KO_BAD_PMAP && !code_reads);
    setup(); policy.provider = NULL; cookie = 0; assert(probe(&r) == KO_UNVERIFIED_SESSION && !code_reads);
    setup(); policy.provider = NULL; hook = 1; assert(probe(&r) == KO_UNVERIFIED_SESSION && !code_reads);
    for (int level = 0; level < 4; ++level) {
        unsigned index = ((text+KO_TEXT_OFFSET) >> (39-level*9)) & 511;
        setup(); tables[level][index] |= CAP_XOTEXT;
        assert(probe(&r) == KO_PROTECTED && !code_reads && !r.bytes_read);
        setup(); tables[level][index] = 0;
        assert(probe(&r) == KO_MISSING && !code_reads);
    }
    setup(); tables[0][511] = CAP_PHYS_LIMIT | 1;
    assert(probe(&r) == KO_BAD_TABLE && !code_reads);
    for (int n = 1; n <= 17; ++n) {
        setup(); policy.provider = NULL; fail_at = n;
        enum ko_status expected = (n <= 4 || n == 10 || n == 11 || n >= 16) ? KO_METADATA_ERROR : n == 9 ? KO_SITE_READ_ERROR : KO_PAGE_READ_ERROR;
        assert(probe(&r) == expected && !r.bytes_read);
    }
    for (int mode = 1; mode <= 6; ++mode) {
        setup(); mutation = mode;
        if (mode <= 2) policy.provider = NULL;
        assert(probe(&r) != KO_MATCH && code_reads == 1 && !r.bytes_read && !ko_nonzero(r.observed, sizeof(r.observed)));
    }
    setup(); mismatch = 1; assert(probe(&r) == KO_MISMATCH && r.bytes_read == 7);
    producer_tests();
    puts("PASS: readiness handshake, no unsafe downgrade, legacy rechecks, producer publication and page guards");
    return 0;
}
