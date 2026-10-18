/* Exercise the actual backend; no SDK or kernel access. */
#include <assert.h>
#include <stdio.h>
#include "../payloads/kernel-offset/backend.h"
static const uint64_t text = UINT64_C(0xffffffff8d640000);
static const uint64_t dmap = UINT64_C(0xffff800000000000);
static uint64_t tables[4][512];
static int calls, code_reads, fail_at, mismatch;
static uint64_t cookie, hook, mock_cr3, mock_pml4;
static int read_mock(void *ctx, uint64_t va, void *out, size_t length) {
    (void)ctx;
    if (++calls == fail_at) return -1;
    uint64_t data = text + TEXT_LENGTH, value = 0;
    if (va == text + KO_TEXT_OFFSET) {
        ++code_reads;
        assert(length == sizeof(ko_expected));
        memcpy(out, ko_expected, length);
        if (mismatch) ((unsigned char *)out)[0] ^= 1;
        return 0;
    }
    assert(length == 8);
    if (va == data + PMAP_OFFSET + PMAP_PML4_OFFSET) value = mock_pml4;
    else if (va == data + PMAP_OFFSET + PMAP_CR3_OFFSET) value = mock_cr3;
    else if (va == data + CAVE_OFFSET + COOKIE_OFFSET) value = cookie;
    else if (va == data + CAVE_OFFSET + HOOK_STATE_OFFSET) value = hook;
    else {
        assert(va >= dmap + 4096 && va < dmap + 5*4096 && !(va & 7));
        value = ((uint64_t *)tables)[(va - dmap - 4096) / 8];
    }
    memcpy(out, &value, length);
    return 0;
}
static void setup(void) {
    memset(tables, 0, sizeof(tables));
    for (int level = 0; level < 4; ++level) {
        unsigned index = ((text + KO_TEXT_OFFSET) >> (39 - level*9)) & 511;
        tables[level][index] = (uint64_t)(level+2)*4096 | 1;
    }
    calls = code_reads = fail_at = mismatch = 0;
    cookie = RESUME_COOKIE; hook = 0; mock_cr3 = 4096; mock_pml4 = dmap + 4096;
}
static enum ko_status probe(struct ko_result *r) {
    return ko_probe(PROFILE_FIRMWARE, PROFILE_SOC, text, text + TEXT_LENGTH, read_mock, NULL, r);
}
int main(void) {
    struct ko_result r;
    setup(); assert(probe(&r) == KO_MATCH && calls == 9 && code_reads == 1);
    assert(r.address == UINT64_C(0xffffffff8d9cfc12) && r.bytes_read == 7);
    assert(!strcmp(ko_status_name(KO_MATCH), "site_signature_match"));
    assert(KO_EXEC_ANCHOR + KO_SHORT_OFFSET == KO_TEXT_OFFSET);
    assert(KO_TEXT_OFFSET + sizeof(ko_expected) <= TEXT_LENGTH);
    assert((KO_TEXT_OFFSET & 4095) + sizeof(ko_expected) <= 4096);
    setup(); assert(ko_probe(0x12000000, PROFILE_SOC, text, text+TEXT_LENGTH, read_mock, NULL, &r) == KO_UNSUPPORTED && calls == 0);
    setup(); assert(ko_probe(PROFILE_FIRMWARE, 0, text, text+TEXT_LENGTH, read_mock, NULL, &r) == KO_UNSUPPORTED && calls == 0);
    const uint64_t bad[][2] = {
        {0, TEXT_LENGTH}, {UINT64_C(0xffff000000000000), UINT64_C(0xffff000000cc0000)},
        {text+1, text+TEXT_LENGTH+1}, {text, text+TEXT_LENGTH-4096},
        {UINT64_MAX-TEXT_LENGTH, UINT64_MAX}
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i) {
        setup(); assert(ko_probe(PROFILE_FIRMWARE, PROFILE_SOC, bad[i][0], bad[i][1], read_mock, NULL, &r) == KO_BAD_BASES && calls == 0);
    }
    setup(); mock_cr3 = 0; assert(probe(&r) == KO_BAD_PMAP && !code_reads);
    setup(); mock_pml4 = UINT64_MAX-4095; assert(probe(&r) == KO_BAD_PMAP && !code_reads);
    setup(); cookie = 0; assert(probe(&r) == KO_UNVERIFIED_SESSION && !code_reads);
    setup(); hook = 1; assert(probe(&r) == KO_UNVERIFIED_SESSION && !code_reads);
    for (int level = 0; level < 4; ++level) {
        unsigned index = ((text+KO_TEXT_OFFSET) >> (39-level*9)) & 511;
        setup(); tables[level][index] |= CAP_XOTEXT;
        assert(probe(&r) == KO_PROTECTED && !code_reads && !r.bytes_read);
        setup(); tables[level][index] = 0;
        assert(probe(&r) == KO_MISSING && !code_reads);
    }
    setup(); tables[0][511] = CAP_PHYS_LIMIT | 1;
    assert(probe(&r) == KO_BAD_TABLE && !code_reads);
    for (int n = 1; n <= 9; ++n) {
        setup(); fail_at = n;
        enum ko_status expected = n <= 4 ? KO_METADATA_ERROR : n <= 8 ? KO_PAGE_READ_ERROR : KO_SITE_READ_ERROR;
        assert(probe(&r) == expected && !code_reads && !r.bytes_read);
    }
    setup(); mismatch = 1; assert(probe(&r) == KO_MISMATCH && r.bytes_read == 7);
    puts("PASS: kernel offset gates, page permissions, bounded reads, mapping, signature and failures");
}
