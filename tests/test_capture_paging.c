#include <assert.h>
#include <stdio.h>
#include "../payloads/kernel-capture/paging.h"
static uint64_t tables[5][512];
static int fail;
static const uint64_t dmap = UINT64_C(0xffff800000000000);
static int read_mock(void *unused, uint64_t va, uint64_t *out) {
    (void)unused;
    uint64_t offset = va - dmap;
    if (fail || offset < 4096 || offset >= 6 * 4096 || (offset & 7)) return -1;
    *out = ((uint64_t *)tables)[(offset - 4096) / 8]; return 0;
}
static enum cap_page_status check(uint64_t va) {
    return cap_check_page(4096, dmap, va, read_mock, NULL);
}
int main(void) {
    tables[0][0] = 8192 | 1; tables[1][0] = 12288 | 1;
    tables[2][0] = 16384 | 1; tables[3][0] = 0x100000 | 1;
    assert(check(0) == CAP_OK);
    assert(check(4096) == CAP_MISSING);
    for (int i = 0; i < 4; ++i) {
        tables[i][0] |= CAP_XOTEXT; assert(check(0) == CAP_PROTECTED);
        tables[i][0] &= ~CAP_XOTEXT;
    }
    tables[2][0] = 0x200000 | 129; assert(check(0x1ff000) == CAP_OK);
    tables[1][0] = 0x40000000 | 129; assert(check(0x3ffff000) == CAP_OK);
    tables[0][0] |= 128; assert(check(0) == CAP_BAD_TABLE); tables[0][0] &= ~128ull;
    fail = 1; assert(check(0) == CAP_READ_ERROR); fail = 0;
    tables[0][0] = CAP_PHYS_LIMIT | 1; assert(check(0) == CAP_BAD_TABLE);
    tables[0][0] = 1; assert(check(0) == CAP_BAD_TABLE);
    tables[0][0] = 0; assert(check(0) == CAP_MISSING);
    puts("PASS: 4K/2M/1G mappings; protected ancestors; missing/invalid tables; read failures");
}
