/* Read-only page-table inspection, shared with the native host tests. */
#ifndef CAPTURE_PAGING_H
#define CAPTURE_PAGING_H
#include <stdint.h>
#include <stddef.h>
#define CAP_PHYS_MASK UINT64_C(0x000ffffffffff000)
#define CAP_XOTEXT (UINT64_C(1) << 58)
#define CAP_PHYS_LIMIT (UINT64_C(1) << 36)
enum cap_page_status { CAP_OK, CAP_MISSING, CAP_PROTECTED, CAP_BAD_TABLE, CAP_READ_ERROR };
typedef int (*cap_read64)(void *, uint64_t, uint64_t *);
static enum cap_page_status cap_check_page(uint64_t root, uint64_t dmap,
        uint64_t va, cap_read64 read64, void *ctx) {
    uint64_t table = root & CAP_PHYS_MASK;
    for (int level = 0; level < 4; ++level) {
        if (!table || table >= CAP_PHYS_LIMIT) return CAP_BAD_TABLE;
        uint64_t entry = 0;
        uint64_t index = (va >> (39 - 9 * level)) & 511;
        if (read64(ctx, dmap + table + index * 8, &entry)) return CAP_READ_ERROR;
        if (!(entry & 1)) return CAP_MISSING;
        if (entry & CAP_XOTEXT) return CAP_PROTECTED;
        if (level == 0 && (entry & 128)) return CAP_BAD_TABLE;
        if (level == 3 || ((level == 1 || level == 2) && (entry & 128))) {
            if ((entry & CAP_PHYS_MASK) >= CAP_PHYS_LIMIT) return CAP_BAD_TABLE;
            return CAP_OK;
        }
        table = entry & CAP_PHYS_MASK;
    }
    return CAP_BAD_TABLE;
}
#endif
