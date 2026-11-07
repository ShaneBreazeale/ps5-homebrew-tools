/* SPDX-License-Identifier: GPL-3.0-or-later
 * Bounded permission audit. It is not an OS page pin or a coherent snapshot.
 */
#ifndef KP_USER_PAGES_H
#define KP_USER_PAGES_H
#include "bridge.h"
typedef int (*kp_phys_read)(void *, uint64_t, uint64_t *);
static inline int kp_page_access(uint64_t root, uint64_t va, int user, int writing,
        kp_phys_read read, void *ctx) {
    const uint64_t mask = UINT64_C(0x000ffffffffff000), limit = UINT64_C(1) << 36;
    uint64_t table = root;
    for (int shift = 39; shift >= 12; shift -= 9) {
        uint64_t entry = 0;
        if (!table || table >= limit || (table & 4095)
                || read(ctx, table + ((va >> shift) & 511) * 8, &entry)) return EFAULT;
        if (!(entry & 1) || (user && !(entry & 4)) || (writing && !(entry & 2))
                || (entry & (UINT64_C(1) << 58))) return EFAULT;
        if (shift == 39 && (entry & 128)) return EFAULT;
        if (shift == 12 || (entry & 128)) {
            uint64_t leaf_mask = (UINT64_C(1) << shift) - 1;
            if (shift > 12 && (entry & mask & leaf_mask & ~UINT64_C(4096))) return EFAULT;
            uint64_t physical = (entry & mask & ~leaf_mask) | (va & leaf_mask);
            return physical < limit ? 0 : EFAULT;
        }
        table = entry & mask;
    }
    return EFAULT;
}
static inline int kp_pages_access(uint64_t root, uint64_t address, size_t length,
        int user, int writing, kp_phys_read read, void *ctx) {
    if (!read || !length || length > 1024 || length - 1 > UINT64_MAX - address
            || (user ? !kp_user_range(address, length) : !kp_kernel(address))) return EFAULT;
    uint64_t first = address & ~UINT64_C(4095), last = (address + length - 1) & ~UINT64_C(4095);
    if (kp_page_access(root, first, user, writing, read, ctx)) return EFAULT;
    return first == last ? 0 : kp_page_access(root, last, user, writing, read, ctx);
}
#endif
