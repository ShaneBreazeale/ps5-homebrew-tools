/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef DEBUG_TARGET_MEMORY_H
#define DEBUG_TARGET_MEMORY_H
#include "target.h"
#include <errno.h>
#include <string.h>
/* Serialized read-only fallback for providers. Envelope validation completes
 * before any reads. No atomicity against writers outside the stopped target. */
static inline int target_read_ranges(void* ctx,
    int (*read_memory)(void*, uint64_t, void*, size_t),
    const struct target_memory_range* ranges, size_t count,
    void* data, size_t capacity, struct target_memory_result* results)
{
    if(!read_memory || !ranges || !data || !results || !count || count > TARGET_MAX_RANGES) return -EINVAL;
    size_t total = 0;
    for(size_t i = 0; i < count; i++) {
        if(!ranges[i].length || ranges[i].length > TARGET_MAX_MEMORY-total) return -EINVAL;
        total += ranges[i].length;
    }
    if(total > capacity) return -ENOSPC;
    memset(data, 0, total);
    size_t offset = 0;
    for(size_t i = 0; i < count; i++) {
        const struct target_memory_range* range = ranges+i;
        struct target_memory_result* result = results+i;
        *result = (struct target_memory_result){.offset = offset};
        if(range->address >= (1ull<<47) || range->length > (1ull<<47)-range->address)
            result->error = -EFAULT;
        else {
            int r = read_memory(ctx, range->address, (unsigned char*)data+offset, range->length);
            result->error = r > 0 ? -EIO : r;
        }
        if(result->error) memset((unsigned char*)data+offset, 0, range->length);
        else result->length = range->length;
        offset += range->length;
    }
    return 0;
}
#endif
