/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "../payloads/process-debugger/target_memory.h"
#include <assert.h>
#include <stdio.h>
static int calls;
static int read_memory(void* ctx, uint64_t address, void* data, size_t size)
{
    (void)ctx; calls++;
    memset(data, 0xa5, size);
    return address == 8 ? -EFAULT : address == 9 ? 1 : 0;
}
int main(void)
{
    struct target_memory_range ranges[] = {{0,4},{8,4},{1ull<<47,4},{9,4},{16,4}};
    struct target_memory_result results[5]; unsigned char data[20];
    assert(target_read_ranges(NULL,read_memory,ranges,5,data,sizeof(data),results)==0);
    assert(calls==4 && results[0].length==4 && !results[0].error && results[4].length==4);
    assert(results[1].error==-EFAULT && results[2].error==-EFAULT && results[3].error==-EIO);
    for(int i=4;i<16;i++) assert(data[i]==0);
    assert(data[0]==0xa5 && data[16]==0xa5);
    calls=0; ranges[4].length=TARGET_MAX_MEMORY;
    assert(target_read_ranges(NULL,read_memory,ranges,5,data,sizeof(data),results)==-EINVAL && !calls);
    ranges[4].length=4;
    assert(target_read_ranges(NULL,read_memory,ranges,5,data,19,results)==-ENOSPC && !calls);
    assert(target_read_ranges(NULL,read_memory,ranges,0,data,20,results)==-EINVAL && !calls);
    puts("bounded multiple-range results and zero-on-failure assertions passed");
}
