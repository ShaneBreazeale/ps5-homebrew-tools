/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "utils.h"
#include "shared_area.h"
#include "ko_ready/ko_resident.h"
static int resident_read(void *ctx, uint64_t address, void *out, size_t size) {
    (void)ctx;
    return copy_from_kernel(out, address, size);
}
static int resident_write(void *ctx, uint64_t address, const void *data, size_t size) {
    (void)ctx;
    return copy_to_kernel(address, data, size);
}
static int user_page(uint64_t va, int writing) {
    uint64_t table = cr3_phys & UINT64_C(0x000ffffffffff000);
    for (int shift=39; shift>=12; shift-=9) {
        if (!table || table >= (UINT64_C(1)<<36)) return EFAULT;
        uint64_t entry;
        memcpy(&entry, DMEM+table+((va>>shift)&511)*8, 8);
        if (!(entry & 1) || !(entry & 4) || (writing && !(entry & 2)) || (entry & (UINT64_C(1)<<58))) return EFAULT;
        if (shift==39 && (entry&128)) return EFAULT;
        if (shift==12 || (entry&128)) return 0;
        table = entry & UINT64_C(0x000ffffffffff000);
    }
    return EFAULT;
}
static int resident_user(void *ctx, uint64_t address, size_t size, int writing) {
    (void)ctx;
    if (!ko_user_range(address,size)) return EFAULT;
    uint64_t end=address+size-1;
    for (uint64_t page=address & ~UINT64_C(4095); page <= (end & ~UINT64_C(4095)); page+=4096)
        if (user_page(page,writing)) return EFAULT;
    return 0;
}
int ko_handle_readiness(uint64_t request, uint64_t size, uint64_t reply, uint64_t reply_size, uint64_t reserved) {
    struct ko_resident_io io = {NULL, resident_read, resident_write, resident_user};
    return ko_resident_handle(&shared_area.ko_readiness, &io, request, size, reply, reply_size, reserved);
}
