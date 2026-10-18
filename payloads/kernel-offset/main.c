/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <ps5/kernel.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "backend.h"
int sceKernelGetMainSocId(void);
static int sdk_read(void *unused, uint64_t address, void *out, size_t length) {
    (void)unused;
    return kernel_copyout((intptr_t)address, out, length);
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint32_t fw = kernel_get_fw_version();
    int soc = sceKernelGetMainSocId();
    uint64_t text = KERNEL_ADDRESS_TEXT_BASE, data = KERNEL_ADDRESS_DATA_BASE;
    struct ko_result result;
    enum ko_status status = ko_probe(fw, soc, text, data, sdk_read, NULL, &result);
    printf("KOFFSET_JSON={\"schema\":1,\"profile\":\"%s\",\"pid\":%d,\"observed_at_unix\":%lld,"
           "\"firmware_raw\":\"0x%08x\",\"soc_id\":\"0x%x\","
           "\"kernel_text_va\":\"0x%016llx\",\"kernel_data_va\":\"0x%016llx\","
           "\"text_offset\":\"0x%llx\",\"address\":\"0x%016llx\","
           "\"status\":\"%s\",\"bytes_read\":%zu,\"observed\":\"",
           KO_PROFILE, getpid(), (long long)time(NULL), fw, soc,
           (unsigned long long)text, (unsigned long long)data,
           (unsigned long long)KO_TEXT_OFFSET, (unsigned long long)result.address,
           ko_status_name(status), result.bytes_read);
    for (size_t i = 0; i < result.bytes_read; ++i) printf("%02x", result.observed[i]);
    puts("\",\"trap_supported\":false}");
    return status == KO_MATCH ? 0 : 1;
}
