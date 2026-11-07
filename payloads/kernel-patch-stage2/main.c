/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <ps5/kernel.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "../../residents/patch/stage2_client.h"
int sceKernelGetMainSocId(void);
#ifdef KERNEL_PATCH_STAGE2_HAS_PROVIDER
extern const struct kp_stage2_provider kp_stage2_provider;
#endif
static int kp_s2_random(unsigned char challenges[2][16]) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, challenges, 32);
    int error = close(fd);
    return n == 32 && !error && kp_nonzero(challenges[0], 16) && kp_nonzero(challenges[1], 16)
        && memcmp(challenges[0], challenges[1], 16) ? 0 : -1;
}
static void hex(const void *data, size_t length) {
    const unsigned char *p = data;
    for (size_t i = 0; i < length; ++i) printf("%02x", p[i]);
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const struct kp_stage2_provider *provider = NULL;
#ifdef KERNEL_PATCH_STAGE2_HAS_PROVIDER
    provider = &kp_stage2_provider;
#endif
    unsigned char challenges[2][16] = {{0}};
    struct kp_s2_observation observation = {0};
    uint32_t fw = kernel_get_fw_version(), soc = (uint32_t)sceKernelGetMainSocId();
    uint64_t text = KERNEL_ADDRESS_TEXT_BASE, data = KERNEL_ADDRESS_DATA_BASE;
    if (provider && kp_s2_random(challenges)) observation.status = KPS2_CHALLENGE;
    else (void)kp_s2_observe(provider, fw, soc, text, data, challenges, &observation);
    printf("KP_STAGE2_JSON={\"schema\":1,\"pid\":%d,\"observed_at_unix\":%lld,"
        "\"firmware\":\"0x%x\",\"soc\":\"0x%x\",\"text_base\":\"0x%llx\",\"data_base\":\"0x%llx\","
        "\"status\":\"%s\",\"write_enabled\":false,\"queries\":[",
        getpid(), (long long)time(NULL), fw, soc, (unsigned long long)text, (unsigned long long)data,
        kp_s2_status_name(observation.status));
    for (unsigned i = 0; i < observation.count; ++i) {
        if (i) putchar(',');
        printf("{\"transport_ok\":%s,\"request\":\"", observation.transport_ok[i] ? "true" : "false");
        hex(observation.requests + i, sizeof(struct kp_probe_request));
        printf("\",\"reply\":\"");
        hex(observation.replies + i, sizeof(struct kp_probe_reply));
        printf("\"}");
    }
    puts("]}");
    return observation.status == KPS2_MATCH ? 0 : 1;
}
