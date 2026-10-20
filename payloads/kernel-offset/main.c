/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <ps5/kernel.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "backend.h"
int sceKernelGetMainSocId(void);
#ifndef KERNEL_OFFSET_LEGACY_FALLBACK
#define KERNEL_OFFSET_LEGACY_FALLBACK 0
#endif
#if KERNEL_OFFSET_LEGACY_FALLBACK != 0 && KERNEL_OFFSET_LEGACY_FALLBACK != 1
#error "KERNEL_OFFSET_LEGACY_FALLBACK must be 0 or 1"
#endif
/* A provider is explicitly linked via KERNEL_OFFSET_PROVIDER. No unknown
 * resident calls or kernel-memory discovery occur when it is absent. */
#ifdef KERNEL_OFFSET_HAS_PROVIDER
extern const struct ko_provider ko_readiness_provider;
#endif
static int sdk_read(void *unused, uint64_t address, void *out, size_t length) {
    (void)unused;
    return kernel_copyout((intptr_t)address, out, length);
}
static int fresh_challenge(uint64_t challenge[2]) {
    unsigned char *p = (void *)challenge;
    size_t left = sizeof(uint64_t) * 2;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    while (left) {
        ssize_t n = read(fd, p, left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return -1; }
        p += n; left -= (size_t)n;
    }
    if (close(fd)) return -1;
    return ko_nonzero(challenge, sizeof(uint64_t) * 2) ? 0 : -1;
}
static void print_hex(const void *bytes, size_t length) {
    const unsigned char *p = bytes;
    while (length--) printf("%02x", *p++);
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint32_t fw = kernel_get_fw_version();
    int soc = sceKernelGetMainSocId();
    uint64_t text = KERNEL_ADDRESS_TEXT_BASE, data = KERNEL_ADDRESS_DATA_BASE;
    struct ko_policy policy = {NULL, {0, 0}, KERNEL_OFFSET_LEGACY_FALLBACK};
#ifdef KERNEL_OFFSET_HAS_PROVIDER
    policy.provider = &ko_readiness_provider;
#endif
    struct ko_result result = {0};
    enum ko_status status;
    if (policy.provider && fresh_challenge(policy.challenge)) status = KO_NONCE_ERROR;
    else status = ko_probe(fw, soc, text, data, sdk_read, NULL, &policy, &result);
    printf("KOFFSET_JSON={\"schema\":2,\"profile\":\"%s\",\"pid\":%d,\"observed_at_unix\":%lld,"
           "\"firmware_raw\":\"0x%08x\",\"soc_id\":\"0x%x\","
           "\"kernel_text_va\":\"0x%016llx\",\"kernel_data_va\":\"0x%016llx\","
           "\"text_offset\":\"0x%llx\",\"address\":\"0x%016llx\","
           "\"status\":\"%s\",\"bytes_read\":%zu,\"observed\":\"",
           KO_PROFILE, getpid(), (long long)time(NULL), fw, (unsigned)soc,
           (unsigned long long)text, (unsigned long long)data,
           (unsigned long long)KO_TEXT_OFFSET, (unsigned long long)result.address,
           ko_status_name(status), result.bytes_read);
    print_hex(result.observed, result.bytes_read);
    printf("\",\"trap_supported\":false,\"readiness\":{\"source\":\"%s\","
           "\"fallback_reason\":%s,\"legacy_profile\":%s,\"abi_version\":%u,\"record_size\":%u,\"state\":%u,\"active_hooks\":%u,\"cr3\":\"0x%llx\",\"build_id\":\"",
           ko_source_name(result.source),
           result.source == KO_SOURCE_LEGACY ? "\"provider_unavailable\"" : "null",
           result.source == KO_SOURCE_LEGACY ? "\"" KO_LEGACY_PROFILE "\"" : "null",
           result.readiness.abi_version, result.readiness.record_size,
           result.readiness.state, result.readiness.active_hooks, (unsigned long long)result.readiness.cr3);
    print_hex(result.readiness.build_id, sizeof(result.readiness.build_id));
    printf("\",\"session_id\":\"");
    print_hex(result.readiness.session, sizeof(result.readiness.session));
    printf("\",\"generation\":\"0x%llx\",\"capabilities\":\"0x%llx\","
           "\"expected_cpus\":\"0x%x\",\"completed_cpus\":\"0x%x\",\"challenge\":\"",
           (unsigned long long)result.readiness.generation,
           (unsigned long long)result.readiness.capabilities,
           result.readiness.expected_cpus, result.readiness.completed_cpus);
    print_hex(result.first_challenge, sizeof(result.first_challenge));
    printf("\",\"final_challenge\":\"");
    print_hex(result.final_challenge, sizeof(result.final_challenge));
    puts("\"}}");
    return status == KO_MATCH ? 0 : 1;
}
