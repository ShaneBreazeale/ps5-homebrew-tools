/* SPDX-License-Identifier: GPL-3.0-or-later
 * New-installation bootstrap only. Writes only the newly allocated shared tail.
 * No patching an already running resident, IDT/TSS writes or slot operations.
 */
#ifndef KP_STAGE2_LOADER_H
#define KP_STAGE2_LOADER_H
#include "stage2.h"
#include "kp_stage2_config.h"
static unsigned char kp_s2_session[16];
static uint32_t kp_s2_soc, kp_s2_completed;
static int kp_s2_prepare(void) {
    int (*soc)(void) = dlsym((void *)1, "sceKernelGetMainSocId");
    if (!soc || (kp_s2_soc = (uint32_t)soc()) != 0x840fd0u) return -1;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    /* Fixed bounded read: a short/interrupted read refuses instead of retrying. */
    ssize_t n = read(fd, kp_s2_session, sizeof(kp_s2_session));
    int error = close(fd);
    kp_s2_completed = 0;
    return n == (ssize_t)sizeof(kp_s2_session) && !error && kp_nonzero(kp_s2_session, 16) ? 0 : -1;
}
static int kp_s2_loader_read(void *unused, uint64_t address, void *out, size_t size) {
    (void)unused;
    return copyout(out, address, size) == (ssize_t)size ? 0 : -1;
}
static int kp_s2_cpu_complete(unsigned cpu, uint64_t entry, uint64_t tss) {
    const unsigned slots[3] = {3, 4, 7};
    const unsigned offsets[3] = {8, 24, 40};
    if (cpu >= 16 || (kp_s2_completed & (1u << cpu))) return -1;
    for (unsigned i = 0; i < 3; ++i) {
        uint64_t expected = 0, actual = 0;
        if (kp_s2_loader_read(NULL, entry + offsets[i], &expected, 8)
                || kp_s2_loader_read(NULL, tss + 28 + slots[i] * 8, &actual, 8)
                || !kp_kernel(expected) || expected != actual) return -1;
    }
    kp_s2_completed |= 1u << cpu;
    return 0;
}
static int kp_s2_publish(uint64_t address, uint64_t data, uint32_t firmware, uint64_t pmap) {
    struct kp_stage2_store state = {0}, check = {0};
    const unsigned char build[32] = KPS2_BUILD_BYTES, token[32] = KPS2_TOKEN_BYTES;
    state.identity = (struct kp_identity){.abi = KP_ABI, .size = sizeof(state.identity),
        .firmware = firmware, .soc = kp_s2_soc, .capabilities = KP_CAP_INSPECT,
        .generation = 1, .text_base = data - UINT64_C(0xcc0000), .data_base = data, .resident_base = address};
    memcpy(state.identity.session, kp_s2_session, 16);
    memcpy(state.identity.build, build, 32);
    memcpy(state.token, token, 32);
    state.pmap = pmap;
    state.expected_cpus = 0xffff;
    state.completed_cpus = kp_s2_completed;
    if ((address & 7) || !kp_kernel(address) || address > UINT64_MAX - sizeof(state)
            || !kp_kernel(pmap) || pmap > UINT64_MAX - 0x30
            || kp_s2_loader_read(NULL, pmap + 0x20, &state.pml4, 8)
            || kp_s2_loader_read(NULL, pmap + 0x28, &state.cr3, 8)
            || !kp_stage2_valid(&state) || !kp_stage2_live(&state, kp_s2_loader_read, NULL)
            || kp_s2_loader_read(NULL, address, &check, sizeof(check))
            || kp_nonzero((const unsigned char *)&check, sizeof(check))) return -1;
    state.gate = 1; /* unavailable during publication */
    if (copyin(address, &state, sizeof(state)) != (ssize_t)sizeof(state)
            || kp_s2_loader_read(NULL, address, &check, sizeof(check))
            || memcmp(&state, &check, sizeof(check))) return -1;
    uint32_t ready = 0, observed = 1;
    if (copyin(address, &ready, sizeof(ready)) != (ssize_t)sizeof(ready)
            || kp_s2_loader_read(NULL, address, &observed, sizeof(observed)) || observed) return -1;
    kp_bridge_wipe(&state, sizeof(state));
    kp_bridge_wipe(&check, sizeof(check));
    return 0;
}
#endif
