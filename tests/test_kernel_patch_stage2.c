/* SPDX-License-Identifier: GPL-3.0-or-later
 * Real stage 2 bootstrap, authenticated bridge and client, with memory/syscall IO.
 */
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "../residents/patch/stage2.h"
#include "../residents/patch/user_pages.h"
#define K UINT64_C(0xffffffff80000000)
#define STORE (K + 0x2000000)
#define PMAP (K + 0x1800000)
#define PML4 (K + 0x3000000)
static struct kp_stage2_store server;
static uint64_t live_cr3 = 0x1000;
static unsigned cpu_values[16], kernel_reads, kernel_writes, fail_copy;
static ssize_t copyout(void *out, uint64_t address, size_t length) {
    ++kernel_reads;
    if (address >= STORE && address - STORE <= sizeof(server) && length <= sizeof(server) - (address - STORE)) {
        memcpy(out, (unsigned char *)&server + (address - STORE), length); return (ssize_t)length;
    }
    uint64_t word;
    if (address == PMAP + 0x20 && length == 8) word = PML4;
    else if (address == PMAP + 0x28 && length == 8) word = live_cr3;
    else if (address == K + 0x38fc12 && length == 7) {
        memcpy(out, "\x4c\x8d\x2d\xf7\xc6\x58\x03", 7); return 7;
    } else if (address >= K + 0x4000000 && address < K + 0x4001000 && length == 8) {
        unsigned cpu = (unsigned)((address - K - 0x4000000) / 0x100);
        word = K + 0x5000000 + cpu;
    } else if (address >= K + 0x6000000 && address < K + 0x6001000 && length == 8) {
        unsigned cpu = (unsigned)((address - K - 0x6000000) / 0x100);
        word = K + 0x5000000 + cpu + cpu_values[cpu];
    } else return -1;
    memcpy(out, &word, 8); return 8;
}
static ssize_t copyin(uint64_t address, const void *in, size_t length) {
    ++kernel_writes;
    if (fail_copy || address != STORE || (length != sizeof(server) && length != 4)) return -1;
    memcpy(&server, in, length);
    return (ssize_t)length;
}
static int soc(void) { return 0x840fd0; }
static void *fake_dlsym(void *handle, const char *name) {
    assert(handle == (void *)1 && !strcmp(name, "sceKernelGetMainSocId"));
    return (void *)soc;
}
#define dlsym fake_dlsym
#include "../residents/patch/stage2_loader.h"
#undef dlsym
static void setup(void) {
    memset(&server, 0, sizeof(server));
    memset(cpu_values, 0, sizeof(cpu_values));
    fail_copy = kernel_reads = kernel_writes = 0;
    live_cr3 = 0x1000;
    assert(!kp_s2_prepare());
    for (unsigned cpu = 0; cpu < 16; ++cpu) {
        assert(!kp_s2_cpu_complete(cpu, K + 0x4000000 + cpu * 0x100, K + 0x6000000 + cpu * 0x100));
    }
    assert(!kp_s2_publish(STORE, K + 0xcc0000, 0x13600000, PMAP));
    assert(kp_stage2_valid(&server) && kernel_writes == 2);
    assert(!memcmp(server.identity.build, (unsigned char[32])KPS2_BUILD_BYTES, 32));
}
static struct {
    const struct kp_bridge_request *input;
    struct kp_probe_reply *output;
    unsigned reads, writes, queries, deny, bad_token, short_copy, fail_reply, corrupt, change;
} call;
static int user_access(void *unused, uint64_t address, size_t length, int writing) {
    (void)unused;
    return call.deny || address != (uint64_t)(uintptr_t)(writing ? (const void *)call.output : (const void *)call.input)
        || length != (writing ? sizeof(*call.output) : sizeof(*call.input));
}
static int read_user(void *unused, uint64_t address, void *out, size_t length) {
    (void)unused;
    assert(!user_access(NULL, address, length, 0));
    ++call.reads;
    if (call.short_copy) { memcpy(out, call.input, 8); return EFAULT; }
    memcpy(out, call.input, length);
    if (call.bad_token) ((struct kp_bridge_request *)out)->token[31] ^= 1;
    return 0;
}
static int write_user(void *unused, uint64_t address, const void *in, size_t length) {
    (void)unused;
    assert(!user_access(NULL, address, length, 1));
    ++call.writes;
    if (call.fail_reply) return EFAULT;
    memcpy(call.output, in, length);
    if (call.corrupt) call.output->challenge[0] ^= 1;
    if (call.change && call.writes == 2) ++call.output->identity.generation;
    return 0;
}
static int read_live(void *unused, uint64_t address, void *out, size_t length) {
    (void)unused;
    return copyout(out, address, length) == (ssize_t)length ? 0 : EFAULT;
}
static int query(void *unused, const struct kp_probe_request *q, struct kp_probe_reply *r) {
    (void)unused;
    ++call.queries;
    return kp_stage2_probe(&server, q, read_live, NULL, r);
}
#define KPS2_TRANSPORT_TEST
#include "../residents/patch/stage2_client.c"
struct kp_s2_call_result kp_s2_call(uint64_t a, uint64_t b, uint64_t c, uint64_t e, uint64_t f, uint64_t nr) {
    assert(b == sizeof(struct kp_bridge_request) && e == sizeof(struct kp_probe_reply) && !f && nr == KP_BRIDGE_COMMAND);
    call.input = (const void *)(uintptr_t)a;
    call.output = (void *)(uintptr_t)c;
    struct kp_bridge_io io = {NULL, user_access, read_user, write_user, query};
    int error = kp_bridge_handle(server.token, &io, a, b, c, e, f);
    return (struct kp_s2_call_result){(uint64_t)error, error != 0};
}
static enum kp_s2_client_status observe(struct kp_s2_observation *out) {
    const unsigned char challenges[2][16] = {{4}, {5}};
    return kp_s2_observe(&kp_stage2_provider, 0x13600000, 0x840fd0, K, K + 0xcc0000, challenges, out);
}
static void end_to_end(void) {
    setup(); memset(&call, 0, sizeof(call));
    struct kp_s2_observation out;
    unsigned writes = kernel_writes;
    assert(observe(&out) == KPS2_MATCH && out.count == 2 && call.queries == 2 && call.writes == 2);
    assert(out.replies[0].identity.capabilities == KP_CAP_INSPECT && kernel_writes == writes);
    assert(!memcmp(&out.replies[0].identity, &out.replies[1].identity, sizeof(struct kp_identity)));
    for (size_t i = 0; i + 32 <= sizeof(out); ++i)
        assert(memcmp((unsigned char *)&out + i, server.token, 32));
    unsigned before_publish = kernel_writes;
    assert(kp_s2_publish(STORE, K + 0xcc0000, 0x13600000, PMAP));
    assert(kernel_writes == before_publish); /* no overwrite of a live publication */
    memset(&call, 0, sizeof(call)); call.bad_token = 1;
    unsigned reads = kernel_reads;
    assert(observe(&out) == KPS2_TRANSPORT && out.count == 1 && !call.writes && !call.queries && kernel_reads == reads);
    memset(&call, 0, sizeof(call)); call.deny = 1;
    assert(observe(&out) == KPS2_TRANSPORT && !call.reads && !call.queries);
    memset(&call, 0, sizeof(call)); call.short_copy = 1;
    assert(observe(&out) == KPS2_TRANSPORT && !call.writes && !call.queries);
    memset(&call, 0, sizeof(call)); call.fail_reply = 1;
    assert(observe(&out) == KPS2_TRANSPORT && out.count == 1);
    memset(&call, 0, sizeof(call)); call.corrupt = 1;
    assert(observe(&out) == KPS2_BAD_REPLY && out.count == 1);
    memset(&call, 0, sizeof(call)); call.change = 1;
    assert(observe(&out) == KPS2_CHANGED && out.count == 2);
    memset(&call, 0, sizeof(call)); live_cr3 = 0x2000;
    assert(observe(&out) == KPS2_REFUSED && out.count == 1 && server.revoked);
    reads = kernel_reads; live_cr3 = 0x1000;
    assert(observe(&out) == KPS2_REFUSED && kernel_reads == reads); /* sticky */
    assert(kernel_writes == writes);
    setup(); memset(&call, 0, sizeof(call));
    const unsigned char duplicate[2][16] = {{1}, {1}};
    assert(kp_s2_observe(&kp_stage2_provider, 0x13600000, 0x840fd0, K, K + 0xcc0000, duplicate, &out) == KPS2_CHALLENGE);
    assert(!call.queries);
    assert(kp_s2_observe(&kp_stage2_provider, 0x14000000, 0x840fd0, K, K + 0xcc0000, duplicate, &out) == KPS2_ENVIRONMENT);
    assert(!call.queries);
    struct kp_stage2_provider wrong_build = kp_stage2_provider;
    wrong_build.build[0] ^= 1;
    const unsigned char fresh[2][16] = {{4}, {5}};
    unsigned checked_reads = kernel_reads;
    assert(kp_s2_observe(&wrong_build, 0x13600000, 0x840fd0, K, K + 0xcc0000, fresh, &out) == KPS2_REFUSED);
    assert(kernel_reads == checked_reads);
    memset(&call, 0, sizeof(call));
    __atomic_store_n(&server.gate, 1, __ATOMIC_RELEASE);
    assert(observe(&out) == KPS2_TRANSPORT && !call.writes);
    __atomic_store_n(&server.gate, 0, __ATOMIC_RELEASE);
    puts("stage 2 authenticated client/bridge/publication passed");
}
static uint64_t pages[4][512];
static int phys_read(void *unused, uint64_t address, uint64_t *out) {
    (void)unused;
    if (address < 0x1000 || address >= 0x5000 || (address & 7)) return EFAULT;
    *out = pages[(address - 0x1000) / 0x1000][(address & 4095) / 8]; return 0;
}
static void paging(void) {
    memset(pages, 0, sizeof(pages));
    pages[0][0] = 0x2007; pages[1][0] = 0x3007; pages[2][0] = 0x4007;
    pages[3][1] = 0x10007; pages[3][2] = 0x20007;
    assert(!kp_pages_access(0x1000, 0x1ff0, 32, 1, 1, phys_read, NULL));
    pages[3][2] &= ~UINT64_C(2);
    assert(kp_pages_access(0x1000, 0x1ff0, 32, 1, 1, phys_read, NULL));
    pages[3][2] |= 2;
    pages[1][0] &= ~UINT64_C(4);
    assert(kp_pages_access(0x1000, 0x1000, 104, 1, 0, phys_read, NULL));
    pages[1][0] |= 4 | (UINT64_C(1) << 58);
    assert(kp_pages_access(0x1000, 0x1000, 104, 1, 0, phys_read, NULL));
    pages[1][0] &= ~(UINT64_C(1) << 58);
    pages[1][0] = 0x40000087;
    assert(!kp_pages_access(0x1000, 0x1000, 104, 1, 1, phys_read, NULL));
    pages[1][0] |= 0x2000; /* misaligned huge page */
    assert(kp_pages_access(0x1000, 0x1000, 104, 1, 0, phys_read, NULL));
    assert(kp_pages_access(0x1000, K, 720, 1, 1, phys_read, NULL));
    assert(kp_pages_access(0x1000, 0x1000, 1025, 1, 0, phys_read, NULL));
    puts("stage 2 page-permission audit passed");
}
uint32_t kernel_get_fw_version(void) { return 0x13600000; }
int sceKernelGetMainSocId(void) { return 0x840fd0; }
const intptr_t KERNEL_ADDRESS_TEXT_BASE = (intptr_t)K;
const intptr_t KERNEL_ADDRESS_DATA_BASE = (intptr_t)(K + 0xcc0000);
#define KERNEL_PATCH_STAGE2_HAS_PROVIDER 1
#define main kp_s2_payload_main
#include "../payloads/kernel-patch-stage2/main.c"
#undef main
int main(int argc, char **argv) {
    if (argc == 2) {
        setup(); memset(&call, 0, sizeof(call));
        if (!strcmp(argv[1], "payload-denied")) call.bad_token = 1;
        else if (strcmp(argv[1], "payload")) return 2;
        return kp_s2_payload_main();
    }
    end_to_end(); paging(); return 0;
}
