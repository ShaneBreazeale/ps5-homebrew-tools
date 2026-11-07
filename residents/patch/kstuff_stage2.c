/* SPDX-License-Identifier: GPL-3.0-or-later
 * Compiled inside the pinned kstuff overlay only. No installation from here.
 */
#include "utils.h"
#include "shared_area.h"
#include "kp_stage2/user_pages.h"
#include "kp_stage2/stage2.h"
struct kp_s2_context { uint64_t root; };
static int kp_s2_phys(void *unused, uint64_t address, uint64_t *out) {
    (void)unused;
    if ((address & 7) || address > (UINT64_C(1) << 36) - 8) return EFAULT;
    memcpy(out, DMEM + address, 8);
    return 0;
}
static int kp_s2_user(void *ctx, uint64_t address, size_t length, int writing) {
    struct kp_s2_context *c = ctx;
    if (cr3_phys != c->root) return EFAULT;
    return kp_pages_access(c->root, address, length, 1, writing, kp_s2_phys, NULL);
}
static int kp_s2_read(void *ctx, uint64_t address, void *out, size_t length) {
    struct kp_s2_context *c = ctx;
    if (cr3_phys != c->root || kp_pages_access(c->root, address, length, 0, 0, kp_s2_phys, NULL)) return EFAULT;
    return copy_from_kernel(out, address, length);
}
static int kp_s2_read_user(void *ctx, uint64_t address, void *out, size_t length) {
    if (kp_s2_user(ctx, address, length, 0)) return EFAULT;
    return copy_from_kernel(out, address, length);
}
static int kp_s2_write_user(void *ctx, uint64_t address, const void *in, size_t length) {
    if (kp_s2_user(ctx, address, length, 1)) return EFAULT;
    return copy_to_kernel(address, in, length);
}
static int kp_s2_query(void *ctx, const struct kp_probe_request *q, struct kp_probe_reply *r) {
    if (FWVER != 0x1360u) return KP_INVALID;
    return kp_stage2_probe(&shared_area.kp_stage2, q, kp_s2_read, ctx, r);
}
int kp_stage2_handle(uint64_t request, uint64_t size, uint64_t reply, uint64_t reply_size, uint64_t reserved) {
    struct kp_s2_context context = {.root = cr3_phys};
    struct kp_bridge_io io = {&context, kp_s2_user, kp_s2_read_user, kp_s2_write_user, kp_s2_query};
    return kp_bridge_handle(shared_area.kp_stage2.token, &io, request, size, reply, reply_size, reserved);
}
#ifdef KP_STAGE3_ENABLED
#include "kp_stage2/stage3_bridge.h"
int kp_stage3_handle(uint32_t selector, uint64_t request, uint64_t size, uint64_t reply,
        uint64_t reply_size, uint64_t reserved) {
    if (FWVER != 0x1360u) return EINVAL;
    struct kp_s2_context context = {.root = cr3_phys};
    struct kp_stage3_io io = {
        .user = {&context,kp_s2_user,kp_s2_read_user,kp_s2_write_user,NULL},
        .service = {&shared_area.kp_stage2,&shared_area.kp_stage3,kp_s2_read,&context,
            shared_area.kp_stage2.identity.resident_base + sizeof(struct kp_stage2_store)
                + offsetof(struct kp_stage3_store,value)}
    };
    return kp_stage3_bridge(&io,selector,request,size,reply,reply_size,reserved);
}
#endif
