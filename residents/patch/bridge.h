/* SPDX-License-Identifier: GPL-3.0-or-later
 * Authenticated, query-only local bridge. User buffers and transport remain
 * platform operations. No mutation operation is dispatched here.
 */
#ifndef KERNEL_PATCH_BRIDGE_H
#define KERNEL_PATCH_BRIDGE_H
#include <errno.h>
#include "probe.h"
#define KP_BRIDGE_SELECTOR UINT32_C(0x4b500001)
#define KP_BRIDGE_COMMAND UINT64_C(0x4b50000100000027)
struct kp_bridge_request {
    uint32_t abi, size;
    unsigned char token[32];
    struct kp_probe_request query;
};
_Static_assert(sizeof(struct kp_bridge_request) == 104, "patch bridge request ABI");
struct kp_bridge_io {
    void *context;
    int (*user_access)(void *, uint64_t, size_t, int);
    int (*read_user)(void *, uint64_t, void *, size_t);
    int (*write_user)(void *, uint64_t, const void *, size_t);
    int (*query)(void *, const struct kp_probe_request *, struct kp_probe_reply *);
};
static inline void kp_bridge_wipe(void *data, size_t length) {
    volatile unsigned char *p = data;
    while (length--) *p++ = 0;
}
static inline int kp_user_range(uint64_t address, size_t length) {
    return address && address < (UINT64_C(1) << 47) && length
        && length <= (UINT64_C(1) << 47) - address;
}
static inline int kp_token_equal(const unsigned char a[32], const unsigned char b[32]) {
    unsigned difference = 0;
    for (unsigned i = 0; i < 32; ++i) difference |= a[i] ^ b[i];
    return !difference;
}
static inline int kp_bridge_handle(const unsigned char token[32], const struct kp_bridge_io *io,
        uint64_t request_address, uint64_t request_size, uint64_t reply_address,
        uint64_t reply_size, uint64_t reserved) {
    if (!token || !kp_nonzero(token, 32) || !io || !io->user_access || !io->read_user
            || !io->write_user || !io->query || reserved
            || request_size != sizeof(struct kp_bridge_request) || reply_size != sizeof(struct kp_probe_reply)
            || !kp_user_range(request_address, request_size) || !kp_user_range(reply_address, reply_size)
            || (request_address < reply_address + reply_size && reply_address < request_address + request_size)) return EINVAL;
    if (io->user_access(io->context, request_address, request_size, 0)
            || io->user_access(io->context, reply_address, reply_size, 1)) return EFAULT;
    struct kp_bridge_request request = {0};
    int error = EFAULT;
    if (io->read_user(io->context, request_address, &request, sizeof(request))) goto done;
    error = EACCES;
    if (!kp_token_equal(token, request.token)) goto done;
    error = EINVAL;
    if (request.abi != KP_ABI || request.size != sizeof(request) || !kp_probe_request_valid(&request.query)) goto done;
    struct kp_probe_reply reply = {0};
    error = io->query(io->context, &request.query, &reply);
    if (error == KP_BUSY) error = EBUSY;
    else if (error) error = EIO;
    if (error) goto done;
    if (reply.abi != KP_ABI || reply.size != sizeof(reply)) { error = EIO; goto done; }
    if (io->user_access(io->context, reply_address, reply_size, 1)
            || io->write_user(io->context, reply_address, &reply, sizeof(reply))) error = EFAULT;
done:
    kp_bridge_wipe(&request, sizeof(request));
    return error;
}
#endif
