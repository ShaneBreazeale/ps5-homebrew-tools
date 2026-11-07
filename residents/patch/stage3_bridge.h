/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef KP_STAGE3_BRIDGE_H
#define KP_STAGE3_BRIDGE_H
#include "stage3.h"
struct kp_stage3_envelope {
    uint32_t abi, size;
    unsigned char token[32];
    struct kp_request command;
};
_Static_assert(sizeof(struct kp_stage3_envelope) == 360, "owned-cell command envelope");
struct kp_stage3_io {
    struct kp_bridge_io user;
    struct kp_stage3_context service;
};
static inline int kp_stage3_bridge(struct kp_stage3_io *io, uint32_t selector, uint64_t a, uint64_t n,
        uint64_t b, uint64_t m, uint64_t reserved) {
    int query = selector == KP_STAGE3_QUERY_SELECTOR;
    if (!io || (selector != KP_STAGE3_EXERCISE_SELECTOR && !query)) return EINVAL;
    struct kp_bridge_io *u = &io->user;
    size_t qs = query ? sizeof(struct kp_bridge_request) : sizeof(struct kp_stage3_envelope);
    size_t rs = query ? sizeof(struct kp_probe_reply) : sizeof(struct kp_result);
    if (!u->user_access || !u->read_user || !u->write_user || !io->service.publication || reserved
            || n != qs || m != rs || !kp_user_range(a,n) || !kp_user_range(b,m)
            || (a < b+m && b < a+n)) return EINVAL;
    if (u->user_access(u->context,a,n,0) || u->user_access(u->context,b,m,1)) return EFAULT;
    union { struct kp_bridge_request q; struct kp_stage3_envelope c; } request = {0};
    union { struct kp_probe_reply q; struct kp_result c; } reply = {0};
    int error = EFAULT;
    if (u->read_user(u->context,a,&request,qs)) goto done;
    error = EACCES;
    if (!kp_nonzero(io->service.publication->token,32)
            || !kp_token_equal(io->service.publication->token,request.q.token)) goto done;
    error = EINVAL;
    if (request.q.abi != KP_ABI || request.q.size != qs) goto done;
    int status = kp_stage3_service(&io->service,query ? &request.q.query : NULL,
        query ? NULL : &request.c.command,query ? &reply.q : NULL,query ? NULL : &reply.c);
    error = status == KP_BUSY ? EBUSY : status ? EIO : 0;
    if (error) goto done;
    /* Results are already cached under the service gate before this copy. A
     * copyout failure leaves history intact for a fresh read-only query. */
    if (u->user_access(u->context,b,m,1) || u->write_user(u->context,b,&reply,rs)) error = EFAULT;
done:
    kp_bridge_wipe(&request,sizeof(request));
    return error;
}
#endif
