/* SPDX-License-Identifier: GPL-3.0-or-later
 * Bounded resident service core. Single serialized installer publishes atomic
 * words; queries never wait or take a lock in the resident exception context.
 */
#ifndef KO_RESIDENT_H
#define KO_RESIDENT_H
#include <errno.h>
#include "readiness.h"
#define KO_CHECK_MAX 64
#define KO_REPLY_WORDS (sizeof(struct ko_ready_reply)/8)
struct ko_live_check { uint64_t address, expected; };
struct ko_resident_image {
    struct ko_ready_reply reply;
    uint64_t check_count;
    struct ko_live_check checks[KO_CHECK_MAX];
};
struct ko_resident_store {
    uint64_t sequence, revoked;
    uint64_t words[sizeof(struct ko_resident_image)/8];
};
_Static_assert(sizeof(struct ko_resident_image) == 1192, "resident image layout");
_Static_assert(sizeof(struct ko_resident_store) == 1208, "resident store layout");
/* Addresses of this fixed store only. Writer must preserve x86 ordering and
 * verify each write; an interrupted publication is left odd (unavailable).
 */
typedef int (*ko_store_read)(void *, uint64_t, void *, size_t);
typedef int (*ko_store_write)(void *, uint64_t, const void *, size_t);
static inline int ko_resident_publish(uint64_t address, struct ko_resident_image *image,
        ko_store_read read, ko_store_write write, void *ctx) {
    uint64_t old = 0, observed = 0;
    if ((address & 7) || !image || image->check_count > KO_CHECK_MAX
        || read(ctx, address, &old, 8) || (old & 1) || old > UINT64_MAX-2) return -1;
    uint64_t odd = old+1, next = old+2;
    if (write(ctx, address, &odd, 8) || read(ctx, address, &observed, 8) || observed != odd) return -1;
    image->reply.generation = next;
    if (write(ctx, address+16, image, sizeof(*image))) return -1;
    struct ko_resident_image check;
    if (read(ctx, address+16, &check, sizeof(check)) || memcmp(image, &check, sizeof(check))) return -1;
    if (write(ctx, address, &next, 8) || read(ctx, address, &observed, 8) || observed != next) return -1;
    return 0;
}
static inline int ko_resident_snapshot(struct ko_resident_store *store, struct ko_resident_image *image) {
    uint64_t first = __atomic_load_n(&store->sequence, __ATOMIC_ACQUIRE);
    if (!first || (first & 1)) return EAGAIN;
    uint64_t words[sizeof(*image)/8];
    for (size_t i=0; i<sizeof(words)/sizeof(words[0]); ++i)
        words[i] = __atomic_load_n(&store->words[i], __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (__atomic_load_n(&store->sequence, __ATOMIC_ACQUIRE) != first) return EAGAIN;
    memcpy(image, words, sizeof(*image));
    if (image->reply.generation != first || image->check_count > KO_CHECK_MAX) return EINVAL;
    return 0;
}
struct ko_resident_io {
    void *ctx;
    int (*read)(void *, uint64_t, void *, size_t);
    int (*write)(void *, uint64_t, const void *, size_t);
    /* Verify current caller's user mapping, including U/S and R/W at every level. */
    int (*user_access)(void *, uint64_t, size_t, int);
};
static inline int ko_user_range(uint64_t address, uint64_t length) {
    return address && address < (UINT64_C(1)<<47) && length
        && length <= (UINT64_C(1)<<47)-address;
}
static inline int ko_resident_handle(struct ko_resident_store *store, const struct ko_resident_io *io,
        uint64_t request_address, uint64_t request_size, uint64_t reply_address, uint64_t reply_size, uint64_t reserved) {
    if (!store || !io || !io->read || !io->write || !io->user_access
        || reserved || request_size != sizeof(struct ko_ready_request) || reply_size != sizeof(struct ko_ready_reply)
        || !ko_user_range(request_address, request_size) || !ko_user_range(reply_address, reply_size)) return EINVAL;
    if (io->user_access(io->ctx, request_address, request_size, 0)
        || io->user_access(io->ctx, reply_address, reply_size, 1)) return EFAULT;
    struct ko_ready_request request;
    if (io->read(io->ctx, request_address, &request, sizeof(request))) return EFAULT;
    if (request.abi_version != KO_READY_ABI || request.record_size != sizeof(request)
        || !ko_nonzero(request.challenge, sizeof(request.challenge))) return EINVAL;
    struct ko_resident_image image;
    int error = ko_resident_snapshot(store, &image);
    if (error) return error;
    struct ko_ready_reply *r = &image.reply;
    if (r->abi_version != KO_READY_ABI || r->record_size != sizeof(*r)
        || request.text != r->text || request.data != r->data
        || request.firmware != r->firmware || request.soc != r->soc) return EINVAL;
    if (r->state == KO_READY) {
        if (!image.check_count) __atomic_store_n(&store->revoked, 1, __ATOMIC_RELEASE);
        for (size_t i=0; i<image.check_count; ++i) {
            uint64_t value = 0;
            uint64_t address = image.checks[i].address;
            /* TSS IST fields are packed at offsets 0x34/0x3c/0x54.
             * These are byte copies, not aligned atomic word accesses. */
            if ((address >> 47) != UINT64_C(0x1ffff) || address > UINT64_MAX-7
                || io->read(io->ctx, address, &value, 8) || value != image.checks[i].expected) {
                __atomic_store_n(&store->revoked, 1, __ATOMIC_RELEASE);
                break;
            }
        }
    }
    if (__atomic_load_n(&store->revoked, __ATOMIC_ACQUIRE)) {
        r->state = KO_FAILED; r->capabilities = 0; r->active_hooks = 1;
    }
    if (__atomic_load_n(&store->sequence, __ATOMIC_ACQUIRE) != r->generation) return EAGAIN;
    memcpy(r->challenge, request.challenge, sizeof(r->challenge));
    if (io->user_access(io->ctx, reply_address, reply_size, 1)
        || io->write(io->ctx, reply_address, r, sizeof(*r))) return EFAULT;
    return 0;
}
#endif
