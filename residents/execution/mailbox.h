/* SPDX-License-Identifier: GPL-3.0-or-later
 * One fixed in-flight request. Native little-endian ABI on coherent shared RAM.
 * No allocation, socket, syscall or dependence on a scheduled transport thread.
 */
#ifndef KERNEL_EXECUTION_MAILBOX_H
#define KERNEL_EXECUTION_MAILBOX_H
#include "control.h"
enum kd_mail_phase { KD_MAIL_EMPTY, KD_MAIL_WRITING, KD_MAIL_READY,
    KD_MAIL_SERVICING, KD_MAIL_DONE, KD_MAIL_READING };
struct kd_mailbox {
    uint32_t phase;
    struct kd_request request;
    struct kd_reply reply;
};
static inline int kd_mail_claim(struct kd_mailbox *m, uint32_t from, uint32_t to) {
    return __atomic_compare_exchange_n(&m->phase, &from, to, 0,
        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}
/* Initialize to zero only while both sides are quiescent. No timeout reset:
 * resetting a mailbox with an in-flight writer/service loses transaction state. */
static inline int kd_mail_submit(struct kd_mailbox *m, const struct kd_request *q) {
    if (!m || !q) return KD_INVALID;
    if (!kd_mail_claim(m, KD_MAIL_EMPTY, KD_MAIL_WRITING)) return KD_BUSY;
    m->request = *q;
    __atomic_store_n(&m->phase, KD_MAIL_READY, __ATOMIC_RELEASE);
    return KD_OK;
}
/* May be polled by a resident CPU in the park loop. A busy coordinator returns
 * the SAME request to READY; nothing is consumed or replayed as a new command. */
static inline int kd_mail_service(struct kd_mailbox *m, struct kd_control *c, uint64_t now) {
    if (!m || !c) return KD_INVALID;
    if (!kd_mail_claim(m, KD_MAIL_READY, KD_MAIL_SERVICING)) return KD_BUSY;
    int error = kd_command(c, &m->request, now, &m->reply);
    __atomic_store_n(&m->phase, error ? KD_MAIL_READY : KD_MAIL_DONE, __ATOMIC_RELEASE);
    return error;
}
static inline int kd_mail_receive(struct kd_mailbox *m, struct kd_reply *out) {
    if (!m || !out) return KD_INVALID;
    if (!kd_mail_claim(m, KD_MAIL_DONE, KD_MAIL_READING)) return KD_BUSY;
    *out = m->reply;
    __atomic_store_n(&m->phase, KD_MAIL_EMPTY, __ATOMIC_RELEASE);
    return KD_OK;
}
#endif
