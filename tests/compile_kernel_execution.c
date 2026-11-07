/* SPDX-License-Identifier: GPL-3.0-or-later
 * Compile-only fixture: force emission of the portable core with the normal
 * Payload SDK/LLVM gate. No main, installed resident, transport or kernel entry.
 */
#include "../residents/execution/mailbox.h"
int kd_fixture_init(struct kd_control *c, const struct kd_identity *id) { return kd_init(c, id); }
int kd_fixture_command(struct kd_control *c, const struct kd_request *q, uint64_t now, struct kd_reply *r) {
    return kd_command(c, q, now, r);
}
int kd_fixture_enter(struct kd_control *c, uint64_t epoch, unsigned cpu,
        const struct kd_frame *f, unsigned reason, uint64_t ticket, uint64_t now) {
    return kd_enter(c, epoch, cpu, f, reason, ticket, now);
}
int kd_fixture_poll(struct kd_control *c, uint64_t epoch, unsigned cpu, uint64_t now, struct kd_action *a) {
    return kd_cpu_poll(c, epoch, cpu, now, a);
}
int kd_fixture_ack(struct kd_control *c, const struct kd_action *a, int verified,
        const struct kd_frame *observed, uint64_t now) {
    return kd_cpu_ack(c, a, verified, observed, now);
}
int kd_fixture_fault(struct kd_control *c, uint64_t epoch, unsigned fault, uint64_t now) {
    return kd_fault(c, epoch, fault, now);
}
int kd_fixture_retire(struct kd_control *c, uint64_t epoch) { return kd_retire(c, epoch); }
int kd_fixture_inspect(struct kd_control *c, uint64_t now, struct kd_reply *r) { return kd_inspect(c, now, r); }
int kd_fixture_submit(struct kd_mailbox *m, const struct kd_request *q) { return kd_mail_submit(m, q); }
int kd_fixture_service(struct kd_mailbox *m, struct kd_control *c, uint64_t now) { return kd_mail_service(m, c, now); }
int kd_fixture_receive(struct kd_mailbox *m, struct kd_reply *r) { return kd_mail_receive(m, r); }
