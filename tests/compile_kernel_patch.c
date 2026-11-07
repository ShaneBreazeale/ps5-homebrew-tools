/* SPDX-License-Identifier: GPL-3.0-or-later
 * Compile-only: no payload, installer, kernel entry or live write backend.
 */
#include "../residents/patch/probe.h"
int kp_fixture_init(struct kp_engine *e, const struct kp_identity *id,
        const struct kp_policy *policies, unsigned count, const struct kp_adapter *a) {
    return kp_init(e, id, policies, count, a);
}
int kp_fixture_execute(struct kp_engine *e, const struct kp_request *q, struct kp_result *r) {
    return kp_execute(e, q, r);
}
int kp_fixture_probe(struct kp_engine *e, const struct kp_probe_request *q, struct kp_probe_reply *r) {
    return kp_probe(e, q, r);
}
