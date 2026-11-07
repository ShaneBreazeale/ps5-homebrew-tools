/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef KP_STAGE2_CLIENT_H
#define KP_STAGE2_CLIENT_H
#include "bridge.h"
struct kp_stage2_provider {
    void *context;
    int (*exchange)(void *, const struct kp_bridge_request *, struct kp_probe_reply *);
    unsigned char build[32], token[32];
};
enum kp_s2_client_status { KPS2_MATCH, KPS2_NO_PROVIDER, KPS2_CHALLENGE, KPS2_TRANSPORT,
    KPS2_BAD_REPLY, KPS2_REFUSED, KPS2_ENVIRONMENT, KPS2_CHANGED };
struct kp_s2_observation {
    enum kp_s2_client_status status;
    unsigned count, transport_ok[2];
    struct kp_probe_request requests[2];
    struct kp_probe_reply replies[2];
};
static inline const char *kp_s2_status_name(enum kp_s2_client_status status) {
    static const char *names[] = {"identity_match", "provider_unavailable", "invalid_challenge",
        "transport_error", "invalid_reply", "resident_refused", "environment_mismatch", "identity_changed"};
    return (unsigned)status < sizeof(names)/sizeof(*names) ? names[status] : "invalid_status";
}
static inline int kp_s2_reply_valid(const struct kp_probe_request *q, const struct kp_probe_reply *r) {
    if (r->abi != KP_ABI || r->size != sizeof(*r) || memcmp(q->challenge, r->challenge, 16)
            || (r->flags & ~KP_PROBE_CHECKED) || r->sequence || r->applied_mask
            || r->poisoned > 1 || kp_nonzero((const unsigned char *)&r->last_request, sizeof(r->last_request))
            || kp_nonzero((const unsigned char *)&r->last_result, sizeof(r->last_result))) return 0;
    if (!kp_nonzero((const unsigned char *)&r->identity, sizeof(r->identity))) {
        return (r->status == KP_INVALID || r->status == KP_STALE) && !r->flags && !r->poisoned;
    }
    if (!kp_identity_valid(&r->identity) || r->identity.capabilities != KP_CAP_INSPECT
            || memcmp(q->build, r->identity.build, 32)) return 0;
    if (r->status == KP_OK) return r->flags == KP_PROBE_CHECKED && !r->poisoned;
    return !r->flags && r->poisoned && (r->status == KP_STALE || r->status == KP_POISONED);
}
static inline enum kp_s2_client_status kp_s2_observe(const struct kp_stage2_provider *provider,
        uint32_t firmware, uint32_t soc, uint64_t text, uint64_t data,
        const unsigned char challenges[2][16], struct kp_s2_observation *out) {
    if (!out) return KPS2_BAD_REPLY;
    memset(out, 0, sizeof(*out));
    out->status = KPS2_NO_PROVIDER;
    if (!provider || !provider->exchange || !kp_nonzero(provider->build, 32)
            || !kp_nonzero(provider->token, 32)) return out->status;
    out->status = KPS2_ENVIRONMENT;
    if ((firmware & 0xffff0000u) != 0x13600000u || soc != 0x840fd0u
            || !kp_kernel(text) || !kp_kernel(data) || (text & 4095) || (data & 4095)
            || data - text != 0xcc0000u) return out->status;
    out->status = KPS2_CHALLENGE;
    if (!challenges || !kp_nonzero(challenges[0], 16) || !kp_nonzero(challenges[1], 16)
            || !memcmp(challenges[0], challenges[1], 16)) return out->status;
    for (unsigned i = 0; i < 2; ++i) {
        struct kp_bridge_request request = {.abi = KP_ABI, .size = sizeof(request)};
        request.query = (struct kp_probe_request){.abi = KP_ABI, .size = sizeof(request.query), .operation = KP_PROBE_QUERY};
        memcpy(request.token, provider->token, 32);
        memcpy(request.query.build, provider->build, 32);
        memcpy(request.query.challenge, challenges[i], 16);
        out->requests[i] = request.query; /* never retain credentials in evidence */
        out->count = i + 1;
        int error = provider->exchange(provider->context, &request, out->replies + i);
        kp_bridge_wipe(&request, sizeof(request));
        out->status = KPS2_TRANSPORT;
        if (error) return out->status;
        out->transport_ok[i] = 1;
        const struct kp_probe_reply *reply = out->replies + i;
        out->status = KPS2_BAD_REPLY;
        if (!kp_s2_reply_valid(out->requests + i, reply)) return out->status;
        out->status = KPS2_REFUSED;
        if (reply->status != KP_OK) return out->status;
        out->status = KPS2_ENVIRONMENT;
        if (reply->identity.firmware != firmware || reply->identity.soc != soc
                || reply->identity.text_base != text || reply->identity.data_base != data) return out->status;
    }
    out->status = KPS2_CHANGED;
    if (memcmp(&out->replies[0].identity, &out->replies[1].identity, sizeof(struct kp_identity))) return out->status;
    out->status = KPS2_MATCH;
    return out->status;
}
#endif
