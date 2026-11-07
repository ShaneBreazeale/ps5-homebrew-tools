/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef KP_STAGE3_CLIENT_H
#define KP_STAGE3_CLIENT_H
#include "stage3_bridge.h"
struct kp_stage3_provider {
    void *context;
    int (*exchange)(void *, uint32_t, const void *, size_t, void *, size_t);
    unsigned char build[32], token[32];
};
enum kp_s3_status { KPS3_RESTORED, KPS3_RECOVERED, KPS3_NO_PROVIDER, KPS3_ENVIRONMENT,
    KPS3_CHALLENGE, KPS3_TRANSPORT, KPS3_BAD_REPLY, KPS3_REFUSED, KPS3_HISTORY,
    KPS3_COMMAND_FAILED, KPS3_UNVERIFIED, KPS3_QUERY_CHECKED, KPS3_CACHED };
struct kp_s3_observation {
    enum kp_s3_status status;
    unsigned count, transport_ok[3], command_attempted, command_transport_ok;
    struct kp_probe_request requests[3];
    struct kp_probe_reply replies[3];
    struct kp_request command;
    struct kp_result result;
};
static inline const char *kp_s3_status_name(enum kp_s3_status status) {
    static const char *names[] = {"exercise_restored", "exercise_restored_recovered", "provider_unavailable",
        "environment_mismatch", "invalid_challenge", "transport_error", "invalid_reply", "resident_refused",
        "history_present", "command_failed", "recovery_unverified", "query_checked", "cached_result"};
    return (unsigned)status < sizeof(names)/sizeof(*names) ? names[status] : "invalid_status";
}
static inline int kp_s3_result_ok(const struct kp_request *q, const struct kp_result *r, uint64_t address) {
    return r->abi == KP_ABI && r->size == sizeof(*r) && r->status == KP_OK && r->state == KP_RESTORED
        && r->flags == 2047 && r->length == 8 && r->sequence == 1 && r->address == address
        && !r->adapter_error && !r->restore_error && !r->journal_error && !r->release_error
        && !memcmp(r->preimage,q->expected,64) && !memcmp(r->observed,q->replacement,64)
        && !memcmp(r->final,q->expected,64);
}
static inline int kp_s3_probe_ok(const struct kp_probe_request *q, const struct kp_probe_reply *r,
        uint32_t fw, uint32_t soc, uint64_t text, uint64_t data) {
    return r->abi == KP_ABI && r->size == sizeof(*r) && !r->status && !r->poisoned && !r->applied_mask
        && (r->flags & KP_PROBE_CHECKED) && !(r->flags & ~(KP_PROBE_CHECKED|KP_PROBE_HAS_LAST))
        && !memcmp(r->challenge,q->challenge,16) && kp_identity_valid(&r->identity)
        && !memcmp(r->identity.build,q->build,32) && r->identity.capabilities == (KP_CAP_INSPECT|KP_CAP_TEST_DATA)
        && r->identity.firmware == fw && r->identity.soc == soc && r->identity.text_base == text
        && r->identity.data_base == data;
}
static inline int kp_s3_query(const struct kp_stage3_provider *p, const unsigned char challenge[16],
        struct kp_probe_request *q, struct kp_probe_reply *r) {
    struct kp_bridge_request envelope = {.abi=KP_ABI,.size=sizeof(envelope)};
    envelope.query = (struct kp_probe_request){.abi=KP_ABI,.size=sizeof(envelope.query),.operation=KP_PROBE_QUERY};
    memcpy(envelope.token,p->token,32); memcpy(envelope.query.build,p->build,32); memcpy(envelope.query.challenge,challenge,16);
    *q = envelope.query;
    int error = p->exchange(p->context,KP_STAGE3_QUERY_SELECTOR,&envelope,sizeof(envelope),r,sizeof(*r));
    kp_bridge_wipe(&envelope,sizeof(envelope));
    return error;
}
/* Separate recovery mode: one fresh query, never dispatches a command. */
static inline enum kp_s3_status kp_s3_inspect(const struct kp_stage3_provider *p,
        uint32_t fw,uint32_t soc,uint64_t text,uint64_t data,const unsigned char challenge[16],
        struct kp_s3_observation *out) {
    if (!out) return KPS3_BAD_REPLY;
    memset(out,0,sizeof(*out)); out->status=KPS3_NO_PROVIDER;
    if (!p || !p->exchange || !kp_nonzero(p->build,32) || !kp_nonzero(p->token,32)) return out->status;
    out->status=KPS3_ENVIRONMENT;
    if ((fw & 0xffff0000u)!=0x13600000u || soc!=0x840fd0u || !kp_kernel(text) || !kp_kernel(data)
            || (text & 4095) || (data & 4095) || data-text!=0xcc0000u) return out->status;
    out->status=KPS3_CHALLENGE;
    if (!challenge || !kp_nonzero(challenge,16)) return out->status;
    out->count=1; out->status=KPS3_TRANSPORT;
    if (kp_s3_query(p,challenge,&out->requests[0],&out->replies[0])) return out->status;
    out->transport_ok[0]=1; out->status=KPS3_REFUSED;
    const struct kp_probe_reply *r=&out->replies[0];
    if (!kp_s3_probe_ok(&out->requests[0],r,fw,soc,text,data)) return out->status;
    out->status=KPS3_BAD_REPLY;
    if (!r->sequence) {
        if (r->flags!=KP_PROBE_CHECKED || kp_nonzero((const unsigned char *)&r->last_request,sizeof(r->last_request))
                || kp_nonzero((const unsigned char *)&r->last_result,sizeof(r->last_result))) return out->status;
        out->status=KPS3_QUERY_CHECKED;
    } else {
        struct kp_request expected; kp_s3_request(&r->identity,&expected);
        if (r->sequence!=1 || r->flags!=(KP_PROBE_CHECKED|KP_PROBE_HAS_LAST)
                || memcmp(&r->last_request,&expected,sizeof(expected))) return out->status;
        out->status=KPS3_CACHED;
    }
    return out->status;
}
/* Exactly two fresh read-only checks, one EXERCISE, one fresh recovery query.
 * No retry, rearm, second mutation or arbitrary address is generated. Existing
 * history stops before writing; a separate query client can recover old history.
 */
static inline enum kp_s3_status kp_s3_exercise(const struct kp_stage3_provider *p,
        uint32_t fw, uint32_t soc, uint64_t text, uint64_t data, const unsigned char challenges[3][16],
        struct kp_s3_observation *out) {
    if (!out) return KPS3_BAD_REPLY;
    memset(out,0,sizeof(*out)); out->status=KPS3_NO_PROVIDER;
    if (!p || !p->exchange || !kp_nonzero(p->build,32) || !kp_nonzero(p->token,32)) return out->status;
    out->status=KPS3_ENVIRONMENT;
    if ((fw & 0xffff0000u) != 0x13600000u || soc != 0x840fd0u || !kp_kernel(text) || !kp_kernel(data)
            || (text & 4095) || (data & 4095) || data-text != 0xcc0000u) return out->status;
    out->status=KPS3_CHALLENGE;
    if (!challenges) return out->status;
    for (unsigned i=0;i<3;++i) {
        if (!kp_nonzero(challenges[i],16)) return out->status;
        for (unsigned j=0;j<i;++j) if (!memcmp(challenges[i],challenges[j],16)) return out->status;
    }
    for (unsigned i=0;i<2;++i) {
        out->count=i+1; out->status=KPS3_TRANSPORT;
        if (kp_s3_query(p,challenges[i],&out->requests[i],&out->replies[i])) return out->status;
        out->transport_ok[i]=1; out->status=KPS3_REFUSED;
        struct kp_probe_reply *r=&out->replies[i];
        if (!kp_s3_probe_ok(&out->requests[i],r,fw,soc,text,data)) return out->status;
        out->status=KPS3_HISTORY;
        if (r->sequence || r->flags != KP_PROBE_CHECKED || kp_nonzero((const unsigned char *)&r->last_request,sizeof(r->last_request))
                || kp_nonzero((const unsigned char *)&r->last_result,sizeof(r->last_result))) return out->status;
    }
    out->status=KPS3_BAD_REPLY;
    if (memcmp(&out->replies[0].identity,&out->replies[1].identity,sizeof(struct kp_identity))) return out->status;
    kp_s3_request(&out->replies[0].identity,&out->command);
    struct kp_stage3_envelope envelope={.abi=KP_ABI,.size=sizeof(envelope),.command=out->command};
    memcpy(envelope.token,p->token,32);
    out->command_attempted=1;
    out->command_transport_ok=!p->exchange(p->context,KP_STAGE3_EXERCISE_SELECTOR,&envelope,sizeof(envelope),&out->result,sizeof(out->result));
    kp_bridge_wipe(&envelope,sizeof(envelope));
    out->count=3; out->status=KPS3_UNVERIFIED;
    if (kp_s3_query(p,challenges[2],&out->requests[2],&out->replies[2])) return out->status;
    out->transport_ok[2]=1;
    const struct kp_probe_reply *r=&out->replies[2];
    if (!kp_s3_probe_ok(&out->requests[2],r,fw,soc,text,data)
            || memcmp(&r->identity,&out->replies[0].identity,sizeof(r->identity)) || r->sequence != 1
            || r->flags != (KP_PROBE_CHECKED|KP_PROBE_HAS_LAST) || memcmp(&r->last_request,&out->command,sizeof(out->command))) return out->status;
    out->status=KPS3_COMMAND_FAILED;
    if (!kp_s3_result_ok(&out->command,&r->last_result,r->identity.resident_base)) return out->status;
    out->status=KPS3_BAD_REPLY;
    if (out->command_transport_ok && memcmp(&out->result,&r->last_result,sizeof(out->result))) return out->status;
    out->status=out->command_transport_ok ? KPS3_RESTORED : KPS3_RECOVERED;
    return out->status;
}
#endif
