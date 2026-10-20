/* SPDX-License-Identifier: GPL-3.0-or-later
 * Bounded, read-only offset inspection. No execution-control adapter exists.
 */
#ifndef KERNEL_OFFSET_BACKEND_H
#define KERNEL_OFFSET_BACKEND_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "readiness.h"
#include "../kernel-capture/paging.h"
#include "../kernel-capture/profile_13_60_pro.h"
#define KO_PROFILE "retail-13.60-pro-exec-join-v1"
#define KO_TEXT_OFFSET UINT64_C(0x38fc12)
#define KO_EXEC_ANCHOR UINT64_C(0x2c0000)
#define KO_SHORT_OFFSET UINT64_C(0xcfc12)
#define KO_DUMP_SHA256 "20da45a0910c990153fbfb7c94e16356867e0bd84f7c9fbf754a45a5dd129673"
static const unsigned char ko_expected[] = {0x4c,0x8d,0x2d,0xf7,0xc6,0x58,0x03};
typedef int (*ko_read_fn)(void *, uint64_t, void *, size_t);
enum ko_status {
    KO_MATCH, KO_UNSUPPORTED, KO_BAD_BASES, KO_METADATA_ERROR,
    KO_BAD_PMAP, KO_UNVERIFIED_SESSION, KO_MISSING, KO_PROTECTED,
    KO_BAD_TABLE, KO_PAGE_READ_ERROR, KO_SITE_READ_ERROR, KO_MISMATCH,
    KO_NO_PROVIDER, KO_READINESS_ERROR, KO_BAD_READINESS, KO_NOT_READY,
    KO_STALE_READINESS, KO_READINESS_CHANGED, KO_NONCE_ERROR
};
enum ko_ready_source { KO_SOURCE_NONE, KO_SOURCE_HANDSHAKE, KO_SOURCE_LEGACY };
#define KO_LEGACY_PROFILE "resume-13.60-pro-v1"
struct ko_policy {
    const struct ko_provider *provider;
    uint64_t challenge[2];
    /* Explicit selection of the known historical resume profile, not detection
     * of resident identity from a cookie. Values other than 0/1 are invalid. */
    int allow_legacy;
};
struct ko_result {
    uint64_t address;
    unsigned char observed[sizeof(ko_expected)];
    size_t bytes_read;
    enum ko_ready_source source;
    struct ko_ready_reply readiness;
    uint64_t first_challenge[2], final_challenge[2];
};
struct ko_reader { ko_read_fn read; void *ctx; };
static int ko_read64(void *opaque, uint64_t address, uint64_t *out) {
    struct ko_reader *reader = opaque;
    *out = 0;
    return reader->read(reader->ctx, address, out, sizeof(*out));
}
static int ko_pointer(uint64_t address) {
    return (address >> 47) == UINT64_C(0x1ffff);
}
static const char *ko_status_name(enum ko_status status) {
    static const char *names[] = {
        "site_signature_match", "unsupported_firmware_model", "invalid_bases",
        "metadata_read_error", "invalid_pmap", "unverified_resume_state",
        "page_missing", "page_protected", "invalid_page_table",
        "page_table_read_error", "site_read_error", "site_signature_mismatch",
        "readiness_provider_unavailable", "readiness_query_error", "invalid_readiness",
        "readiness_not_ready", "stale_readiness_reply", "readiness_changed", "challenge_unavailable"
    };
    return (unsigned)status < sizeof(names)/sizeof(names[0]) ? names[status] : "invalid_status";
}
static const char *ko_source_name(enum ko_ready_source source) {
    return source == KO_SOURCE_HANDSHAKE ? "versioned_handshake" :
           source == KO_SOURCE_LEGACY ? "legacy_cookie" : "none";
}
static enum ko_status ko_validate_ready(const struct ko_ready_reply *r,
        const struct ko_ready_request *request, const struct ko_provider *provider, uint64_t cr3) {
    if (r->abi_version != KO_READY_ABI || r->record_size != sizeof(*r)
        || !ko_nonzero(provider->expected_build_id, sizeof(provider->expected_build_id))
        || memcmp(r->build_id, provider->expected_build_id, sizeof(r->build_id))
        || !ko_nonzero(r->session, sizeof(r->session)) || !r->generation
        || r->text != request->text || r->data != request->data || r->cr3 != cr3
        || r->firmware != request->firmware || r->soc != request->soc
        || ko_nonzero(r->reserved, sizeof(r->reserved))) return KO_BAD_READINESS;
    if (memcmp(r->challenge, request->challenge, sizeof(r->challenge))) return KO_STALE_READINESS;
    if (r->state != KO_READY || r->capabilities != KO_CAP_INSPECT || r->active_hooks
        || !r->expected_cpus || (r->expected_cpus & ~KO_CPU_MASK)
        || r->completed_cpus != r->expected_cpus) return KO_NOT_READY;
    return KO_MATCH;
}
static enum ko_status ko_audit(uint64_t cr3, uint64_t dmap, uint64_t address, struct ko_reader *reader) {
    switch (cap_check_page(cr3, dmap, address, ko_read64, reader)) {
    case CAP_MISSING: return KO_MISSING;
    case CAP_PROTECTED: return KO_PROTECTED;
    case CAP_BAD_TABLE: return KO_BAD_TABLE;
    case CAP_READ_ERROR: return KO_PAGE_READ_ERROR;
    case CAP_OK: return KO_MATCH;
    }
    return KO_BAD_TABLE;
}
static enum ko_status ko_legacy_ready(struct ko_reader *reader, uint64_t data) {
    uint64_t cookie, hook;
    if (ko_read64(reader, data + CAVE_OFFSET + COOKIE_OFFSET, &cookie)
        || ko_read64(reader, data + CAVE_OFFSET + HOOK_STATE_OFFSET, &hook)) return KO_METADATA_ERROR;
    return cookie == RESUME_COOKIE && hook == 0 ? KO_MATCH : KO_UNVERIFIED_SESSION;
}
/* The caller supplies live SDK bases and a deliberately linked provider. Each
 * exchange must return one synchronized snapshot, not a raw/torn memory copy.
 * No fallback is allowed after an available provider returns a bad record.
 */
static enum ko_status ko_probe(uint32_t fw, int soc, uint64_t text, uint64_t data,
        ko_read_fn read, void *ctx, const struct ko_policy *policy, struct ko_result *result) {
    memset(result, 0, sizeof(*result));
    if ((fw & 0xffff0000u) != PROFILE_FIRMWARE || soc != PROFILE_SOC) return KO_UNSUPPORTED;
    if (!read || !policy || (policy->allow_legacy != 0 && policy->allow_legacy != 1)
        || !ko_pointer(text) || !ko_pointer(data) || data < text
        || data - text != TEXT_LENGTH || (text & 4095)
        || data > UINT64_MAX - PMAP_OFFSET - 0x30
        || data > UINT64_MAX - CAVE_OFFSET - HOOK_STATE_OFFSET - 8) return KO_BAD_BASES;
    result->address = text + KO_TEXT_OFFSET;
    struct ko_reader reader = {read, ctx};
    uint64_t pml4, cr3;
    if (ko_read64(&reader, data + PMAP_OFFSET + PMAP_PML4_OFFSET, &pml4)
        || ko_read64(&reader, data + PMAP_OFFSET + PMAP_CR3_OFFSET, &cr3)) return KO_METADATA_ERROR;
    if (!ko_pointer(pml4) || (pml4 & 4095) || !cr3 || (cr3 & 4095)
        || cr3 >= CAP_PHYS_LIMIT || pml4 < cr3) return KO_BAD_PMAP;
    uint64_t dmap = pml4 - cr3;
    if (!ko_pointer(dmap) || dmap > UINT64_MAX - CAP_PHYS_LIMIT) return KO_BAD_PMAP;
    const struct ko_provider *provider = policy->provider;
    struct ko_ready_request request = {KO_READY_ABI, sizeof(request), {0, 0}, text, data, fw, (uint32_t)soc};
    struct ko_ready_reply first = {0};
    enum ko_query_result query = KO_QUERY_UNAVAILABLE;
    if (provider) {
        if (!provider->exchange) return KO_READINESS_ERROR;
        if (!ko_nonzero(policy->challenge, sizeof(policy->challenge))) return KO_NONCE_ERROR;
        memcpy(request.challenge, policy->challenge, sizeof(request.challenge));
        query = provider->exchange(provider->ctx, &request, &first);
    }
    enum ko_status status;
    if (query == KO_QUERY_OK) {
        result->source = KO_SOURCE_HANDSHAKE;
        status = ko_validate_ready(&first, &request, provider, cr3);
        if (status != KO_MATCH) return status;
        result->readiness = first;
        memcpy(result->first_challenge, request.challenge, sizeof(request.challenge));
    } else if (query == KO_QUERY_UNAVAILABLE) {
        if (!policy->allow_legacy) return KO_NO_PROVIDER;
        result->source = KO_SOURCE_LEGACY;
        status = ko_legacy_ready(&reader, data);
        if (status != KO_MATCH) return status;
    } else return KO_READINESS_ERROR;
    status = ko_audit(cr3, dmap, result->address, &reader);
    if (status != KO_MATCH) return status;
    /* The fixed seven-byte instruction is wholly inside this audited page. */
    if (read(ctx, result->address, result->observed, sizeof(result->observed))) {
        memset(result->observed, 0, sizeof(result->observed));
        return KO_SITE_READ_ERROR;
    }
    /* Recheck layout, mappings and readiness after the bounded observation. */
    uint64_t after_pml4, after_cr3;
    if (ko_read64(&reader, data + PMAP_OFFSET + PMAP_PML4_OFFSET, &after_pml4)
        || ko_read64(&reader, data + PMAP_OFFSET + PMAP_CR3_OFFSET, &after_cr3)) status = KO_METADATA_ERROR;
    else if (after_pml4 != pml4 || after_cr3 != cr3) status = KO_READINESS_CHANGED;
    else status = ko_audit(cr3, dmap, result->address, &reader);
    if (status == KO_MATCH && result->source == KO_SOURCE_HANDSHAKE) {
        struct ko_ready_reply final = {0};
        /* A distinct second challenge prevents replaying the first reply.
         * Nonces establish freshness to a trusted provider, not authentication. */
        request.challenge[0] ^= UINT64_MAX;
        if (!ko_nonzero(request.challenge, sizeof(request.challenge))) request.challenge[1] = 1;
        query = provider->exchange(provider->ctx, &request, &final);
        if (query != KO_QUERY_OK) status = KO_READINESS_CHANGED;
        else status = ko_validate_ready(&final, &request, provider, cr3);
        if (status == KO_MATCH) {
            memcpy(result->final_challenge, request.challenge, sizeof(request.challenge));
            memcpy(final.challenge, first.challenge, sizeof(final.challenge));
            if (memcmp(&first, &final, sizeof(first))) status = KO_READINESS_CHANGED;
        }
    } else if (status == KO_MATCH) {
        /* A previously absent interface appearing/changing during a legacy
         * observation is not permission to finish under weaker evidence. */
        if (provider) {
            struct ko_ready_reply unused = {0};
            request.challenge[0] ^= UINT64_MAX;
            if (!ko_nonzero(request.challenge, sizeof(request.challenge))) request.challenge[1] = 1;
            if (provider->exchange(provider->ctx, &request, &unused) != KO_QUERY_UNAVAILABLE)
                status = KO_READINESS_CHANGED;
        }
        if (status == KO_MATCH) status = ko_legacy_ready(&reader, data);
    }
    if (status != KO_MATCH) {
        memset(result->observed, 0, sizeof(result->observed));
        return status;
    }
    result->bytes_read = sizeof(result->observed);
    return memcmp(result->observed, ko_expected, sizeof(ko_expected)) ? KO_MISMATCH : KO_MATCH;
}
#endif
