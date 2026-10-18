/* SPDX-License-Identifier: GPL-3.0-or-later
 * Bounded, read-only offset inspection. No execution-control adapter exists.
 */
#ifndef KERNEL_OFFSET_BACKEND_H
#define KERNEL_OFFSET_BACKEND_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
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
    KO_BAD_TABLE, KO_PAGE_READ_ERROR, KO_SITE_READ_ERROR, KO_MISMATCH
};
struct ko_result {
    uint64_t address;
    unsigned char observed[sizeof(ko_expected)];
    size_t bytes_read;
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
        "page_table_read_error", "site_read_error", "site_signature_mismatch"
    };
    return (unsigned)status < sizeof(names)/sizeof(names[0]) ? names[status] : "invalid_status";
}
/* The caller supplies live SDK bases, never a base copied from an old dump.
 * The page check is a point-in-time observation, not an SMP lock or bypass.
 */
static enum ko_status ko_probe(uint32_t fw, int soc, uint64_t text, uint64_t data,
        ko_read_fn read, void *ctx, struct ko_result *result) {
    memset(result, 0, sizeof(*result));
    if ((fw & 0xffff0000u) != PROFILE_FIRMWARE || soc != PROFILE_SOC)
        return KO_UNSUPPORTED;
    if (!read || !ko_pointer(text) || !ko_pointer(data) || data < text
        || data - text != TEXT_LENGTH || (text & 4095)
        || data > UINT64_MAX - PMAP_OFFSET - 0x30
        || data > UINT64_MAX - CAVE_OFFSET - HOOK_STATE_OFFSET - 8)
        return KO_BAD_BASES;
    result->address = text + KO_TEXT_OFFSET;
    struct ko_reader reader = {read, ctx};
    uint64_t pml4, cr3, cookie, hook;
    if (ko_read64(&reader, data + PMAP_OFFSET + PMAP_PML4_OFFSET, &pml4)
        || ko_read64(&reader, data + PMAP_OFFSET + PMAP_CR3_OFFSET, &cr3))
        return KO_METADATA_ERROR;
    if (!ko_pointer(pml4) || (pml4 & 4095) || !cr3 || (cr3 & 4095)
        || cr3 >= CAP_PHYS_LIMIT || pml4 < cr3)
        return KO_BAD_PMAP;
    uint64_t dmap = pml4 - cr3;
    if (!ko_pointer(dmap) || dmap > UINT64_MAX - CAP_PHYS_LIMIT)
        return KO_BAD_PMAP;
    if (ko_read64(&reader, data + CAVE_OFFSET + COOKIE_OFFSET, &cookie)
        || ko_read64(&reader, data + CAVE_OFFSET + HOOK_STATE_OFFSET, &hook))
        return KO_METADATA_ERROR;
    if (cookie != RESUME_COOKIE || hook != 0) return KO_UNVERIFIED_SESSION;
    enum cap_page_status page = cap_check_page(cr3, dmap, result->address, ko_read64, &reader);
    switch (page) {
    case CAP_MISSING: return KO_MISSING;
    case CAP_PROTECTED: return KO_PROTECTED;
    case CAP_BAD_TABLE: return KO_BAD_TABLE;
    case CAP_READ_ERROR: return KO_PAGE_READ_ERROR;
    case CAP_OK: break;
    }
    /* The fixed seven-byte instruction is wholly inside this audited page. */
    if (read(ctx, result->address, result->observed, sizeof(result->observed))) {
        memset(result->observed, 0, sizeof(result->observed));
        return KO_SITE_READ_ERROR;
    }
    result->bytes_read = sizeof(result->observed);
    return memcmp(result->observed, ko_expected, sizeof(ko_expected)) ? KO_MISMATCH : KO_MATCH;
}
#endif
