/* SPDX-License-Identifier: GPL-3.0-or-later
 * Versioned request/reply ABI. Transport and synchronization belong to a
 * deliberately linked provider; no speculative syscall or kernel mailbox.
 */
#ifndef KO_READINESS_H
#define KO_READINESS_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define KO_READY_ABI 1u
#define KO_CAP_INSPECT UINT64_C(1)
#define KO_CPU_MASK UINT32_C(0xffff)
enum ko_ready_state { KO_INITIALIZING = 1, KO_READY = 2, KO_FAILED = 3 };
enum ko_query_result { KO_QUERY_OK = 0, KO_QUERY_UNAVAILABLE = 1, KO_QUERY_ERROR = -1 };
struct ko_ready_request {
    uint32_t abi_version, record_size;
    uint64_t challenge[2];
    uint64_t text, data;
    uint32_t firmware, soc;
};
struct ko_ready_reply {
    uint32_t abi_version, record_size;
    uint64_t challenge[2], session[2];
    uint64_t generation, capabilities;
    uint64_t text, data, cr3;
    uint32_t firmware, soc, state, active_hooks, expected_cpus, completed_cpus;
    unsigned char build_id[32];
    uint64_t reserved[3];
};
_Static_assert(sizeof(struct ko_ready_request) == 48, "readiness request ABI");
_Static_assert(sizeof(struct ko_ready_reply) == 160, "readiness reply ABI");
typedef enum ko_query_result (*ko_query_fn)(void *, const struct ko_ready_request *, struct ko_ready_reply *);
struct ko_provider {
    ko_query_fn exchange;
    void *ctx;
    /* Pinned producer build SHA-256; not supplied by the reply being checked. */
    unsigned char expected_build_id[32];
};
static inline int ko_nonzero(const void *bytes, size_t length) {
    const unsigned char *p = bytes;
    unsigned char value = 0;
    while (length--) value |= *p++;
    return value != 0;
}
#endif
