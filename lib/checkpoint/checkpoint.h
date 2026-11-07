/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PS5_DURABLE_CHECKPOINT_H
#define PS5_DURABLE_CHECKPOINT_H
#include "../../common/evidence.h"

/* One caller at a time; use your app's mutex or one deliberately chosen thread.
 * Identity/group mask are chosen at runtime. No reconnect or automatic retry.
 */
struct cp_client {
    int fd, error;
    uint32_t timeout_ms;
    uint64_t groups;
    struct pe_record record;
};
/* Initialize via cp_init before any other operation. IPv4 literal, no DNS.
 * Hello and each enabled checkpoint return only after a durable host ACK.
 * Errors are positive errno; a failed client stays failed until explicitly
 * initialized as a NEW session. The caller must stop the suspect operation.
 */
int cp_init(struct cp_client *, const uint64_t session[2],
            const unsigned char build_id[32], uint64_t groups, uint32_t timeout_ms);
int cp_connect(struct cp_client *, const char *ipv4, uint16_t port);
int cp_emit(struct cp_client *, unsigned group, uint32_t thread, uint32_t site,
            uint32_t phase, const uint64_t arguments[4]);
int cp_end(struct cp_client *);
void cp_close(struct cp_client *);
#endif
