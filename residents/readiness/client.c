/* SPDX-License-Identifier: GPL-3.0-or-later
 * Deliberately linked SDK client for the matching resident overlay only.
 */
#include "readiness.h"
#include "ko_transport.h"
#include "ko_build_id.h"
static enum ko_query_result exchange(void *ctx, const struct ko_ready_request *request,
        struct ko_ready_reply *reply) {
    (void)ctx;
    if (!request || !reply || request->abi_version != KO_READY_ABI
        || request->record_size != sizeof(*request)) return KO_QUERY_ERROR;
    memset(reply, 0, sizeof(*reply));
    struct ko_call_result result = ko_kstuff_call((uint64_t)(uintptr_t)request, sizeof(*request),
            (uint64_t)(uintptr_t)reply, 0, sizeof(*reply), 0, KO_KEK_COMMAND);
    /* An old resident can fall through to ordinary getppid and return a PID.
     * Neither that value, nor ENOSYS/other errno, proves interface absence. */
    if (result.failed || result.value != 0) return KO_QUERY_ERROR;
    return KO_QUERY_OK;
}
const struct ko_provider ko_readiness_provider = {exchange, NULL, KO_BUILD_ID_BYTES};
