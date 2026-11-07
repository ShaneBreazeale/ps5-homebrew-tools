/* SPDX-License-Identifier: GPL-3.0-or-later
 * Publish the owned cell only in the newly allocated shared area. Stage 2's
 * credential/gate publication is last, after all stage 3 bytes read back.
 */
#ifndef KP_STAGE3_LOADER_H
#define KP_STAGE3_LOADER_H
#include "stage3.h"
#include "stage2_loader.h"
static int kp_s3_publish(uint64_t address, uint64_t data, uint32_t firmware, uint64_t pmap) {
    struct kp_stage3_store state = {.abi=KP_ABI,.size=sizeof(state),.value=KP_STAGE3_BEFORE};
    unsigned char check[256];
    struct kp_stage2_store publication;
    uint64_t target = address + sizeof(struct kp_stage2_store);
    if ((address & 7) || !kp_kernel(address) || address > UINT64_MAX - sizeof(state) - sizeof(struct kp_stage2_store)) return -1;
    if (kp_s2_loader_read(NULL,address,&publication,sizeof(publication))
            || kp_nonzero((const unsigned char *)&publication,sizeof(publication))) return -1;
    for (size_t off = 0; off < sizeof(state); off += sizeof(check)) {
        size_t n = sizeof(state)-off < sizeof(check) ? sizeof(state)-off : sizeof(check);
        if (kp_s2_loader_read(NULL,target+off,check,n) || kp_nonzero(check,n)) return -1;
    }
    for (size_t off = 0; off < sizeof(state); off += sizeof(check)) {
        size_t n = sizeof(state)-off < sizeof(check) ? sizeof(state)-off : sizeof(check);
        const unsigned char *bytes = (const unsigned char *)&state + off;
        if (copyin(target+off,bytes,n) != (ssize_t)n || kp_s2_loader_read(NULL,target+off,check,n)
                || memcmp(bytes,check,n)) return -1;
    }
    return kp_s2_publish(address,data,firmware,pmap);
}
#endif
