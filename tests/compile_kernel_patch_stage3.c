/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
void *dlsym(void *, const char *);
ssize_t copyout(void *, uint64_t, size_t);
ssize_t copyin(uint64_t, const void *, size_t);
#include "kp_stage2/stage3_loader.h"
int compile_stage3(uint64_t address,uint64_t data,uint32_t fw,uint64_t pmap) {
    (void)kp_s2_cpu_complete;
    return kp_s2_prepare() || kp_s3_publish(address,data,fw,pmap);
}
