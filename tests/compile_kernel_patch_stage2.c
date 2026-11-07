/* SPDX-License-Identifier: GPL-3.0-or-later
 * SDK compile-only bootstrap fixture. No kernel entry or installation.
 */
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
void *dlsym(void *, const char *);
ssize_t copyout(void *, unsigned long long, size_t);
ssize_t copyin(unsigned long long, const void *, size_t);
#include "kp_stage2/stage2_loader.h"
int kp_s2_fixture_prepare(void) { return kp_s2_prepare(); }
int kp_s2_fixture_cpu(unsigned cpu, uint64_t entry, uint64_t tss) { return kp_s2_cpu_complete(cpu, entry, tss); }
int kp_s2_fixture_publish(uint64_t address, uint64_t data, uint32_t firmware, uint64_t pmap) {
    return kp_s2_publish(address, data, firmware, pmap);
}
