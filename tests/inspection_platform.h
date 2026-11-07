/* Host-only sysctl and SDK doubles. Offsets model the SDK kinfo_vmentry ABI;
 * tests also construct records from numeric byte offsets independently. */
#ifndef INSPECTION_TEST_PLATFORM_H
#define INSPECTION_TEST_PLATFORM_H
#include <sys/types.h>
#define CTL_KERN 1
#define KERN_PROC 14
#define KERN_PROC_PROC 8
#define KERN_PROC_PATHNAME 12
#define KERN_PROC_VMMAP 32
#define KVME_PROT_READ 1
#define KVME_PROT_WRITE 2
#define KVME_PROT_EXEC 4
struct kinfo_vmentry {
    int kve_structsize, kve_type;
    uint64_t kve_start, kve_end, kve_offset;
    unsigned char gap[24];
    int kve_protection;
    unsigned char reserved[76];
    char kve_path[1024];
};
int sysctl(const int *, unsigned, void *, size_t *, const void *, size_t);
uint32_t kernel_get_fw_version(void);
int kernel_dynlib_handle(pid_t, const char *, uint32_t *);
intptr_t kernel_dynlib_mapbase_addr(pid_t, uint32_t);
intptr_t kernel_dynlib_entry_addr(pid_t, uint32_t);
#endif
