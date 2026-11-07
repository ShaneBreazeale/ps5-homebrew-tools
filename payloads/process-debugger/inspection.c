/* SPDX-License-Identifier: GPL-3.0-or-later
 * Read-only process discovery. No attach, target calls, kernel writes or fallback
 * to a guessed kernel layout. Missing selectors and incompatible records fail.
 */
#include "inspection.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifndef PROCESS_INSPECTION_TEST
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <ps5/kernel.h>
#else
#include "inspection_platform.h"
#endif
#define MAX_QUERY_BYTES (4u * 1024u * 1024u)
#define MAX_PROCESS_RECORDS 4096
#define PROCESS_RECORD_SIZE 1096u
struct process_app_info {
    uint32_t app_id;
    uint64_t unknown;
    uint32_t app_type;
    char title_id[10];
    unsigned char spare[236];
};
int sceKernelGetAppInfo(pid_t, struct process_app_info *);
/* Sony's process records differ from the SDK's kinfo_proc. This is the same
 * checked 13.60 layout as process-watch; never cast records to kinfo_proc. */
static uint32_t word32(const unsigned char *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint64_t word64(const unsigned char *p) { uint64_t v; memcpy(&v,p,8); return v; }
static int query(int selector, uint64_t pid, unsigned char **out, size_t *length)
{
    int mib[4] = {CTL_KERN, KERN_PROC, selector, (int)pid};
    unsigned mib_length = selector == KERN_PROC_PROC ? 3 : 4;
    *out = NULL; *length = 0;
    for(int attempt = 0; attempt < 3; attempt++) {
        size_t size = 0;
        if(sysctl(mib, mib_length, NULL, &size, NULL, 0)) return -(errno ? errno : EIO);
        if(!size || size > MAX_QUERY_BYTES) return -E2BIG;
        size_t capacity = size <= MAX_QUERY_BYTES-65536 ? size+65536 : MAX_QUERY_BYTES;
        unsigned char *data = calloc(1, capacity);
        if(!data) return -ENOMEM;
        size = capacity;
        int r = sysctl(mib, mib_length, data, &size, NULL, 0), error = errno;
        if(!r && size <= capacity) { *out = data; *length = size; return 0; }
        free(data);
        if(!r) return -EOVERFLOW;
        if(error != ENOMEM) return -(error ? error : EIO);
    }
    return -EAGAIN;
}
int process_describe(uint64_t pid, struct target_process_info *out)
{
    if(!out || !pid || pid > INT_MAX) return -EINVAL;
    memset(out, 0, sizeof(*out));
    if((kernel_get_fw_version() & 0xffff0000u) != 0x13600000u) return -ENOTSUP;
    unsigned char *data; size_t size;
    int r = query(KERN_PROC_PROC, 0, &data, &size);
    if(r < 0) return r;
    struct target_process_info info = {0};
    size_t at = 0; int records = 0, found = 0;
    while(at < size) {
        if(size-at < 4 || ++records > MAX_PROCESS_RECORDS) { r = -EPROTO; break; }
        size_t stride = word32(data+at);
        if(stride != PROCESS_RECORD_SIZE || stride > size-at) { r = -EPROTO; break; }
        const unsigned char *record = data+at;
        if(word32(record+72) == pid) {
            if(found++) { r = -EPROTO; break; }
            info.pid = pid; info.parent_pid = word32(record+76);
            info.start_seconds = word64(record+336);
            uint64_t microseconds = word64(record+344);
            if(microseconds >= 1000000 || !info.start_seconds || !memchr(record+447, 0, 20)) {
                r = -EPROTO; break;
            }
            info.start_microseconds = (uint32_t)microseconds;
            memcpy(info.name, record+447, 20);
            info.fields = TARGET_INFO_PROCESS;
        }
        at += stride;
    }
    free(data);
    if(r < 0) return r;
    if(!found) return -ESRCH;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, (int)pid};
    size = sizeof(info.path);
    if(!sysctl(mib, 4, info.path, &size, NULL, 0) && size && size <= sizeof(info.path) &&
        memchr(info.path, 0, size) && info.path[0]) info.fields |= TARGET_INFO_PATH;
    else memset(info.path, 0, sizeof(info.path));
    struct process_app_info app = {0};
    if(!sceKernelGetAppInfo((pid_t)pid, &app)) {
        info.app_id = app.app_id; info.app_type = app.app_type;
        memcpy(info.title_id, app.title_id, 10);
        info.fields |= TARGET_INFO_APP;
    }
    *out = info;
    return 0;
}
int process_maps(uint64_t pid, struct target_map *out, size_t capacity, size_t *count)
{
    if(!count || (!out && capacity) || !pid || pid > INT_MAX) return -EINVAL;
    *count = 0;
    /* KERN_PROC_VMMAP uses the SDK's variable-length FreeBSD record format.
     * Some Sony kernels omit this selector; propagate that error without a
     * kernel-memory walker. Only the researched firmware is enabled initially. */
    if((kernel_get_fw_version() & 0xffff0000u) != 0x13600000u) return -ENOTSUP;
    unsigned char *data; size_t size;
    int r = query(KERN_PROC_VMMAP, pid, &data, &size);
    if(r < 0) return r;
    size_t at = 0, n = 0;
    uint64_t previous_end = 0;
    while(at < size) {
        const size_t path_offset = offsetof(struct kinfo_vmentry, kve_path);
        if(size-at < path_offset+1 || n == TARGET_MAX_MAPS) { r = -EPROTO; break; }
        struct kinfo_vmentry native = {0};
        size_t stride = word32(data+at);
        if(stride < path_offset+1 || stride > sizeof(native) || stride > size-at) { r = -EPROTO; break; }
        memcpy(&native, data+at, stride);
        if(!memchr(data+at+path_offset, 0, stride-path_offset) ||
            native.kve_start >= native.kve_end || native.kve_end > (1ull<<47) ||
            native.kve_start < previous_end || (native.kve_protection & ~7)) { r = -EPROTO; break; }
        previous_end = native.kve_end;
        if(n < capacity) {
            struct target_map *map = out+n;
            memset(map, 0, sizeof(*map));
            map->start = native.kve_start; map->end = native.kve_end; map->offset = native.kve_offset;
            if(native.kve_protection & KVME_PROT_READ) map->permissions |= TARGET_MAP_READ;
            if(native.kve_protection & KVME_PROT_WRITE) map->permissions |= TARGET_MAP_WRITE;
            if(native.kve_protection & KVME_PROT_EXEC) map->permissions |= TARGET_MAP_EXECUTE;
            size_t length = strlen(native.kve_path);
            map->name_truncated = length >= sizeof(map->name);
            if(map->name_truncated) length = sizeof(map->name)-1;
            memcpy(map->name, native.kve_path, length);
        }
        n++; at += stride;
    }
    free(data);
    if(r < 0) return r;
    if(n > capacity) return -ENOSPC;
    *count = n;
    return 0;
}
int process_module(uint64_t pid, const char *basename, struct target_module *out)
{
    if(!out || !pid || pid > INT_MAX || !basename || !*basename ||
        strnlen(basename, 256) == 256 || strchr(basename, '/')) return -EINVAL;
    memset(out, 0, sizeof(*out));
    uint32_t handle;
    errno = 0;
    if(kernel_dynlib_handle((pid_t)pid, basename, &handle)) return -(errno ? errno : EIO);
    errno = 0;
    uint64_t base = (uint64_t)kernel_dynlib_mapbase_addr((pid_t)pid, handle);
    if(!base) return -(errno ? errno : EIO);
    if(base >= (1ull<<47)) return -EIO;
    errno = 0;
    uint64_t entry = (uint64_t)kernel_dynlib_entry_addr((pid_t)pid, handle);
    if(!entry && errno) return -errno;
    if(entry >= (1ull<<47)) return -EIO;
    *out = (struct target_module){base, entry, handle};
    return 0;
}
