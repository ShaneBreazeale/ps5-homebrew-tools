/* SPDX-License-Identifier: GPL-3.0-or-later
 * One sysctl snapshot. No kernel writes, hooks, debug registers, or files.
 * Offsets match the 13.60 kinfo_proc records used by procwatch.
 */
#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PID_OFFSET 72u
#define PPID_OFFSET 76u
#define STAT_OFFSET 388u
#define COMM_OFFSET 447u
#define NTHR_OFFSET 596u
#define PROC_ONLY 8

struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    uint32_t app_type;
    char title_id[10];
    unsigned char spare[236];
};
int sceKernelGetAppInfo(pid_t pid, struct app_info *info);

static uint32_t word32(const unsigned char *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static void safe_string(char *out, size_t out_size,
                        const unsigned char *in, size_t in_size) {
    size_t i = 0;
    while (i < in_size && i + 1 < out_size && in[i]) {
        out[i] = in[i] >= 32 && in[i] < 127 ? (char)in[i] : '?';
        ++i;
    }
    out[i] = 0;
}

int main(void) {
    const char ready[] = "shellshot: ready\n";
    write(STDERR_FILENO, ready, sizeof(ready) - 1);
    setvbuf(stdout, NULL, _IOLBF, 0);

    int mib[3] = { CTL_KERN, KERN_PROC, PROC_ONLY };
    size_t need = 0;
    if (sysctl(mib, 3, NULL, &need, NULL, 0) || !need || need > 4u * 1024u * 1024u) {
        printf("shellshot: size_failed errno=%d need=%zu\n", errno, need);
        return 1;
    }
    size_t cap = need + 65536;
    unsigned char *p = calloc(1, cap);
    if (!p)
        return 1;
    size_t n = cap;
    if (sysctl(mib, 3, p, &n, NULL, 0)) {
        printf("shellshot: query_failed errno=%d\n", errno);
        free(p);
        return 1;
    }

    printf("shellshot: time=%lld bytes=%zu\n", (long long)time(NULL), n);
    size_t at = 0;
    int count = 0;
    while (at + 4 <= n) {
        size_t stride = word32(p + at);
        if (stride < COMM_OFFSET + 20 || stride > n - at) {
            printf("shellshot: layout_invalid at=%zu stride=%zu\n", at, stride);
            free(p);
            return 2;
        }
        uint32_t pid = word32(p + at + PID_OFFSET);
        uint32_t ppid = word32(p + at + PPID_OFFSET);
        uint32_t nthr = word32(p + at + NTHR_OFFSET);
        unsigned stat = p[at + STAT_OFFSET];
        char comm[21];
        safe_string(comm, sizeof(comm), p + at + COMM_OFFSET, 20);
        int interesting = strstr(comm, "Shell") || strstr(comm, "SysCore")
            || strstr(comm, "eboot") || strstr(comm, "NK")
            || strstr(comm, "kstuff") || strstr(comm, "payload");
        if (interesting) {
            struct app_info info;
            memset(&info, 0, sizeof(info));
            int rc = sceKernelGetAppInfo((pid_t)pid, &info);
            char title[11];
            safe_string(title, sizeof(title), (unsigned char *)info.title_id, 10);
            printf("proc pid=%u ppid=%u stat=%u nthr=%u comm=%s app_rc=%d appid=0x%x type=0x%x title=%s\n",
                   pid, ppid, stat, nthr, comm, rc, info.app_id, info.app_type, title);
        }
        at += stride;
        ++count;
    }
    printf("shellshot: complete procs=%d\n", count);
    free(p);
    return 0;
}
