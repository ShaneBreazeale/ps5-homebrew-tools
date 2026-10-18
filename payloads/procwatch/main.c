/* SPDX-License-Identifier: GPL-3.0-or-later
 * Sysctl-only process birth/death log for one launch window.
 * No ptrace, signals, kernel reads or writes, credential changes, hooks,
 * debug registers, or console files.
 *
 * Offsets are the ones checked against the 13.60 kinfo_proc records:
 * pid 72, ppid 76, slptime 316, start 336, stat 388, comm 447, nthreads 596.
 * xstat 304 sits in that same checked span.
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

#define MAX_BYTES (4u * 1024u * 1024u)
#define MAX_PROCS 256
#define PID_OFFSET 72u
#define PPID_OFFSET 76u
#define XSTAT_OFFSET 304u
#define SLPTIME_OFFSET 316u
#define START_OFFSET 336u
#define STAT_OFFSET 388u
#define COMM_OFFSET 447u
#define NTHR_OFFSET 596u
#define PROC_ONLY 8
#define WATCH_SECONDS 180
#define POLL_MS 50

struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    uint32_t app_type;
    char title_id[10];
    unsigned char spare[236];
};
int sceKernelGetAppInfo(pid_t pid, struct app_info *info);

struct ent {
    uint32_t pid;
    uint32_t ppid;
    uint32_t start;
    uint32_t slptime;
    uint32_t nthr;
    uint16_t xstat;
    uint8_t stat;
    char comm[21];
};

static uint32_t word32(const unsigned char *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint16_t word16(const unsigned char *p) {
    uint16_t v;
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

static unsigned char *query_procs(size_t *bytes) {
    int mib[3] = { CTL_KERN, KERN_PROC, PROC_ONLY };
    for (int attempt = 0; attempt < 3; ++attempt) {
        size_t need = 0;
        errno = 0;
        if (sysctl(mib, 3, NULL, &need, NULL, 0)) {
            printf("query sizing_failed errno=%d\n", errno);
            return NULL;
        }
        if (!need || need > MAX_BYTES - 65536) {
            printf("query invalid_size=%zu\n", need);
            return NULL;
        }
        size_t cap = need + 65536;
        unsigned char *p = calloc(1, cap);
        if (!p) {
            puts("allocation_failed");
            return NULL;
        }
        *bytes = cap;
        errno = 0;
        int rc = sysctl(mib, 3, p, bytes, NULL, 0);
        int error = errno;
        if (!rc && *bytes <= cap)
            return p;
        free(p);
        if (error != ENOMEM) {
            printf("query failed rc=%d errno=%d\n", rc, error);
            return NULL;
        }
    }
    puts("query retries_exhausted");
    return NULL;
}

static int parse_procs(const unsigned char *p, size_t n, struct ent *out, int *count) {
    size_t at = 0;
    int nent = 0;
    while (at < n) {
        if (n - at < 4)
            return -1;
        size_t stride = word32(p + at);
        if (stride < COMM_OFFSET + 20 || stride > 4096 || stride > n - at)
            return -1;
        if (nent == MAX_PROCS) {
            puts("procwatch: too_many");
            return -1;
        }
        struct ent *e = &out[nent++];
        memset(e, 0, sizeof(*e));
        e->pid = word32(p + at + PID_OFFSET);
        e->ppid = word32(p + at + PPID_OFFSET);
        e->xstat = word16(p + at + XSTAT_OFFSET);
        e->slptime = word32(p + at + SLPTIME_OFFSET);
        e->start = word32(p + at + START_OFFSET);
        e->stat = p[at + STAT_OFFSET];
        e->nthr = word32(p + at + NTHR_OFFSET);
        safe_string(e->comm, sizeof(e->comm), p + at + COMM_OFFSET, 20);
        at += stride;
    }
    *count = nent;
    return 0;
}

static int find_pid(const struct ent *t, int n, uint32_t pid) {
    for (int i = 0; i < n; ++i)
        if (t[i].pid == pid)
            return i;
    return -1;
}

static void print_app(uint32_t pid) {
    struct app_info info;
    memset(&info, 0, sizeof(info));
    int rc = sceKernelGetAppInfo((pid_t)pid, &info);
    char title[11];
    safe_string(title, sizeof(title), (unsigned char *)info.title_id, 10);
    printf("app pid=%u rc=%d appid=0x%x type=0x%x title=%s\n",
           pid, rc, info.app_id, info.app_type, title);
}

static void print_ent(const char *kind, long long now, const struct ent *e) {
    printf("%s time=%lld pid=%u ppid=%u start=%u stat=%u xstat=%u slptime=%u nthr=%u comm=%s\n",
           kind, now, e->pid, e->ppid, e->start, e->stat, e->xstat, e->slptime, e->nthr, e->comm);
}

int main(void) {
    const char ready[] = "procwatch: ready (sysctl only)\n";
    write(STDERR_FILENO, ready, sizeof(ready) - 1);
    setvbuf(stdout, NULL, _IOLBF, 0);

    pid_t self = getpid();
    size_t n = 0;
    unsigned char *p = query_procs(&n);
    if (!p)
        return 1;
    struct ent cur[MAX_PROCS];
    struct ent prev[MAX_PROCS];
    int ncur = 0;
    if (parse_procs(p, n, cur, &ncur)) {
        free(p);
        puts("procwatch: layout_invalid");
        return 2;
    }
    free(p);
    if (find_pid(cur, ncur, (uint32_t)self) < 0) {
        printf("procwatch: self_missing pid=%d count=%d\n", self, ncur);
        return 2;
    }

    long long t0 = (long long)time(NULL);
    printf("baseline time=%lld count=%d self=%d\n", t0, ncur, self);
    for (int i = 0; i < ncur; ++i)
        print_ent("base", t0, &cur[i]);
    memcpy(prev, cur, (size_t)ncur * sizeof(prev[0]));
    int nprev = ncur;
    int births = 0;
    int deaths = 0;
    int ticks = 0;

    while ((long long)time(NULL) - t0 < WATCH_SECONDS) {
        struct timespec delay = {0, POLL_MS * 1000000L};
        nanosleep(&delay, NULL);
        p = query_procs(&n);
        if (!p)
            return 3;
        if (parse_procs(p, n, cur, &ncur)) {
            free(p);
            puts("procwatch: layout_invalid");
            return 2;
        }
        free(p);
        long long now = (long long)time(NULL);
        for (int i = 0; i < ncur; ++i) {
            int old = find_pid(prev, nprev, cur[i].pid);
            if (old < 0) {
                print_ent("birth", now, &cur[i]);
                print_app(cur[i].pid);
                ++births;
            } else if (cur[i].stat == 5 && prev[old].stat != 5) {
                print_ent("zombie", now, &cur[i]);
            }
        }
        for (int i = 0; i < nprev; ++i) {
            if (find_pid(cur, ncur, prev[i].pid) < 0) {
                print_ent("death", now, &prev[i]);
                ++deaths;
            }
        }
        ++ticks;
        if (ticks % (1000 / POLL_MS) == 0) {
            printf("tick time=%lld procs=%d births=%d deaths=%d\n",
                   now, ncur, births, deaths);
        }
        memcpy(prev, cur, (size_t)ncur * sizeof(prev[0]));
        nprev = ncur;
    }
    printf("procwatch: complete births=%d deaths=%d\n", births, deaths);
    return 0;
}
