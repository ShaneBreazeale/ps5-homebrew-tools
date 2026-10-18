/* SPDX-License-Identifier: GPL-3.0-or-later
 * Bounded, sysctl-only process/thread capture. No ptrace, signals, kernel
 * memory operations, credentials, hooks, debug registers, or console files.
 * Raw records are retained because Sony's ABI can differ from SDK headers.
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
#define MAX_RECORDS 4096u
#define PREFIX_BYTES 467u
#define COMM_OFFSET 447u /* Used by kstuff main.c find_proc. */
#define PID_OFFSET 72u
#define ALL_THREADS 0
#define PROC_ONLY 8
#define PID_WITH_THREADS 17
#define PATHNAME 12

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

static void raw_record(const char *tag, size_t seq,
                       const unsigned char *p, size_t n) {
    for (size_t at = 0; at < n; at += 64) {
        printf("raw tag=%s seq=%zu offset=%zu hex=", tag, seq, at);
        size_t end = at + 64 < n ? at + 64 : n;
        for (size_t i = at; i < end; ++i)
            printf("%02x", p[i]);
        putchar('\n');
    }
}

/* Query returns a private user buffer. Retry only ENOMEM caused by growth
 * between the size query and copy; this never retries a payload send. */
static unsigned char *query(int kind, int pid, size_t *bytes) {
    int mib[4] = { CTL_KERN, KERN_PROC, kind, pid };
    unsigned mib_len = kind == ALL_THREADS || kind == PROC_ONLY ? 3 : 4;
    for (int attempt = 0; attempt < 3; ++attempt) {
        size_t need = 0;
        errno = 0;
        if (sysctl(mib, mib_len, NULL, &need, NULL, 0)) {
            printf("query kind=%d pid=%d sizing_failed errno=%d\n", kind, pid, errno);
            return NULL;
        }
        if (!need || need > MAX_BYTES - 65536) {
            printf("query kind=%d pid=%d invalid_size=%zu\n", kind, pid, need);
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
        int rc = sysctl(mib, mib_len, p, bytes, NULL, 0);
        int error = errno;
        printf("query kind=%d pid=%d rc=%d errno=%d bytes=%zu\n",
               kind, pid, rc, error, *bytes);
        if (!rc && *bytes <= cap)
            return p;
        free(p);
        if (error != ENOMEM)
            return NULL;
    }
    return NULL;
}

static int print_records(const char *tag, const unsigned char *p, size_t n,
                          int raw_all, int *pids, size_t *pid_count) {
    size_t at = 0, seq = 0;
    while (at < n && seq < MAX_RECORDS) {
        if (n - at < 4)
            break;
        size_t stride = word32(p + at);
        if (stride < PREFIX_BYTES || stride > 4096 || stride > n - at) {
            printf("layout_invalid tag=%s offset=%zu stride=%zu remaining=%zu\n",
                   tag, at, stride, n - at);
            raw_record(tag, seq, p + at, n - at < 4096 ? n - at : 4096);
            return -1;
        }
        uint32_t pid = word32(p + at + PID_OFFSET);
        char comm[21];
        safe_string(comm, sizeof(comm), p + at + COMM_OFFSET, 20);
        printf("record tag=%s seq=%zu stride=%zu pid_hint=%u comm_hint=%s\n",
               tag, seq, stride, pid, comm);
        /* These are ABI hints only. Preserve every returned byte so offsets
         * can be checked offline before decoding wait state and thread IDs. */
        if (raw_all)
            raw_record(tag, seq, p + at, stride);
        if (pids && pid_count && *pid_count < 256 && pid > 0 && pid < 1000000) {
            int seen = 0;
            for (size_t i = 0; i < *pid_count; ++i)
                if (pids[i] == (int)pid)
                    seen = 1;
            if (!seen)
                pids[(*pid_count)++] = (int)pid;
        }
        at += stride;
        ++seq;
    }
    printf("records_end tag=%s count=%zu consumed=%zu total=%zu\n", tag, seq, at, n);
    return at == n ? 0 : -1;
}

int main(void) {
    const char ready[] = "thread-probe: ready (sysctl only)\n";
    write(STDERR_FILENO, ready, sizeof(ready) - 1);
    setvbuf(stdout, NULL, _IOLBF, 0);
    pid_t self = getpid();
    printf("thread-probe: self_pid=%d\n", self);
    size_t n = 0;
    unsigned char *p = query(KERN_PROC_PID, self, &n);
    if (!p)
        return 1;
    int layout_ok = n >= PREFIX_BYTES && word32(p) == n
                    && word32(p + PID_OFFSET) == (uint32_t)self
                    && memchr(p + COMM_OFFSET, 0, 20) != NULL;
    printf("prefix_validation self_pid_match=%d returned_size=%zu\n", layout_ok, n);
    raw_record("self", 0, p, n);
    free(p);
    if (!layout_ok) {
        puts("thread-probe: refusing record interpretation after self mismatch");
        return 2;
    }
    for (int pass = 0; pass < 3; ++pass) {
        int pids[256];
        size_t pid_count = 0;
        printf("snapshot pass=%d time=%lld\n", pass, (long long)time(NULL));
        p = query(ALL_THREADS, 0, &n);
        if (p) {
            char tag[32];
            snprintf(tag, sizeof(tag), "all-%d", pass);
            int rc = print_records(tag, p, n, 1, pids, &pid_count);
            free(p);
            if (rc)
                return 3;
        } else {
            /* Some firmware restricts KERN_PROC_ALL. Process-only discovery
             * followed by per-PID thread queries uses the same sysctl API. */
            p = query(PROC_ONLY, 0, &n);
            if (!p)
                return 4;
            int rc = print_records("procs", p, n, 0, pids, &pid_count);
            free(p);
            if (rc)
                return 5;
            for (size_t i = 0; i < pid_count; ++i) {
                char tag[48];
                snprintf(tag, sizeof(tag), "pid-%d-%d", pids[i], pass);
                p = query(PID_WITH_THREADS, pids[i], &n);
                if (p) {
                    rc = print_records(tag, p, n, 1, NULL, NULL);
                    free(p);
                    if (rc)
                        return 6;
                }
            }
        }
        if (pass == 0) {
            for (size_t i = 0; i < pid_count; ++i) {
                char path[1024] = {0};
                size_t path_len = sizeof(path);
                int mib[4] = { CTL_KERN, KERN_PROC, PATHNAME, pids[i] };
                errno = 0;
                int rc = sysctl(mib, 4, path, &path_len, NULL, 0);
                path[sizeof(path) - 1] = 0;
                char clean[1024];
                safe_string(clean, sizeof(clean), (unsigned char *)path, sizeof(path));
                printf("path pid=%d rc=%d errno=%d bytes=%zu value=%s\n",
                       pids[i], rc, errno, path_len, clean);
            }
        }
        fflush(stdout);
        if (pass < 2) {
            const struct timespec delay = {1, 0};
            nanosleep(&delay, NULL);
        }
    }
    puts("thread-probe: complete");
    return 0;
}
