/* SPDX-License-Identifier: GPL-3.0-or-later
 * Bounded process/thread capture. No ptrace, signals, kernel writes,
 * credential changes, hooks, debug registers, or console files.
 * Raw records are retained because Sony's ABI can differ from SDK headers.
 */
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <ps5/kernel.h>
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
#define PATHNAME 12

/* Same app-info layout as the SDK's samples/ps/main.c. Oversize the
 * backing buffer; fields after title_id are not interpreted. */
struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    uint32_t app_type;
    char title_id[10];
    unsigned char spare[236];
};
int sceKernelGetAppInfo(pid_t pid, struct app_info *info);
int sceKernelGetMainSocId(void);
static uint64_t self_proc;
static int kernel_layout_ok;

static int kernel_pointer(uint64_t p) {
    return p >> 48 == 0xffff && !(p & 7);
}

static uint64_t word64(const unsigned char *p) {
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static int read_kernel(uint64_t address, void *out, size_t n) {
    if (!kernel_pointer(address))
        return -1;
    return kernel_copyout((intptr_t)address, out, n);
}

static uint64_t bounded_proc(pid_t pid) {
    uint64_t proc = 0;
    if (read_kernel((uint64_t)KERNEL_ADDRESS_ALLPROC, &proc, 8))
        return 0;
    for (unsigned count = 0; proc && count < 512; ++count) {
        unsigned char prefix[0xc0];
        if (read_kernel(proc, prefix, sizeof(prefix)))
            return 0;
        uint32_t found;
        memcpy(&found, prefix + 0xbc, 4);
        if (found == (uint32_t)pid)
            return proc;
        uint64_t next = word64(prefix);
        if (next == proc)
            return 0;
        proc = next;
    }
    return 0;
}

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

/* SDK crt1.o kernel_get_proc_thread uses proc+0x10, td+0x10 for
 * list links and td+0x9c for TID. Validate those offsets on our own
 * process against thr_self before using them on other processes. */
static int validate_kernel_layout(pid_t self) {
    long own_tid = -1;
    if (syscall(SYS_thr_self, &own_tid))
        return 0;
    self_proc = bounded_proc(self);
    if (!self_proc)
        return 0;
    unsigned char proc_prefix[0x20];
    if (read_kernel(self_proc, proc_prefix, sizeof(proc_prefix)))
        return 0;
    uint64_t td = word64(proc_prefix + 0x10);
    for (unsigned i = 0; td && i < 256; ++i) {
        unsigned char head[0xa0];
        if (read_kernel(td, head, sizeof(head)) || word64(head + 8) != self_proc)
            return 0;
        uint32_t tid = word32(head + 0x9c);
        if (tid == (uint32_t)own_tid) {
            printf("kernel_layout self_proc=0x%016llx self_td=0x%016llx tid=%ld matched=1\n",
                   (unsigned long long)self_proc, (unsigned long long)td, own_tid);
            return 1;
        }
        uint64_t next = word64(head + 0x10);
        if (next == td)
            return 0;
        td = next;
    }
    return 0;
}

static void capture_threads(int pid, const char *comm, int pass) {
    uint64_t proc = bounded_proc(pid);
    unsigned char prefix[0x20];
    if (!proc || read_kernel(proc, prefix, sizeof(prefix))) {
        printf("threads pid=%d unavailable\n", pid);
        return;
    }
    uint64_t td = word64(prefix + 0x10);
    uint64_t visited[256];
    for (size_t i = 0; td && i < 256; ++i) {
        for (size_t j = 0; j < i; ++j)
            if (visited[j] == td) {
                printf("threads pid=%d cycle_detected\n", pid);
                return;
            }
        visited[i] = td;
        unsigned char bytes[0x480];
        if (read_kernel(td, bytes, sizeof(bytes)) || word64(bytes + 8) != proc) {
            printf("threads pid=%d index=%zu read_or_owner_failed\n", pid, i);
            return;
        }
        uint32_t tid = word32(bytes + 0x9c);
        char tag[80];
        snprintf(tag, sizeof(tag), "td-%d-%u-%d", pid, tid, pass);
        printf("thread pid=%d comm=%s index=%zu tid=%u td=0x%016llx proc=0x%016llx\n",
               pid, comm, i, tid, (unsigned long long)td, (unsigned long long)proc);
        raw_record(tag, i, bytes, sizeof(bytes));
        td = word64(bytes + 0x10);
    }
    printf("threads_end pid=%d next=0x%016llx\n", pid, (unsigned long long)td);
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
        struct app_info info;
        memset(&info, 0, sizeof(info));
        int app_rc = sceKernelGetAppInfo((pid_t)pid, &info);
        char title[11];
        safe_string(title, sizeof(title), (unsigned char *)info.title_id, 10);
        printf("app pid=%u rc=%d appid=0x%x type=0x%x title=%s\n",
               pid, app_rc, info.app_id, info.app_type, title);
        /* These are ABI hints only. Preserve every returned byte so offsets
         * can be checked offline before decoding wait state and thread IDs. */
        if (raw_all)
            raw_record(tag, seq, p + at, stride);
        if (kernel_layout_ok && (pid == (uint32_t)getpid()
            || !strcmp(comm, "SceShellCore") || !strcmp(comm, "SceShellUI")
            || !strcmp(comm, "SceAIO") || strstr(comm, "eboot")
            || (!app_rc && !strcmp(title, "PPSA90001"))))
            capture_threads((int)pid, comm, tag[strlen(tag) - 1] - '0');
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
    const char ready[] = "thread-probe-v2: ready (kernel reads, no hooks)\n";
    write(STDERR_FILENO, ready, sizeof(ready) - 1);
    setvbuf(stdout, NULL, _IOLBF, 0);
    pid_t self = getpid();
    printf("thread-probe: self_pid=%d\n", self);
    uint32_t fw = kernel_get_fw_version();
    int soc = sceKernelGetMainSocId();
    printf("firmware=0x%08x soc=0x%x\n", fw, soc);
    if ((fw & 0xffff0000u) != 0x13600000u || soc != 0x840fd0) {
        puts("unsupported firmware/model");
        return 7;
    }
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
    kernel_layout_ok = validate_kernel_layout(self);
    printf("kernel_layout_validated=%d\n", kernel_layout_ok);
    for (int pass = 0; pass < 3; ++pass) {
        int pids[256];
        size_t pid_count = 0;
        printf("snapshot pass=%d time=%lld\n", pass, (long long)time(NULL));
        p = query(PROC_ONLY, 0, &n);
        if (p) {
            char tag[32];
            snprintf(tag, sizeof(tag), "all-%d", pass);
            int rc = print_records(tag, p, n, 1, pids, &pid_count);
            free(p);
            if (rc)
                return 3;
        } else {
            /* v2 already discovers processes with PROC_ONLY and reads threads
             * from the kernel, so v1's per-PID sysctl fallback has nothing to
             * fall back to. Without all-N records the capture is unusable. */
            printf("snapshot pass=%d process_query_failed\n", pass);
            return 4;
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
