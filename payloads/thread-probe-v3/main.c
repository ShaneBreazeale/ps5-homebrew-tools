/* SPDX-License-Identifier: GPL-3.0-or-later
 * Thread probe v3: continuous plateau walker for a target title.
 * v2 capture core (allproc walk via SDK kernel reads, bounded thread
 * chains, raw records) plus title-targeted discovery and a live loop:
 * poll the target's threads every interval until the process is gone or
 * the cap expires, so a wedged app can be observed mid-plateau and the
 * trace survives a later console panic on the host side. No kernel
 * writes, hooks, or debug registers.
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
#include <errno.h>

#define PREFIX_BYTES 467u
#define COMM_OFFSET 447u
#define PID_OFFSET 72u
#define PROC_PID_AT 0xbcu   /* kernel proc prefix pid field used by v2 */
#define PROC_TD_AT 0x10u
#define TD_NEXT_AT 0x10u
#define TD_OWNER_AT 0x8u
#define TD_TID_AT 0x9cu
#define MAX_THREADS_PER_PROC 256u
#define DEFAULT_INTERVAL_MS 2000u
#define DEFAULT_CAP_PASSES 300u

struct app_info {
    uint32_t app_id;
    uint32_t app_type;
    uint64_t reserved[10];
    char title_id[10];
};

int sceKernelGetAppInfo(pid_t pid, struct app_info *info);
int sceKernelGetMainSocId(void);

static uint64_t word64(const unsigned char *p) {
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint32_t word32(const unsigned char *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static int kernel_pointer(uint64_t p) {
    return p >> 48 == 0xffff && !(p & 7);
}

static int read_kernel(uint64_t address, void *out, size_t n) {
    if (!kernel_pointer(address))
        return -1;
    return kernel_copyout((intptr_t)address, out, n);
}

static void safe_string(char *out, size_t out_size,
                        const unsigned char *src, size_t n) {
    size_t i;
    for (i = 0; i + 1 < out_size && i < n && src[i]; ++i)
        out[i] = src[i];
    out[i] = 0;
}

/* Discovery uses per-pid KERN_PROC_PID sysctl (the kstuff find_proc
 * pattern): from an elfldr payload the kernel-side allproc walk only
 * reaches system processes, while per-pid queries return user procs.
 * Match by title via app info first, then by comm prefix (an app's comm
 * begins with the title id or the eboot name). */
static int find_target_pid(const char *title, pid_t *out_pid,
                           uint64_t *out_proc) {
    char comm_prefix[8];
    snprintf(comm_prefix, sizeof(comm_prefix), "%.4s", title);
    for (pid_t pid = 1; pid < 1024; ++pid) {
        size_t sz = 1096;
        int key[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
        char buf[1097] = {0};
        if (sysctl(key, 4, buf, &sz, 0, 0) || sz < PREFIX_BYTES)
            continue;
        struct app_info info;
        memset(&info, 0, sizeof(info));
        if (!sceKernelGetAppInfo(pid, &info)) {
            char t[11];
            safe_string(t, sizeof(t), (unsigned char *)info.title_id, 10);
            if (!strcmp(t, title))
                goto found;
        }
        if (!strncmp(buf + COMM_OFFSET, comm_prefix, strlen(comm_prefix)))
            goto found;
        continue;
found:
        {
            uint64_t proc = 0;
            if (read_kernel((uint64_t)KERNEL_ADDRESS_ALLPROC, &proc, 8))
                return -1;
            for (unsigned count = 0; proc && count < 600; ++count) {
                unsigned char prefix[0xc0];
                if (read_kernel(proc, prefix, sizeof(prefix)))
                    return -1;
                if ((pid_t)word32(prefix + PROC_PID_AT) == pid) {
                    *out_pid = pid;
                    *out_proc = proc;
                    return 0;
                }
                uint64_t next = word64(prefix);
                if (next == proc)
                    break;
                proc = next;
            }
        }
    }
    return -1;
}

/* One bounded walk of the target's thread chain. Prints a compact line
 * per thread and keeps the full 0x480-byte raw record on stdout so the
 * host summarizer can decode wait channels without ABI guesses here. */
static int capture_target(const char *title, int pass) {
    pid_t pid = 0;
    uint64_t proc = 0;
    if (find_target_pid(title, &pid, &proc)) {
        printf("WALK pass=%d target=%s not_found\n", pass, title);
        return -1;
    }
    uint64_t td = 0;
    if (read_kernel(proc + PROC_TD_AT, &td, 8) || !kernel_pointer(td)) {
        printf("WALK pass=%d pid=%d head_invalid\n", pass, pid);
        return -1;
    }
    printf("WALK pass=%d pid=%d proc=0x%016llx\n",
           pass, pid, (unsigned long long)proc);
    uint64_t visited[MAX_THREADS_PER_PROC];
    size_t count = 0;
    while (td && count < MAX_THREADS_PER_PROC) {
        for (size_t j = 0; j < count; ++j)
            if (visited[j] == td) {
                printf("walk pid=%d cycle_at=%zu\n", pid, count);
                return (int)count;
            }
        visited[count++] = td;
        static unsigned char bytes[0x480];
        if (read_kernel(td, bytes, sizeof(bytes))
        || word64(bytes + TD_OWNER_AT) != proc) {
            printf("walk pid=%d index=%zu read_or_owner_failed\n", pid, count - 1);
            return (int)count;
        }
        uint32_t tid = word32(bytes + TD_TID_AT);
        printf("thread pid=%d index=%zu tid=%u td=0x%016llx\n",
               pid, count - 1, tid, (unsigned long long)td);
        printf("raw td-%u-%d=", tid, pass);
        for (size_t i = 0; i < sizeof(bytes); ++i)
            printf("%02x", bytes[i]);
        putchar('\n');
        td = word64(bytes + TD_NEXT_AT);
    }
    printf("walk_end pid=%d threads=%zu\n", pid, count);
    return (int)count;
}

int main(int argc, char **argv) {
    const char ready[] = "thread-probe-v3: ready (plateau walker)\n";
    write(STDERR_FILENO, ready, sizeof(ready) - 1);
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *title = argc > 1 ? argv[1] : "PPSA90001";
    unsigned interval_ms = DEFAULT_INTERVAL_MS;
    unsigned cap = DEFAULT_CAP_PASSES;
    if (argc > 2)
        interval_ms = (unsigned)strtoul(argv[2], NULL, 0);
    if (argc > 3)
        cap = (unsigned)strtoul(argv[3], NULL, 0);
    if (!interval_ms)
        interval_ms = DEFAULT_INTERVAL_MS;
    if (!cap)
        cap = DEFAULT_CAP_PASSES;

    uint32_t fw = kernel_get_fw_version();
    int soc = sceKernelGetMainSocId();
    printf("thread-probe-v3 target=%s interval_ms=%u cap=%u\n",
           title, interval_ms, cap);
    printf("firmware=0x%08x soc=0x%x self_pid=%d\n", fw, soc, getpid());
    if ((fw & 0xffff0000u) != 0x13600000u || soc != 0x840fd0) {
        puts("unsupported firmware/model");
        return 7;
    }

    const struct timespec delay = {
        (time_t)(interval_ms / 1000),
        (long)(interval_ms % 1000) * 1000000L,
    };
    int misses = 0;
    for (unsigned pass = 0; pass < cap; ++pass) {
        int n = capture_target(title, (int)pass);
        if (n < 0 && ++misses >= 30) {
            /* Half a minute of absence at the default cadence: stop. */
            printf("thread-probe-v3: target absent for %d passes, done\n",
                   misses);
            break;
        }
        if (n >= 0)
            misses = 0;
        fflush(stdout);
        nanosleep(&delay, NULL);
    }
    puts("thread-probe-v3: complete");
    return 0;
}
