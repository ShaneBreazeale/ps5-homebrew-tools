/* SPDX-License-Identifier: GPL-3.0-or-later
 * Resident development control on TCP 9098, one authenticated line per connection:
 * PING <token>, LIST <token>, KILL <token> <target>, SHOT <token>.
 * SHOT reads an existing screenshot; it is not a framebuffer capture.
 * Process offsets match process-snapshot / process-watch on firmware 13.60.
 */
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <ps5/kernel.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define DEV_CTL_PORT 9098
#define MAX_BYTES (4u * 1024u * 1024u)
#define MAX_PROCS 512
#define PID_OFFSET 72u
#define PPID_OFFSET 76u
#define STAT_OFFSET 388u
#define COMM_OFFSET 447u
#define NTHR_OFFSET 596u
#define PROC_ONLY 8
#define MAX_SHOT_BYTES (UINT64_C(64) << 20)
#define MAX_SHOT_ENTRIES 8192
#define CLIENT_SECONDS 30
#define SHOT_DIR "/user/av_contents/photo"

struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    uint32_t app_type;
    char title_id[10];
    unsigned char spare[236];
};

/* Declared by hand, like process-snapshot does for sceKernelGetAppInfo:
 * the SDK ships these as libkernel stubs with no public header. */
int sceKernelLoadStartModule(const char *name, size_t argc, const void *argv,
                             uint32_t flags, void *opt, int *res);
int sceKernelDlsym(int handle, const char *symbol, void **addr);
int sceKernelGetAppInfo(pid_t pid, struct app_info *info);

struct ent {
    uint32_t pid;
    uint32_t ppid;
    uint32_t nthr;
    uint8_t stat;
    char comm[21];
    char title[11];
};

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

/* Serial accept loop: all I/O shares the deadline established at accept. */
static struct timespec g_deadline;
static char g_token[65];

static int remaining_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    int64_t ns = (int64_t)(g_deadline.tv_sec - now.tv_sec) * 1000000000 +
                 g_deadline.tv_nsec - now.tv_nsec;
    return ns > 0 ? (int)((ns + 999999) / 1000000) : 0;
}

static int wait_socket(int fd, short events) {
    for (;;) {
        int ms = remaining_ms();
        if (!ms)
            return -1;
        struct pollfd p = { .fd = fd, .events = events };
        int rc = poll(&p, 1, ms);
        if (rc < 0 && errno == EINTR)
            continue;
        return rc > 0 && remaining_ms() ? 0 : -1;
    }
}

static int send_all(int fd, const void *data, size_t len) {
    const unsigned char *p = data;
    while (len) {
        if (wait_socket(fd, POLLOUT) < 0)
            return -1;
        ssize_t n = send(fd, p, len, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (n <= 0)
            return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int reply(int fd, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        return -1;
    if ((size_t)n >= sizeof(buf))
        n = (int)sizeof(buf) - 1;
    return send_all(fd, buf, (size_t)n);
}

/* One sysctl query; caller frees the buffer. Returns 0 on success. */
static int query_procs(unsigned char **out, size_t *out_n) {
    int mib[3] = { CTL_KERN, KERN_PROC, PROC_ONLY };
    for (int attempt = 0; attempt < 3; ++attempt) {
        size_t need = 0;
        errno = 0;
        if (sysctl(mib, 3, NULL, &need, NULL, 0))
            return -1;
        if (!need || need > MAX_BYTES - 65536)
            return -1;
        size_t cap = need + 65536;
        unsigned char *p = calloc(1, cap);
        if (!p)
            return -1;
        size_t n = cap;
        errno = 0;
        int rc = sysctl(mib, 3, p, &n, NULL, 0);
        int error = errno;
        if (!rc && n <= cap) {
            *out = p;
            *out_n = n;
            return 0;
        }
        free(p);
        if (error != ENOMEM)
            return -1;
    }
    return -1;
}

static int collect_procs(struct ent *ents, int max, int *truncated) {
    unsigned char *p = NULL;
    size_t n = 0;
    if (query_procs(&p, &n))
        return -1;
    size_t at = 0;
    int count = 0;
    *truncated = 0;
    while (at < n) {
        if (n - at < sizeof(uint32_t)) {
            free(p);
            return -2;
        }
        size_t stride = word32(p + at);
        if (stride < 600 || stride > n - at ||
            NTHR_OFFSET + sizeof(uint32_t) > stride ||
            NTHR_OFFSET + sizeof(uint32_t) > n - at) {
            free(p);
            return -2;
        }
        if (count < max) {
            struct ent *e = &ents[count];
            e->pid = word32(p + at + PID_OFFSET);
            e->ppid = word32(p + at + PPID_OFFSET);
            e->nthr = word32(p + at + NTHR_OFFSET);
            e->stat = p[at + STAT_OFFSET];
            safe_string(e->comm, sizeof(e->comm), p + at + COMM_OFFSET, 20);
            struct app_info info;
            memset(&info, 0, sizeof(info));
            if (sceKernelGetAppInfo((pid_t)e->pid, &info) == 0)
                safe_string(e->title, sizeof(e->title),
                            (unsigned char *)info.title_id, 10);
            else
                e->title[0] = 0;
        } else {
            *truncated = 1;
        }
        at += stride;
        ++count;
    }
    free(p);
    return count;
}

static int is_protected(const char *comm) {
    return strstr(comm, "Shell") != NULL || strstr(comm, "SysCore") != NULL ||
           strstr(comm, "SceShell") != NULL;
}

static int is_all_digits(const char *s) {
    if (!*s)
        return 0;
    for (; *s; ++s)
        if (*s < '0' || *s > '9')
            return 0;
    return 1;
}

/* Stage A: system-level kill request. Returns 1 on request success,
 * 0 if no request succeeded, -1 if unavailable. Exit is not observed. */
static int kill_via_system(const char *target, int *app_id_out) {
    int handle = sceKernelLoadStartModule("libSceSystemService.sprx", 0, NULL,
                                          0, NULL, NULL);
    if (handle < 0)
        return -1;

    int (*get_running_lnc)(void) = NULL;
    int (*get_running_sys)(void) = NULL;
    int (*get_app_id)(const char *title_id) = NULL;
    int (*kill_app_lnc)(int app_id) = NULL;
    int (*kill_app_sys)(int app_id) = NULL;
    sceKernelDlsym(handle, "sceLncUtilGetAppIdOfRunningBigApp",
                   (void **)&get_running_lnc);
    sceKernelDlsym(handle, "sceSystemServiceGetAppIdOfRunningBigApp",
                   (void **)&get_running_sys);
    sceKernelDlsym(handle, "sceLncUtilGetAppId", (void **)&get_app_id);
    sceKernelDlsym(handle, "sceLncUtilKillApp", (void **)&kill_app_lnc);
    sceKernelDlsym(handle, "sceSystemServiceKillApp", (void **)&kill_app_sys);
    if (!kill_app_lnc && !kill_app_sys)
        return -1;

    int app_id = -1;
    if (strcmp(target, "ACTIVE") == 0) {
        if (get_running_lnc)
            app_id = get_running_lnc();
        if (app_id <= 0 && get_running_sys)
            app_id = get_running_sys();
    } else if (strncmp(target, "PPSA", 4) == 0 && get_app_id) {
        app_id = get_app_id(target);
    }
    if (app_id <= 0)
        return 0;
    *app_id_out = app_id;
    if (!remaining_ms())
        return 0;
    if (kill_app_lnc && kill_app_lnc(app_id) == 0)
        return 1;
    if (!remaining_ms())
        return 0;
    if (kill_app_sys && kill_app_sys(app_id) == 0)
        return 1;
    return 0;
}

/* Validate the entire snapshot and every match before sending any signal. */
static int kill_via_sysctl(int fd, const char *target, int title_only) {
    int numeric = is_all_digits(target);
    unsigned long want_pid = 0;
    if (numeric) {
        errno = 0;
        want_pid = strtoul(target, NULL, 10);
        if (errno == ERANGE || want_pid > INT_MAX || want_pid == 0)
            return reply(fd, "ERR:NOT_FOUND\n");
        if (want_pid == 1)
            return reply(fd, "ERR:REFUSED\n");
    }
    struct ent ents[MAX_PROCS];
    int truncated = 0;
    int count = collect_procs(ents, MAX_PROCS, &truncated);
    if (count < 0)
        return reply(fd, "ERR:QUERY_FAILED\n");
    if (truncated)
        return reply(fd, "ERR:TRUNCATED\n");

    pid_t matches[MAX_PROCS];
    int matched = 0;
    pid_t self = getpid();
    for (int i = 0; i < count; ++i) {
        struct ent *e = &ents[i];
        int match = numeric ? e->pid == want_pid :
            ((!title_only && strcmp(e->comm, target) == 0) ||
             (e->title[0] && strcmp(e->title, target) == 0));
        if (!match || e->pid == (uint32_t)self)
            continue;
        if (e->pid == 1 || is_protected(e->comm))
            return reply(fd, "ERR:REFUSED\n");
        /* Never let a malformed pid become kill(0) or kill(-1). */
        if (e->pid == 0 || e->pid > INT_MAX)
            return reply(fd, "ERR:QUERY_FAILED\n");
        matches[matched++] = (pid_t)e->pid;
    }
    if (!matched)
        return reply(fd, "ERR:NOT_FOUND\n");
    if (!remaining_ms())
        return -1;
    int killed = 0, failed = 0;
    pid_t first = 0;
    for (int i = 0; i < matched; ++i) {
        if (!remaining_ms())
            return -1;
        if (kill(matches[i], SIGKILL) == 0) {
            if (!killed)
                first = matches[i];
            ++killed;
        } else {
            ++failed;
        }
    }
    if (failed)
        return reply(fd, "ERR:PARTIAL killed=%d failed=%d\n", killed, failed);
    return reply(fd, "OK:KILLED pid=%u count=%d\n", (unsigned)first, killed);
}

static int handle_kill(int fd, const char *target) {
    if (!target[0])
        return reply(fd, "ERR:EMPTY_TARGET\n");
    int active = strcmp(target, "ACTIVE") == 0;
    int title = strncmp(target, "PPSA", 4) == 0;
    if (active || title) {
        int app_id = -1;
        int rc = kill_via_system(target, &app_id);
        if (rc == 1)
            return reply(fd, "OK:KILLED app=%d\n", app_id);
        if (active)
            return reply(fd, rc < 0 ? "ERR:UNAVAILABLE\n" : "ERR:NOT_FOUND\n");
    }
    return kill_via_sysctl(fd, target, title);
}

static int handle_list(int fd) {
    struct ent ents[MAX_PROCS];
    int truncated = 0;
    int count = collect_procs(ents, MAX_PROCS, &truncated);
    if (count < 0)
        return reply(fd, "ERR:QUERY_FAILED\n");
    int shown = count < MAX_PROCS ? count : MAX_PROCS;
    for (int i = 0; i < shown; ++i) {
        if (reply(fd, "proc pid=%u ppid=%u stat=%u nthr=%u comm=%s title=%s\n",
                  ents[i].pid, ents[i].ppid, ents[i].stat, ents[i].nthr,
                  ents[i].comm, ents[i].title) < 0)
            return -1;
    }
    return reply(fd, "OK:LIST n=%d%s\n", count,
                 truncated ? " truncated" : "");
}

static int has_ext(const char *name, const char *ext) {
    size_t nl = strlen(name), el = strlen(ext);
    if (nl < el)
        return 0;
    const char *tail = name + nl - el;
    for (size_t i = 0; i < el; ++i) {
        char a = tail[i], b = ext[i];
        if (a >= 'A' && a <= 'Z')
            a += 'a' - 'A';
        if (b >= 'A' && b <= 'Z')
            b += 'a' - 'A';
        if (a != b)
            return 0;
    }
    return 1;
}

struct shot {
    char path[576];
    const char *fmt;
    time_t mtime;
};

/* Open every path component without following symlinks, including parents
 * that may have changed since lstat. Paths here are absolute, from readdir. */
static int open_shot_path(const char *path, int flags) {
    char copy[576];
    if (strlen(path) >= sizeof(copy) || path[0] != '/')
        return -1;
    strcpy(copy, path);
    int dir = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dir < 0)
        return -1;
    char *save = NULL;
    char *part = strtok_r(copy, "/", &save);
    while (part) {
        char *next = strtok_r(NULL, "/", &save);
        int file = openat(dir, part, O_NOFOLLOW | O_NONBLOCK |
                          (next ? O_RDONLY | O_DIRECTORY : flags));
        close(dir);
        if (file < 0)
            return -1;
        dir = file;
        part = next;
    }
    return dir;
}

static void scan_shot_dir(const char *dir, int depth, struct shot *shots,
                          int *count, int *scanned) {
    struct stat st;
    if (!remaining_ms() || lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
        return;
    int file = open_shot_path(dir, O_RDONLY | O_DIRECTORY);
    if (file < 0)
        return;
    DIR *d = fdopendir(file);
    if (!d) {
        close(file);
        return;
    }
    struct dirent *e;
    while (*scanned < MAX_SHOT_ENTRIES && remaining_ms() && (e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        ++*scanned;
        char path[576];
        int len = snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        if (len < 0 || (size_t)len >= sizeof(path) || lstat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            if (depth > 0)
                scan_shot_dir(path, depth - 1, shots, count, scanned);
        } else if (S_ISREG(st.st_mode)) {
            const char *fmt = has_ext(e->d_name, ".png") ? "png" :
                (has_ext(e->d_name, ".jpg") || has_ext(e->d_name, ".jpeg"))
                ? "jpg" : NULL;
            if (fmt) {
                struct shot *shot = &shots[(*count)++];
                strcpy(shot->path, path);
                shot->fmt = fmt;
                shot->mtime = st.st_mtime;
            }
        }
    }
    closedir(d);
}

static int newest_first(const void *a, const void *b) {
    const struct shot *sa = a, *sb = b;
    return sa->mtime < sb->mtime ? 1 : sa->mtime > sb->mtime ? -1 :
           strcmp(sa->path, sb->path);
}

static int handle_shot(int fd) {
    struct shot *shots = calloc(MAX_SHOT_ENTRIES, sizeof(*shots));
    if (!shots)
        return reply(fd, "ERR:NO_SCREENSHOT\n");
    int count = 0, scanned = 0;
    scan_shot_dir(SHOT_DIR, 3, shots, &count, &scanned);
    qsort(shots, (size_t)count, sizeof(*shots), newest_first);
    int file = -1;
    struct stat st;
    const char *fmt = NULL;
    for (int i = 0; i < count && remaining_ms(); ++i) {
        file = open_shot_path(shots[i].path, O_RDONLY);
        if (file < 0)
            continue;
        if (fstat(file, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
            (uint64_t)st.st_size <= MAX_SHOT_BYTES) {
            fmt = shots[i].fmt;
            break;
        }
        close(file);
        file = -1;
    }
    free(shots);
    if (file < 0)
        return reply(fd, "ERR:NO_SCREENSHOT\n");
    if (reply(fd, "OK:SHOT %s %llu\n", fmt,
              (unsigned long long)st.st_size) < 0) {
        close(file);
        return -1;
    }
    unsigned char buf[65536];
    uint64_t sent = 0;
    uint64_t size = (uint64_t)st.st_size;
    while (sent < size) {
        size_t want = size - sent < sizeof(buf) ? (size_t)(size - sent)
                                                : sizeof(buf);
        ssize_t n = read(file, buf, want);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        if (send_all(fd, buf, (size_t)n) < 0)
            break;
        sent += (uint64_t)n;
    }
    close(file);
    return sent == size ? 0 : -1;
}

/* cap includes space for NUL. Callers supply a nonempty buffer. */
static int read_line(int fd, char *buf, size_t cap) {
    size_t len = 0;
    buf[0] = 0;
    for (;;) {
        if (wait_socket(fd, POLLIN) < 0)
            return -1;
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (n <= 0 || c == 0)
            return -1;
        if (c == '\n')
            return (int)len;
        if (len + 1 >= cap)
            return -1;
        buf[len++] = c;
        buf[len] = 0;
    }
}

static int authenticated(const char *token) {
    if (!token || strlen(token) != 64)
        return 0;
    volatile unsigned diff = 0;
    for (size_t i = 0; i < 64; ++i) {
        unsigned char c = (unsigned char)token[i];
        unsigned hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        diff |= (unsigned)(c ^ (unsigned char)g_token[i]) | (hex ^ 1u);
    }
    return diff == 0;
}

static void handle_client(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return;
    char cmd[256];
    int len = read_line(fd, cmd, sizeof(cmd));
    if (len < 0 || !remaining_ms())
        return;
    if (len && cmd[len - 1] == '\r')
        cmd[--len] = 0;
    char *token = strchr(cmd, ' ');
    char *target = NULL;
    if (token) {
        *token++ = 0;
        target = strchr(token, ' ');
        if (target)
            *target++ = 0;
    }
    if (!authenticated(token)) {
        reply(fd, "ERR:AUTH\n");
        return;
    }
    if (!remaining_ms())
        return;
    if (strcmp(cmd, "PING") == 0 && !target)
        reply(fd, "OK:PONG\n");
    else if (strcmp(cmd, "LIST") == 0 && !target)
        handle_list(fd);
    else if (strcmp(cmd, "KILL") == 0)
        handle_kill(fd, target ? target : "");
    else if (strcmp(cmd, "SHOT") == 0 && !target)
        handle_shot(fd);
    else
        reply(fd, "ERR:UNKNOWN_CMD\n");
}

static int make_token(void) {
    unsigned char bytes[32];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;
    size_t at = 0;
    while (at < sizeof(bytes)) {
        ssize_t n = read(fd, bytes + at, sizeof(bytes) - at);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            close(fd);
            return -1;
        }
        at += (size_t)n;
    }
    close(fd);
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(bytes); ++i) {
        g_token[2 * i] = hex[bytes[i] >> 4];
        g_token[2 * i + 1] = hex[bytes[i] & 15];
    }
    g_token[64] = 0;
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint32_t fw = kernel_get_fw_version();
    if ((fw & 0xffff0000u) != 0x13600000u) {
        puts("dev-control: unsupported firmware");
        return 7;
    }
    if (make_token() < 0)
        return 1;
    struct sigaction ignore = { .sa_handler = SIG_IGN };
    sigaction(SIGPIPE, &ignore, 0);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(DEV_CTL_PORT);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(srv, 4) < 0) {
        perror("bind/listen");
        close(srv);
        return 1;
    }
    printf("dev-control: ready pid=%d port=%d token=%s\n",
           (int)getpid(), DEV_CTL_PORT, g_token);
    for (;;) {
        int client = accept(srv, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (clock_gettime(CLOCK_MONOTONIC, &g_deadline) != 0) {
            close(client);
            continue;
        }
        g_deadline.tv_sec += CLIENT_SECONDS;
        handle_client(client);
        close(client);
    }
    close(srv);
    return 0;
}
