/* SPDX-License-Identifier: GPL-3.0-or-later
 * Streams a completed capture directory off the console. No kernel access.
 * Listens on LISTEN_PORT, serves manifest.json then kernel_text.bin, then exits.
 * Framing per file: "FPK1" u32 name_len_le u64 size_le, name, raw bytes.
 * Completion: "END1" followed by twelve zero bytes and connection close.
 * PS5 is little endian; framing integers are copied in native byte order.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef LISTEN_PORT
#define LISTEN_PORT 9030
#endif
#ifndef CAPTURE_ROOT
#define CAPTURE_ROOT "/data"
#endif
#ifndef CAPTURE_PREFIX
#define CAPTURE_PREFIX "capture-"
#endif
#define MAX_CAPTURE_BYTES (UINT64_C(1) << 30)
#define ACCEPT_TIMEOUT_SEC 120
#define SEND_TIMEOUT_SEC 30

static int find_capture_dir(char *out, size_t out_len) {
    #ifdef CAPTURE_DIRECTORY
    int len = snprintf(out, out_len, "%s", CAPTURE_DIRECTORY);
    return len < 0 || (size_t)len >= out_len ? -1 : 0;
#endif
    DIR *d = opendir(CAPTURE_ROOT);
    if (!d) { perror("opendir /data"); return -1; }
    char best[256] = {0};
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strncmp(e->d_name, CAPTURE_PREFIX, sizeof(CAPTURE_PREFIX) - 1)) continue;
        char probe[1024];
        snprintf(probe, sizeof(probe), CAPTURE_ROOT "/%s/kernel_text.bin", e->d_name);
        struct stat st;
        if (stat(probe, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (st.st_size <= 0 || (uint64_t)st.st_size > MAX_CAPTURE_BYTES) continue;
        if (!best[0] || strcmp(e->d_name, best) > 0) snprintf(best, sizeof(best), "%s", e->d_name);
    }
    closedir(d);
    if (!best[0]) { puts("No completed capture directory found"); return -1; }
    int len = snprintf(out, out_len, CAPTURE_ROOT "/%s", best);
    return len < 0 || (size_t)len >= out_len ? -1 : 0;
}

static int send_all(int fd, const void *data, size_t len) {
    const unsigned char *p = data;
    while (len) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int send_framed_file(int conn, const char *path, const char *name) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) { perror(path); return -1; }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 || (uint64_t)st.st_size > MAX_CAPTURE_BYTES) { close(fd); return -1; }
    uint64_t size = (uint64_t)lseek(fd, 0, SEEK_END);
    if (size == (uint64_t)-1 || lseek(fd, 0, SEEK_SET) == (off_t)-1) { perror("lseek"); close(fd); return -1; }
    if (!strcmp(name, "manifest.json") && size > (UINT64_C(1) << 20)) { close(fd); return -1; }
    char header[16];
    memcpy(header, "FPK1", 4);
    uint32_t name_len = (uint32_t)strlen(name);
    memcpy(header + 4, &name_len, 4);
    memcpy(header + 8, &size, 8);
    if (send_all(conn, header, sizeof(header))
        || send_all(conn, name, name_len)) { close(fd); return -1; }
    uint64_t sent = 0;
    unsigned char buf[65536];
    while (sent < size) {
        ssize_t n = read(fd, buf, size - sent < sizeof(buf) ? (size_t)(size - sent) : sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        if (send_all(conn, buf, (size_t)n)) break;
        sent += (uint64_t)n;
        if (!(sent & 0xfffff)) printf("Streamed %s: %llu bytes\n", name, (unsigned long long)sent);
    }
    close(fd);
    if (sent != size) { printf("FAILED %s at %llu/%llu\n", name, (unsigned long long)sent, (unsigned long long)size); return -1; }
    printf("Sent %s: %llu bytes\n", name, (unsigned long long)sent);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char dir[160];
    if (find_capture_dir(dir, sizeof(dir))) return 1;
    printf("Capture dir: %s\n", dir);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(LISTEN_PORT);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) || listen(s, 1)) { perror("bind/listen"); close(s); return 1; }
    puts("EXPORT_LISTENING");
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    struct timeval tv = {ACCEPT_TIMEOUT_SEC, 0};
    if (select(s + 1, &rfds, NULL, NULL, &tv) <= 0) { puts("No receiver connected in time"); close(s); return 1; }
    int conn = accept(s, NULL, NULL);
    close(s);
    if (conn < 0) { perror("accept"); return 1; }
    #ifdef SO_NOSIGPIPE
    setsockopt(conn, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    #endif
    struct timeval sto = {SEND_TIMEOUT_SEC, 0};
    setsockopt(conn, SOL_SOCKET, SO_SNDTIMEO, &sto, sizeof(sto));
    char path[220];
    int ok = 0;
    snprintf(path, sizeof(path), "%s/manifest.json", dir);
    if (send_framed_file(conn, path, "manifest.json") == 0) {
        snprintf(path, sizeof(path), "%s/kernel_text.bin", dir);
        ok = send_framed_file(conn, path, "kernel_text.bin") == 0;
    }
    if (ok) {
        const unsigned char done[16] = {'E', 'N', 'D', '1'};
        ok = send_all(conn, done, sizeof(done)) == 0;
    }
    close(conn);
    puts(ok ? "EXPORT OK" : "EXPORT FAILED");
    return ok ? 0 : 2;
}
