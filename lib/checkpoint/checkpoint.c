/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "checkpoint.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int64_t cp_clock(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
void cp_close(struct cp_client *c) {
    if (c && c->fd >= 0) { close(c->fd); c->fd = -1; }
}
static int cp_fail(struct cp_client *c, int error) {
    cp_close(c); c->error = error ? error : EIO; return c->error;
}
static int cp_wait(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t now = cp_clock();
        if (now < 0) return EIO;
        if (now >= deadline) return ETIMEDOUT;
        struct pollfd p = {fd, events, 0};
        int result = poll(&p, 1, (int)(deadline-now));
        if (result < 0) { if (errno == EINTR) continue; return errno; }
        if (!result) return ETIMEDOUT;
        if (p.revents & events) return 0;
        if (p.revents & (POLLERR|POLLHUP|POLLNVAL)) return ECONNRESET;
    }
}
static int cp_transfer(int fd, unsigned char *buffer, size_t size, int sending, int64_t deadline) {
    size_t offset = 0;
    while (offset < size) {
        int error = cp_wait(fd, sending ? POLLOUT : POLLIN, deadline);
        if (error) return error;
        int flags = 0;
#ifdef MSG_NOSIGNAL
        if (sending) flags = MSG_NOSIGNAL;
#endif
        ssize_t n = sending ? send(fd, buffer+offset, size-offset, flags)
                            : recv(fd, buffer+offset, size-offset, 0);
        if (n < 0) { if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue; return errno; }
        if (!n) return ECONNRESET;
        offset += (size_t)n;
    }
    return 0;
}
static int cp_publish(struct cp_client *c, uint32_t kind, int64_t deadline) {
    unsigned char packet[PE_SIZE], expected[PE_ACK_SIZE], ack[PE_ACK_SIZE];
    if (c->error) return c->error;
    if (c->fd < 0) return ENOTCONN;
    if (c->record.sequence == UINT64_MAX) return cp_fail(c, EOVERFLOW);
    c->record.kind = kind;
    ++c->record.sequence;
    int64_t now = cp_clock();
    if (now < 0) return cp_fail(c, EIO);
    c->record.ticks = (uint64_t)now; /* monotonic milliseconds, not wall time */
    pe_encode(&c->record, packet); pe_ack(&c->record, expected);
    int error = cp_transfer(c->fd, packet, sizeof(packet), 1, deadline);
    if (!error) error = cp_transfer(c->fd, ack, sizeof(ack), 0, deadline);
    if (!error && memcmp(expected, ack, sizeof(ack))) error = EPROTO;
    return error ? cp_fail(c, error) : 0;
}
int cp_init(struct cp_client *c, const uint64_t session[2],
            const unsigned char build_id[32], uint64_t groups, uint32_t timeout_ms) {
    if (!c || !session || !build_id) return EINVAL;
    unsigned char any = 0;
    for (unsigned i = 0; i < 32; ++i) any |= build_id[i];
    /* Call only on fresh/closed storage; do not silently close a live client. */
    pe_zero(c, sizeof(*c)); c->fd = -1;
    if (!(session[0]|session[1]) || !any || !timeout_ms || timeout_ms > 60000)
        return c->error = EINVAL;
    c->timeout_ms = timeout_ms; c->groups = groups;
    c->record.session[0] = session[0]; c->record.session[1] = session[1];
    for (unsigned i = 0; i < 32; ++i) c->record.build_id[i] = build_id[i];
    c->record.cpu = PE_NO_CPU;
    c->record.subject_pid = (uint32_t)getpid();
    return 0;
}
int cp_connect(struct cp_client *c, const char *ipv4, uint16_t port) {
    if (!c || !ipv4 || !port) return EINVAL;
    if (c->error) return c->error;
    if (!c->timeout_ms) return EINVAL;
    if (c->fd >= 0 || c->record.sequence) return EBUSY;
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET; address.sin_port = htons(port);
    if (inet_pton(AF_INET, ipv4, &address.sin_addr) != 1) return EINVAL;
    int64_t now = cp_clock();
    if (now < 0) return cp_fail(c, EIO);
    int64_t deadline = now + c->timeout_ms;
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0) return cp_fail(c, errno);
#ifdef SO_NOSIGPIPE
    int one = 1;
    if (setsockopt(c->fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one))) return cp_fail(c, errno);
#endif
    int mode = fcntl(c->fd, F_GETFL, 0);
    if (mode < 0 || fcntl(c->fd, F_SETFL, mode|O_NONBLOCK)) return cp_fail(c, errno);
    if (connect(c->fd, (struct sockaddr *)&address, sizeof(address))) {
        if (errno != EINPROGRESS) return cp_fail(c, errno);
        int error = cp_wait(c->fd, POLLOUT, deadline), pending = 0;
        socklen_t length = sizeof(pending);
        if (error) return cp_fail(c, error);
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &pending, &length)) return cp_fail(c, errno);
        if (pending) return cp_fail(c, pending);
    }
    return cp_publish(c, PE_HELLO, deadline);
}
int cp_emit(struct cp_client *c, unsigned group, uint32_t thread, uint32_t site,
            uint32_t phase, const uint64_t arguments[4]) {
    if (!c || group >= 64 || !site || phase > PE_AFTER) return EINVAL;
    if (c->error) return c->error;
    if (!(c->groups & (UINT64_C(1)<<group))) return 0;
    if (c->fd < 0) return ENOTCONN;
    c->record.thread = thread; c->record.site = site; c->record.phase = phase;
    for (unsigned i = 0; i < 4; ++i) c->record.arguments[i] = arguments ? arguments[i] : 0;
    int64_t now = cp_clock();
    if (now < 0) return cp_fail(c, EIO);
    return cp_publish(c, PE_CHECKPOINT, now+c->timeout_ms);
}
int cp_end(struct cp_client *c) {
    if (!c) return EINVAL;
    if (c->error) return c->error;
    c->record.thread = c->record.site = c->record.phase = 0;
    for (unsigned i = 0; i < 4; ++i) c->record.arguments[i] = 0;
    int64_t now = cp_clock();
    if (now < 0) return cp_fail(c, EIO);
    int error = cp_publish(c, PE_END, now+c->timeout_ms);
    cp_close(c); return error;
}
