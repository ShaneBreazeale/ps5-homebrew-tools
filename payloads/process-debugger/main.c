/* SPDX-License-Identifier: GPL-3.0-or-later
 * Listener and server lifecycle. Target policy belongs to the backend;
 * packet parsing and transport belong to the RSP adapter.
 */
#include "ptrace_backend.h"
#include "rsp.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#define DETACH_RETRIES 8
#define CREDENTIAL_RETRIES 8
#ifndef PROCESS_DEBUG_PORT
#define PROCESS_DEBUG_PORT 1234
#endif

int main(void)
{
    struct debug_target* backend = process_debug_target();
    setvbuf(stdout, 0, _IONBF, 0);
    struct sigaction ignore = {.sa_handler = SIG_IGN};
    sigaction(SIGPIPE, &ignore, 0);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if(listener < 0) return 1;
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in sa = {
        .sin_len = sizeof(sa), .sin_family = AF_INET,
        .sin_port = (unsigned short)((PROCESS_DEBUG_PORT >> 8) | (PROCESS_DEBUG_PORT << 8)),
        .sin_addr = {.s_addr = 0},
    };
    if(bind(listener, (void*)&sa, sizeof(sa)) < 0 || listen(listener, 1) < 0) { close(listener); return 2; }
    printf("process-debugger: ready pid=%d port=%d (ptrace backend)\n", getpid(), PROCESS_DEBUG_PORT);
    fflush(stdout);
    for(;;) {
        int connection = accept(listener, 0, 0);
        if(connection < 0) { if(errno == EINTR) continue; break; }
        int nodelay = 1;
        setsockopt(connection, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
        int shutdown_requested = rsp_serve(backend, connection, listener) == 1;
        /* On disconnect, keep the server alive until detach succeeds. Exiting
         * while attached could kill the target on FreeBSD-derived kernels.
         * Retry transient detach failures a bounded number of times, then stop:
         * a poisoned or persistently un-detachable target is left stopped and
         * alive for manual recovery, not resumed, killed, or spun on forever
         * while flooding the log. */
        struct target_identity identity;
        struct target_state state;
        backend->ops->identity(backend->ctx, &identity);
        for(int tries = 0; identity.pid && backend->ops->detach(backend->ctx) < 0; ) {
            backend->ops->state(backend->ctx, &state);
            if(state.memory_poisoned || ++tries >= DETACH_RETRIES) {
#ifndef PROCESS_DEBUGGER_TEST
                (void)process_backend_restore_credentials();
#endif
                const char wedged[] = "process-debugger: cannot detach; target left stopped, "
                    "manual recovery required\n";
                write(1, wedged, sizeof(wedged)-1);
                for(;;) { struct timespec idle = {3600, 0}; nanosleep(&idle, 0); }
            }
            const char failed[] = "process-debugger: detach failed; retrying without exiting\n";
            write(1, failed, sizeof(failed)-1);
            struct timespec delay = {1, 0}; nanosleep(&delay, 0);
            backend->ops->identity(backend->ctx, &identity);
        }
#ifndef PROCESS_DEBUGGER_TEST
        /* No target is attached here (detach already succeeded), so the risk is
         * the reverse of detach: a live process holding elevated credentials.
         * Retry a bounded number of times, then exit so process teardown drops
         * the elevated ucred rather than leaking it under an endless retry. */
        for(int tries = 0; process_backend_restore_credentials(); ) {
            const char failed[] = "process-debugger: credential restore failed; retrying\n";
            write(1, failed, sizeof(failed)-1);
            if(++tries >= CREDENTIAL_RETRIES) {
                const char giving_up[] = "process-debugger: credential restore failed repeatedly; "
                    "exiting to drop elevated credentials\n";
                write(1, giving_up, sizeof(giving_up)-1);
                close(connection);
                backend->ops->finish_test(backend->ctx);
                close(listener);
                return 3;
            }
            struct timespec delay = {1, 0}; nanosleep(&delay, 0);
        }
#endif
        close(connection);
        if(shutdown_requested) break;
    }
    backend->ops->finish_test(backend->ctx);
    close(listener);
    return 0;
}
