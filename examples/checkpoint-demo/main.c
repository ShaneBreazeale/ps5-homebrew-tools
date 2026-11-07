/* SPDX-License-Identifier: GPL-3.0-or-later
 * Benign host/SDK compile example. No kernel operation or console deployment.
 */
#include "../../lib/checkpoint/checkpoint.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static int hex(const char *text, unsigned char *bytes, unsigned count) {
    if (!text) return 0;
    for (unsigned i = 0; i < count; ++i) {
        unsigned value = 0;
        for (unsigned n = 0; n < 2; ++n) {
            unsigned char ch = (unsigned char)*text++;
            if (ch >= '0' && ch <= '9') value = (value<<4) | (ch-'0');
            else if (ch >= 'a' && ch <= 'f') value = (value<<4) | (ch-'a'+10);
            else if (ch >= 'A' && ch <= 'F') value = (value<<4) | (ch-'A'+10);
            else return 0;
        }
        bytes[i] = (unsigned char)value;
    }
    return !*text;
}
int main(int argc, char **argv) {
    /* Environment works for an app launcher that supplies it; payload loaders
     * may not. A real payload should explicitly read its own bounded config. */
    const char *host = argc > 1 ? argv[1] : getenv("CP_HOST");
    const char *port_text = argc > 2 ? argv[2] : getenv("CP_PORT");
    const char *session_text = argc > 3 ? argv[3] : getenv("CP_SESSION");
    const char *build_text = argc > 4 ? argv[4] : getenv("CP_BUILD_ID");
    const char *groups_text = argc > 5 ? argv[5] : getenv("CP_GROUPS");
    unsigned char session_bytes[16], build[32];
    char *end = NULL;
    unsigned long port = port_text ? strtoul(port_text, &end, 10) : 0;
    if (!host || !port_text || !*port_text || !end || *end || !port || port > 65535
        || !hex(session_text, session_bytes, 16) || !hex(build_text, build, 32)) {
        fprintf(stderr, "usage: checkpoint-demo HOST PORT SESSION_HEX BUILD_HEX [GROUP_MASK]\n"); return 2;
    }
    uint64_t groups = UINT64_MAX;
    if (groups_text) {
        errno = 0; groups = strtoull(groups_text, &end, 0);
        if (errno || !*groups_text || *end || *groups_text == '-') return 2;
    }
    uint64_t session[2] = {pe_get64(session_bytes), pe_get64(session_bytes+8)};
    struct cp_client client;
    int error = cp_init(&client, session, build, groups, 2000);
    if (!error) error = cp_connect(&client, host, (uint16_t)port);
    uint64_t args[4] = {123, 0, 0, 0};
    if (!error) error = cp_emit(&client, 0, 1, 100, PE_BEFORE, args);
    if (!error) {
        /* Substitute the suspect operation ONLY after the BEFORE succeeded. */
        args[1] = args[0] + 1;
        error = cp_emit(&client, 0, 1, 100, PE_AFTER, args);
    }
    if (!error) error = cp_end(&client);
    cp_close(&client);
    if (error) fprintf(stderr, "checkpoint error %d; suspect operation must not proceed\n", error);
    return error ? 1 : 0;
}
