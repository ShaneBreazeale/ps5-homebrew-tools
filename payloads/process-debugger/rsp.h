/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PROCESS_RSP_H
#define PROCESS_RSP_H
#include "target.h"
/* -1: transport failure/disconnect, 1: explicit clean server shutdown.
 * The caller owns descriptors and must detach/restore after either outcome. */
int rsp_serve(struct debug_target *, int connection_fd, int listener_fd);
#endif
