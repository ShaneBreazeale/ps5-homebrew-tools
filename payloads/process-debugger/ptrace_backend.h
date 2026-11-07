/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PROCESS_PTRACE_BACKEND_H
#define PROCESS_PTRACE_BACKEND_H
#include "target.h"
/* One provider instance, one attached usermode PID, one serialized controller. */
struct debug_target *process_debug_target(void);
/* Server lifecycle cleanup, including credential failure without an attachment. */
int process_backend_restore_credentials(void);
#endif
