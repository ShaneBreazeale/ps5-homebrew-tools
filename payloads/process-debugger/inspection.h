/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PROCESS_INSPECTION_H
#define PROCESS_INSPECTION_H
#include "target.h"
int process_describe(uint64_t pid, struct target_process_info *);
int process_maps(uint64_t pid, struct target_map *, size_t capacity, size_t *count);
int process_module(uint64_t pid, const char *basename, struct target_module *);
#endif
