/* SPDX-License-Identifier: GPL-3.0-or-later
 * Target operations, independent of packets, sockets, ptrace and GDB layouts.
 * Calls are serialized by one controller. Errors are negative native errno;
 * adapters translate them to their own protocol. Output is valid on success.
 * Lists never exceed the caller's capacity; insufficient capacity is -ENOSPC.
 * All methods are required; unsupported operations return -ENOTSUP, except an
 * unsupported breakpoint kind returns -ENOSYS. IDs are numeric, not title IDs.
 */
#ifndef DEBUG_TARGET_H
#define DEBUG_TARGET_H
#include <stdint.h>
#include <stddef.h>

#define TARGET_MAX_THREADS 256
#define TARGET_MAX_MEMORY 1024
#define TARGET_MAX_RANGES 16
#define TARGET_MAX_MAPS 2048
#define TARGET_MAX_REGISTER_DATA 4096
enum target_scope { TARGET_USER_PROCESS = 1, TARGET_KERNEL };
enum target_stop_kind { TARGET_STOP_SIGNAL, TARGET_EXITED, TARGET_TERMINATED };
enum target_break_kind { TARGET_BREAK_NONE, TARGET_BREAK_SOFTWARE,
    TARGET_BREAK_EXECUTE, TARGET_BREAK_WRITE, TARGET_BREAK_ACCESS, TARGET_BREAK_READ };
enum target_thread_role { TARGET_REGISTER_THREAD, TARGET_RESUME_THREAD };
enum target_execution { TARGET_CONTINUE, TARGET_STEP };
enum target_map_permissions { TARGET_MAP_READ = 1, TARGET_MAP_WRITE = 2, TARGET_MAP_EXECUTE = 4 };

struct target_identity { uint64_t pid; enum target_scope scope; };
enum target_info_fields { TARGET_INFO_PROCESS = 1, TARGET_INFO_PATH = 2, TARGET_INFO_APP = 4 };
struct target_process_info {
    uint64_t pid, parent_pid, start_seconds;
    uint32_t start_microseconds, fields, app_id, app_type;
    char name[21], path[1024], title_id[11];
};
struct target_module { uint64_t base, entry; uint32_t handle; };
/* Inspection only. XSAVE is an opaque architecture image with its reported
 * feature mask, not a GDB register file. No extended-register write operation. */
enum target_register_bank { TARGET_REG_FS_GS_BASE, TARGET_REG_XSAVE };
struct target_register_data {
    size_t length;
    uint64_t features;
    unsigned char bytes[TARGET_MAX_REGISTER_DATA];
};
enum target_capability {
    TARGET_CAP_VERIFIED_WRITES = 1ull << 0, TARGET_CAP_PROCESS_INFO = 1ull << 1,
    TARGET_CAP_MAP_QUERY = 1ull << 2, TARGET_CAP_MODULE_LOOKUP = 1ull << 3,
    TARGET_CAP_FS_GS_QUERY = 1ull << 4, TARGET_CAP_XSAVE_QUERY = 1ull << 5,
    TARGET_CAP_SOFTWARE_BREAK = 1ull << 6, TARGET_CAP_HARDWARE_BREAK = 1ull << 7,
    TARGET_CAP_DATA_WATCH = 1ull << 8, TARGET_CAP_READ_RANGES = 1ull << 9,
    TARGET_CAP_STOP_ID = 1ull << 10
};
struct target_capabilities {
    uint64_t implemented;
    uint32_t firmware;
    uint64_t server_pid;
};
struct target_stop {
    enum target_stop_kind kind;
    int signal, exit_code;
    uint64_t thread, address;
    enum target_break_kind breakpoint;
};
struct target_state {
    int stopped, poisoned, memory_poisoned;
    uint64_t stop_id; /* Nonzero, provider-lifetime serial; changes at each stop. */
    uint64_t selected_thread, resume_thread, owned_child_pid;
    struct target_stop stop;
};
struct target_map {
    uint64_t start, end, offset;
    unsigned permissions;
    int name_truncated;
    char name[256];
};
/* Architecture values, not a wire register file or numbering scheme. */
struct target_registers {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15, rip, rflags;
    uint32_t cs, ss, ds, es, fs, gs;
};
struct target_debug_registers { uint64_t address[4], status, control; };
struct target_memory_range { uint64_t address; size_t length; };
/* Each requested slice reserves its full length at offset, including failures.
 * Failed slices are zeroed, error is negative native errno, length is zero. */
struct target_memory_result { size_t offset, length; int error; };
/* 0: no request, 1: interrupt target, negative errno: controller failure.
 * Called synchronously while waiting for execution; must not reenter target
 * operations. A backend never reads the controller's transport itself. */
struct target_wait { int (*poll)(void *); void *ctx; };
struct target_child_setup { void (*close_resources)(void *); void *ctx; };
struct target_test_info { uint64_t pid, pc, watch, done; };

struct target_ops {
    int (*identity)(void *, struct target_identity *);
    int (*capabilities)(void *, struct target_capabilities *);
    int (*describe)(void *, struct target_process_info *);
    int (*module)(void *, const char *basename, struct target_module *);
    int (*state)(void *, struct target_state *);
    int (*maps)(void *, struct target_map *, size_t capacity, size_t *count);
    int (*threads)(void *, uint64_t *, size_t capacity, size_t *count);
    /* Zero selects the stop thread for registers or clears the resume choice. */
    int (*select_thread)(void *, enum target_thread_role, uint64_t);
    int (*read_memory)(void *, uint64_t, void *, size_t);
    int (*read_memory_ranges)(void *, const struct target_memory_range *, size_t count,
        void *data, size_t capacity, struct target_memory_result *);
    int (*write_memory)(void *, uint64_t, const void *, size_t);
    int (*read_registers)(void *, uint64_t thread, struct target_registers *);
    int (*write_registers)(void *, uint64_t thread, const struct target_registers *);
    int (*read_debug_registers)(void *, uint64_t thread, struct target_debug_registers *);
    int (*read_register_bank)(void *, uint64_t thread, enum target_register_bank, struct target_register_data *);
    int (*breakpoint)(void *, int insert, enum target_break_kind, uint64_t, unsigned length);
    int (*attach)(void *, uint64_t pid);
    int (*detach)(void *);
    /* Resume returns 0 at a stop, 1 on exit/termination, or negative errno.
     * State must be inspected after errors: execution/ownership can be changed. */
    int (*resume)(void *, enum target_execution, uint64_t thread, int signal, const struct target_wait *);
    int (*terminate)(void *);
    /* Owned-child diagnostics are backend operations with the same ownership
     * restrictions for every frontend. They are not arbitrary target helpers. */
    int (*spawn_test)(void *, const struct target_child_setup *, struct target_test_info *);
    int (*finish_test)(void *);
    int (*lease_test_hardware)(void *);
};
struct debug_target { const struct target_ops *ops; void *ctx; };
#endif
