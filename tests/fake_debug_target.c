/* SPDX-License-Identifier: GPL-3.0-or-later
 * An RSP test provider with no ptrace or PS5 ABI dependencies. Assertions check
 * calls across the public boundary, including enum and register translation.
 */
#include "rsp.h"
#include "target_memory.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
struct fake_target {
    struct target_identity identity;
    struct target_state state;
    struct target_registers registers[2];
    unsigned char memory[128];
    int await_interrupt, oversized_list;
};
static int identity(void* ctx, struct target_identity* out)
{
    *out = ((struct fake_target*)ctx)->identity; return 0;
}
static int state(void* ctx, struct target_state* out)
{
    *out = ((struct fake_target*)ctx)->state; return 0;
}
static int capabilities(void* ctx, struct target_capabilities* out)
{
    (void)ctx; *out = (struct target_capabilities){.implemented = TARGET_CAP_PROCESS_INFO |
        TARGET_CAP_MAP_QUERY | TARGET_CAP_MODULE_LOOKUP | TARGET_CAP_FS_GS_QUERY | TARGET_CAP_XSAVE_QUERY |
        TARGET_CAP_READ_RANGES | TARGET_CAP_STOP_ID,
        .firmware = 0x13600000, .server_pid = 66}; return 0;
}
static int describe(void* ctx, struct target_process_info* out)
{
    (void)ctx;
    *out = (struct target_process_info){.pid = 77, .parent_pid = 4, .start_seconds = 1700000000,
        .start_microseconds = 42, .fields = 7, .app_id = 12, .app_type = 1,
        .name = "test$#;", .path = "/app0/test$#.elf", .title_id = "PPSA00001"}; return 0;
}
static int maps(void* ctx, struct target_map* out, size_t capacity, size_t* count)
{
    struct fake_target* t = ctx;
    assert(capacity >= 2);
    out[0] = (struct target_map){.start = 0x400000, .end = 0x404000, .offset = 0,
        .permissions = TARGET_MAP_READ|TARGET_MAP_EXECUTE, .name = "/app0/test$#.elf"};
    out[1] = (struct target_map){.start = 0x404000, .end = 0x408000, .offset = 0x4000,
        .permissions = TARGET_MAP_READ|TARGET_MAP_WRITE, .name = "/app0/test$#.elf"};
    *count = t->oversized_list ? capacity+1 : 2; return 0;
}
static int module(void* ctx, const char* name, struct target_module* out)
{
    (void)ctx;
    if(strcmp(name, "test.sprx")) return -ENOENT;
    *out = (struct target_module){.base = 0x400000, .entry = 0x401000, .handle = 0x42}; return 0;
}
static int read_register_bank(void* ctx, uint64_t thread, enum target_register_bank bank,
    struct target_register_data* out)
{
    (void)ctx; assert(thread == 901 || thread == 902);
    memset(out, 0, sizeof(*out));
    if(bank == TARGET_REG_FS_GS_BASE) {
        uint64_t bases[] = {0x123456789ull, 0xabcdef123ull};
        memcpy(out->bytes, bases, sizeof(bases)); out->length = sizeof(bases);
    } else {
        assert(bank == TARGET_REG_XSAVE);
        out->length = 832; out->features = 7;
        for(size_t i = 0; i < out->length; i++) out->bytes[i] = i;
    }
    return 0;
}
static int attach(void* ctx, uint64_t pid)
{
    struct fake_target* t = ctx;
    if(pid != 77) return -ESRCH;
    if(t->identity.pid) return -EBUSY;
    t->identity = (struct target_identity){77, TARGET_USER_PROCESS};
    t->state = (struct target_state){.stopped = 1, .selected_thread = 901, .stop_id = 1,
        .stop = {.kind = TARGET_STOP_SIGNAL, .signal = SIGSTOP, .thread = 901}};
    return 0;
}
static int detach(void* ctx)
{
    struct fake_target* t = ctx;
    t->identity.pid = 0; t->state.stopped = 0; return 0;
}
static int threads(void* ctx, uint64_t* out, size_t capacity, size_t* count)
{
    struct fake_target* t = ctx;
    assert(capacity >= 2);
    out[0] = 901; out[1] = 902;
    *count = t->oversized_list ? capacity + 1 : 2;
    return 0;
}
static int select_thread(void* ctx, enum target_thread_role role, uint64_t thread)
{
    struct fake_target* t = ctx;
    if(thread && thread != 901 && thread != 902) return -ESRCH;
    if(role == TARGET_REGISTER_THREAD) t->state.selected_thread = thread ? thread : 901;
    else { assert(role == TARGET_RESUME_THREAD); t->state.resume_thread = thread; }
    return 0;
}
static int read_registers(void* ctx, uint64_t thread, struct target_registers* out)
{
    assert(thread == 901 || thread == 902);
    *out = ((struct fake_target*)ctx)->registers[thread == 902]; return 0;
}
static int write_registers(void* ctx, uint64_t thread, const struct target_registers* in)
{
    assert(thread == 901 || thread == 902);
    ((struct fake_target*)ctx)->registers[thread == 902] = *in; return 0;
}
static int read_memory(void* ctx, uint64_t address, void* out, size_t size)
{
    struct fake_target* t = ctx;
    if(address > sizeof(t->memory) || size > sizeof(t->memory)-address) return -EFAULT;
    memcpy(out, t->memory+address, size); return 0;
}
static int read_ranges(void* ctx, const struct target_memory_range* ranges, size_t count,
    void* data, size_t capacity, struct target_memory_result* results)
{
    return target_read_ranges(ctx, read_memory, ranges, count, data, capacity, results);
}
static int write_memory(void* ctx, uint64_t address, const void* in, size_t size)
{
    struct fake_target* t = ctx;
    if(address > sizeof(t->memory) || size > sizeof(t->memory)-address) return -EFAULT;
    memcpy(t->memory+address, in, size); return 0;
}
static int breakpoint(void* ctx, int insert, enum target_break_kind kind, uint64_t address, unsigned size)
{
    struct fake_target* t = ctx;
    assert(address == 0x40 && size == 1);
    if(kind == TARGET_BREAK_READ) return -ENOSYS;
    assert(kind == TARGET_BREAK_SOFTWARE || kind == TARGET_BREAK_EXECUTE ||
        kind == TARGET_BREAK_WRITE || kind == TARGET_BREAK_ACCESS);
    t->state.stop.breakpoint = insert ? kind : TARGET_BREAK_NONE;
    t->state.stop.address = address; return 0;
}
static int resume(void* ctx, enum target_execution action, uint64_t thread, int signal,
    const struct target_wait* wait)
{
    struct fake_target* t = ctx;
    assert(!signal && wait && wait->poll);
    assert(action == TARGET_CONTINUE || action == TARGET_STEP);
    t->state.stopped = 0;
    if(t->await_interrupt) {
        for(int i = 0; i < 2000; i++) {
            int r = wait->poll(wait->ctx);
            if(r < 0) return r;
            if(r == 1) {
                t->state.stop.signal = SIGSTOP; t->state.stopped = 1; t->state.stop_id++; return 0;
            }
            struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL);
        }
        return -ETIMEDOUT;
    }
    if(!thread) thread = t->state.resume_thread ? t->state.resume_thread : 901;
    assert(thread == 901 || thread == 902);
    if(action == TARGET_STEP) t->registers[thread == 902].rip++;
    t->state.stop.thread = t->state.selected_thread = thread;
    t->state.stop.signal = SIGTRAP; t->state.stopped = 1; t->state.stop_id++; return 0;
}
int main(int argc, char** argv)
{
    assert(argc >= 2);
    struct fake_target fake = {0};
    fake.registers[0] = (struct target_registers){.rax = 0x1122334455667788ull,
        .rip = 0x1000, .rsp = 0x20, .rbp = 0x30, .rflags = 0x202, .cs = 0x43, .ss = 0x3b};
    fake.registers[1] = (struct target_registers){.rax = 0x8877665544332211ull, .rip = 0x2000};
    uint64_t frames[] = {0x50, 0x400010, 0, 0x400020};
    memcpy(fake.memory+0x30, frames, 16); memcpy(fake.memory+0x50, frames+2, 16);
    fake.await_interrupt = argc > 2 && !strcmp(argv[2], "wait");
    fake.oversized_list = argc > 2 && !strcmp(argv[2], "oversized");
    /* Only operations used by these sessions need implementations. A real
     * provider supplies the entire table, returning unsupported where needed. */
    const struct target_ops ops = {.identity = identity, .capabilities = capabilities,
        .describe = describe, .maps = maps, .module = module, .read_register_bank = read_register_bank, .state = state,
        .attach = attach, .detach = detach, .threads = threads, .select_thread = select_thread,
        .read_registers = read_registers, .write_registers = write_registers,
        .read_memory = read_memory, .read_memory_ranges = read_ranges, .write_memory = write_memory,
        .breakpoint = breakpoint, .resume = resume};
    struct debug_target target = {&ops, &fake};
    (void)rsp_serve(&target, atoi(argv[1]), -1);
    return 0;
}
