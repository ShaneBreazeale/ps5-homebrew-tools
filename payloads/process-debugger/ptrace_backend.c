/* SPDX-License-Identifier: GPL-3.0-or-later
 * Single-process ptrace provider. No packets, sockets or GDB register layouts.
 * SDK credential helpers remain confined here; no direct PCB writes.
 */
#include "ptrace_backend.h"
#include "inspection.h"
#include "target_memory.h"
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#ifndef PROCESS_DEBUGGER_TEST
#include <sys/syscall.h>
#include <ps5/kernel.h>
#endif
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include "hwbreak.h"

#ifdef PROCESS_DEBUGGER_KERNEL_DBREGS
#error "PROCESS_DEBUGGER_KERNEL_DBREGS was retired; direct PCB writes are not supported"
#endif
#define MAX_THREADS TARGET_MAX_THREADS
#define MAX_MEMORY TARGET_MAX_MEMORY
#define MAX_SWBREAK 64
#define INT3 0xcc

struct thread_state {
    lwpid_t id;
    struct dbreg original, baseline;
    int suspended, stepped;
};
struct swbreak {
    unsigned long long address;
    unsigned char original;
    int used;
};
static struct {
    pid_t pid;
    lwpid_t selected, resume_thread, stopped_thread;
    struct thread_state threads[MAX_THREADS];
    int count, stopped, status, poisoned, memory_poisoned, last_step, step_complete;
    lwpid_t step_thread;
    struct hwbreak bp[4];
    struct swbreak sw[MAX_SWBREAK];
    int hit, sw_hit;
} target;
static uint64_t stop_serial;
static pid_t test_pid;
static volatile unsigned long long test_value;
static volatile int test_done;

#ifndef PROCESS_DEBUGGER_TEST
/* SDK samples/test_privileges uses this authid and all capability bits for
 * raw ptrace. Keep the original credentials until both restorations succeed. */
static uint64_t saved_authid;
static uint8_t saved_caps[16];
static int credentials_dirty;
static int raw_attach_succeeded;
static int restore_credentials(void)
{
    if(!credentials_dirty) return 0;
    pid_t self = getpid();
    int caps = kernel_set_ucred_caps(self, saved_caps);
    int auth = kernel_set_ucred_authid(self, saved_authid);
    if(caps || auth) return -EIO;
    credentials_dirty = 0;
    return 0;
}
#endif
static int call(int request, int id, void* address, int data)
{
#ifdef PROCESS_DEBUGGER_TEST
    int r = ptrace(request, id, address, data);
    return r < 0 ? -errno : r;
#else
    raw_attach_succeeded = 0;
    if(restore_credentials()) return -EIO;
    pid_t self = getpid();
    saved_authid = kernel_get_ucred_authid(self);
    if(!saved_authid || kernel_get_ucred_caps(self, saved_caps)) return -EACCES;
    uint8_t elevated[16];
    for(int i = 0; i < 16; i++) elevated[i] = 0xff;
    credentials_dirty = 1;
    int r = -1, error = EACCES;
    if(!kernel_set_ucred_authid(self, 0x4800000000010003ull) &&
       !kernel_set_ucred_caps(self, elevated)) {
        r = request == -1 ? (int)__syscall(SYS_kill, id, data) :
            (int)__syscall(SYS_ptrace, request, id, address, data);
        error = errno;
        if(request == PT_ATTACH && r == 0) raw_attach_succeeded = 1;
    }
    if(restore_credentials()) return -EIO;
    return r < 0 ? -(error ? error : EIO) : r;
#endif
}
/* PT_SETDBREGS returning success is insufficient: some kernels can sanitize
 * state. Verify addresses and all slot enable/access/length fields, ignoring
 * reserved DR7 bits and stale DR6 status. Callers own rollback on failure. */
static int write_dbregs_checked(int tid, const struct dbreg* desired)
{
    int r = call(PT_SETDBREGS, tid, (void*)desired, 0);
    if(r) return r < 0 ? r : -EIO;
    struct dbreg actual;
    r = call(PT_GETDBREGS, tid, &actual, 0);
    if(r) return r < 0 ? r : -EIO;
    for(int k = 0; k < 4; k++)
        if(actual.dr[k] != desired->dr[k]) return -EIO;
    if((actual.dr[7] ^ desired->dr[7]) & 0xffff00fful) return -EIO;
    return 0;
}
static int signal_process(pid_t pid, int sig)
{
#ifdef PROCESS_DEBUGGER_TEST
    return kill(pid, sig);
#else
    int r = call(-1, pid, 0, sig);
    if(r) { errno = r < 0 ? -r : EPERM; return -1; }
    return 0;
#endif
}
static int thread_index(lwpid_t id)
{
    for(int i = 0; i < target.count; i++) if(target.threads[i].id == id) return i;
    return -1;
}
static int refresh_threads(void)
{
    lwpid_t ids[MAX_THREADS];
    int count = call(PT_GETNUMLWPS, target.pid, 0, 0);
    if(count < 0) return count;
    if(count > MAX_THREADS) return -E2BIG;
    count = call(PT_GETLWPLIST, target.pid, ids, MAX_THREADS);
    if(count <= 0) return count < 0 ? count : -ESRCH;
    /* Retain snapshots for surviving LWPs; discard only exited LWPs. */
    for(int i = 0; i < target.count;) {
        int found = 0;
        for(int j = 0; j < count; j++) if(ids[j] == target.threads[i].id) found = 1;
        if(!found) target.threads[i] = target.threads[--target.count];
        else i++;
    }
    for(int j = 0; j < count; j++) if(thread_index(ids[j]) < 0) {
        if(target.count == MAX_THREADS) return -E2BIG;
        struct thread_state t = {0};
        t.id = ids[j];
        int r = call(PT_GETDBREGS, t.id, &t.original, 0);
        if(r < 0) return r;
        /* New LWPs may inherit our breakpoints. Remove owned fields from their
         * baseline only when they match the installed address/control. */
        for(int k = 0; k < 4; k++) if(target.bp[k].used &&
            t.original.dr[k] == target.bp[k].address &&
            (t.original.dr[7] & hwbreak_mask(k)) == hwbreak_control(&target.bp[k], k)) {
            t.original.dr[k] = 0;
            t.original.dr[7] &= ~hwbreak_mask(k);
        }
        t.baseline = t.original;
        target.threads[target.count++] = t;
    }
    return 0;
}
static int restore_thread_control(void)
{
    int result = 0;
    for(int i = 0; i < target.count; i++) {
        struct thread_state* t = &target.threads[i];
        if(t->stepped) {
            int r = call(PT_CLEARSTEP, t->id, 0, 0);
            if(r < 0) result = r; else t->stepped = 0;
        }
        if(t->suspended) {
            int r = call(PT_RESUME, t->id, 0, 0);
            if(r < 0) result = r; else t->suspended = 0;
        }
    }
    return result;
}
static int apply_breakpoints(void)
{
    /* All-stop transaction: restore every touched thread on failure. */
    struct dbreg before[MAX_THREADS];
    int i, result = 0;
    for(i = 0; i < target.count; i++) {
        struct dbreg next;
        result = call(PT_GETDBREGS, target.threads[i].id, &before[i], 0);
        if(result < 0) break;
        next = target.threads[i].baseline;
        for(int k = 0; k < 4; k++) if(target.bp[k].used) {
            if(next.dr[7] & (3ul << (2*k))) { result = -EBUSY; break; }
            next.dr[k] = target.bp[k].address;
            next.dr[7] &= ~hwbreak_mask(k);
            next.dr[7] |= hwbreak_control(&target.bp[k], k);
        }
        if(result < 0) break;
        next.dr[6] = 0;
        result = write_dbregs_checked(target.threads[i].id, &next);
        if(result < 0) {
            /* A failed syscall may still have touched the current thread. */
            if(write_dbregs_checked(target.threads[i].id, &before[i]) < 0)
                target.poisoned = 1;
            break;
        }
    }
    if(result < 0) while(i-- > 0)
        if(write_dbregs_checked(target.threads[i].id, &before[i]) < 0)
            target.poisoned = 1;
    return result < 0 ? result : 0;
}
static int wait_stop(int interruptible, const struct target_wait* wait)
{
    int interrupted = 0;
    unsigned polls = 0;
    for(;;) {
        int status = 0;
        pid_t r = wait4(target.pid, &status, WNOHANG | WUNTRACED, 0);
        if(!polls) printf("process-debugger: wait pid=%d result=%d status=%x errno=%d\n", target.pid, r, status, errno);
        ++polls;
        if(!interruptible && polls >= 5000) return -ETIMEDOUT;
        if(r < 0) { if(errno == EINTR) continue; return -errno; }
        if(r == target.pid) {
            target.status = status;
            target.step_complete = 0;
            if(WIFEXITED(status) || WIFSIGNALED(status)) {
                if(target.pid == test_pid) test_pid = 0;
                target.pid = 0; target.count = 0; target.stopped = 0;
                return 1;
            }
            if(!WIFSTOPPED(status)) continue;
            target.stopped = 1;
            if(++stop_serial == 0) ++stop_serial;
            struct ptrace_lwpinfo info = {0};
            int e = call(PT_LWPINFO, target.pid, &info, sizeof(info));
            if(e < 0) return e;
            target.stopped_thread = target.selected = info.pl_lwpid;
            if((e = restore_thread_control()) < 0) return e;
            if((e = refresh_threads()) < 0) return e;
            target.hit = -1;
            target.sw_hit = -1;
            if(WSTOPSIG(status) == SIGTRAP) {
                struct dbreg db;
                if((e = call(PT_GETDBREGS, target.stopped_thread, &db, 0)) < 0) return e;
                struct reg event_regs;
                if((e = call(PT_GETREGS, target.stopped_thread, &event_regs, 0)) < 0) return e;
                printf("process-debugger: trap tid=%d code=%d rip=%llx dr6=%lx dr7=%lx\n",
                       target.stopped_thread, info.pl_siginfo.si_code,
                       (unsigned long long)event_regs.r_rip, db.dr[6], db.dr[7]);
                if(!target.last_step && event_regs.r_rip) {
                    unsigned long long at = (unsigned long long)event_regs.r_rip - 1;
                    for(int i = 0; i < MAX_SWBREAK; i++) if(target.sw[i].used &&
                        target.sw[i].address == at) {
                        unsigned char insn = 0;
                        struct ptrace_io_desc io = {PIOD_READ_D, (void*)at, &insn, 1};
                        if((e = call(PT_IO, target.pid, &io, 0)) < 0) return e;
                        if(io.piod_len == 1 && insn == INT3) {
                            event_regs.r_rip = at;
                            if((e = call(PT_SETREGS, target.stopped_thread, &event_regs, 0)) < 0)
                                return e;
                            target.sw_hit = i;
                        }
                        break;
                    }
                }
                if(target.sw_hit < 0) for(int k = 0; k < 4; k++)
                    if((db.dr[6] & (1ul << k)) && target.bp[k].used) {
                        target.hit = k; break;
                    }
            }
            /* PS5 retail PT_GETDBREGS exposes stale DR6 (observed BS set
             * after both stepping and hardware traps). Classify only events
             * that are unambiguous without those status bits. */
            if(target.sw_hit < 0 && target.hit < 0 && WSTOPSIG(status) == SIGTRAP &&
               !target.last_step &&
               (info.pl_flags & PL_FLAG_SI) && info.pl_siginfo.si_code == TRAP_TRACE) {
                struct reg regs;
                if((e = call(PT_GETREGS, target.stopped_thread, &regs, 0)) < 0) return e;
                int data_slot = -1, data_count = 0;
                for(int k = 0; k < 4; k++) if(target.bp[k].used) {
                    if(target.bp[k].type == 1 && target.bp[k].address == (unsigned long long)regs.r_rip)
                        target.hit = k;
                    if(target.bp[k].type != 1) { data_slot = k; data_count++; }
                }
                int index = thread_index(target.stopped_thread);
                if(target.hit < 0 && data_count == 1 && index >= 0 &&
                   !(target.threads[index].baseline.dr[7] & 255)) target.hit = data_slot;
            }
            /* Internal breakpoint step-over may hide only the matching trace
             * completion. Application signals, breakpoint traps and another
             * LWP's stop must be returned to the client without another resume. */
            target.step_complete = target.last_step &&
                target.stopped_thread == target.step_thread &&
                WSTOPSIG(status) == SIGTRAP && (info.pl_flags & PL_FLAG_SI) &&
                info.pl_siginfo.si_code == TRAP_TRACE && target.hit < 0 && target.sw_hit < 0;
            return apply_breakpoints();
        }
        if(interruptible && !interrupted && wait && wait->poll) {
            int event = wait->poll(wait->ctx);
            if(event < 0) return event;
            if(event > 1) return -EINVAL;
            if(event == 1) {
                if(signal_process(target.pid, SIGSTOP) < 0) return -errno;
                interrupted = 1;
            }
        }
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, 0);
    }
}
static int attach_process(unsigned long long pid)
{
    if(target.pid) return -EBUSY;
    if(pid <= 1 || pid > 0x7fffffff || pid == (unsigned)getpid()) return -EINVAL;
#ifndef PROCESS_DEBUGGER_TEST
    printf("process-debugger: attaching pid=%llu\n", pid);
#endif
    int r = call(PT_ATTACH, pid, 0, 0);
#ifndef PROCESS_DEBUGGER_TEST
    printf("process-debugger: PT_ATTACH result=%d\n", r);
#endif
    int attached = r == 0;
#ifndef PROCESS_DEBUGGER_TEST
    attached |= raw_attach_succeeded;
#endif
    if(!attached) return r < 0 ? r : -EPERM;
    __builtin_memset(&target, 0, sizeof(target));
    target.pid = pid; target.hit = -1; target.sw_hit = -1;
    if(r < 0) return r; /* Preserve ownership for cleanup after restoration errors. */
    return wait_stop(0, NULL);
}
static int write_memory_checked(uint64_t, const void*, size_t);
static int detach_process(void)
{
    if(!target.pid) return 0;
    /* Detach resumes execution. A failed memory rollback cannot be repaired by
     * restoring breakpoint bytes/debug registers, so preserve the stopped target. */
    if(target.memory_poisoned) return -EIO;
    int r;
    if(!target.stopped) {
        if(signal_process(target.pid, SIGSTOP) < 0) return -errno;
        r = wait_stop(0, NULL);
        if(r != 0) return r < 0 ? r : 0;
    }
    if((r = restore_thread_control()) < 0) return r;
    for(int i = 0; i < MAX_SWBREAK; i++) if(target.sw[i].used) {
        unsigned char orig = target.sw[i].original;
        r = write_memory_checked(target.sw[i].address, &orig, 1);
        if(r < 0) return r;
        target.sw[i].used = 0;
    }
    for(int i = 0; i < target.count; i++)
        if((r = write_dbregs_checked(target.threads[i].id, &target.threads[i].original)) < 0) return r;
    if((r = call(PT_DETACH, target.pid, (void*)1, 0)) < 0) return r;
    __builtin_memset(&target, 0, sizeof(target));
    return 0;
}
static void from_native(struct target_registers* g, const struct reg* r)
{
#define R(n) g->n = r->r_##n
    R(rax); R(rbx); R(rcx); R(rdx); R(rsi); R(rdi); R(rbp); R(rsp);
    R(r8); R(r9); R(r10); R(r11); R(r12); R(r13); R(r14); R(r15); R(rip);
    R(cs); R(ss); R(ds); R(es); R(fs); R(gs);
#undef R
    g->rflags = r->r_rflags;
}
static void to_native(struct reg* r, const struct target_registers* g)
{
#define R(n) r->r_##n = g->n
    R(rax); R(rbx); R(rcx); R(rdx); R(rsi); R(rdi); R(rbp); R(rsp);
    R(r8); R(r9); R(r10); R(r11); R(r12); R(r13); R(r14); R(r15); R(rip);
    R(cs); R(ss); R(ds); R(es); R(fs); R(gs);
#undef R
    r->r_rflags = g->rflags;
}
static int raw_memory_io(int op, unsigned long long addr, void* buf, size_t n)
{
    if(!target.pid || !target.stopped) return -ESRCH;
    if(n && (addr >= (1ull << 47) || n > (1ull << 47) - addr)) return -EFAULT;
    struct ptrace_io_desc io = {op, (void*)addr, buf, n};
    int r = call(PT_IO, target.pid, &io, 0);
    return r < 0 ? r : io.piod_len == n ? 0 : -EFAULT;
}
/* A rejected syscall can still mutate bytes. Commit only on exact readback;
 * on failure restore the complete prior range and verify it independently of
 * the rollback syscall's return. An unverifiable rollback holds the target. */
static int write_memory_transaction(uint64_t addr, const void* data, size_t n, void* previous)
{
    if(n > MAX_MEMORY) return -EINVAL;
    unsigned char before[MAX_MEMORY], observed[MAX_MEMORY];
    int r = raw_memory_io(PIOD_READ_D, addr, before, n);
    if(r < 0 || !n) return r;
    r = raw_memory_io(PIOD_WRITE_D, addr, (void*)data, n);
    if(!r) {
        r = raw_memory_io(PIOD_READ_D, addr, observed, n);
        if(!r && memcmp(observed, data, n)) r = -EIO;
    }
    if(r < 0) {
        int restored = !raw_memory_io(PIOD_READ_D, addr, observed, n) &&
            !memcmp(observed, before, n);
        if(!restored) {
            (void)raw_memory_io(PIOD_WRITE_D, addr, before, n);
            restored = !raw_memory_io(PIOD_READ_D, addr, observed, n) &&
                !memcmp(observed, before, n);
        }
        if(!restored) target.memory_poisoned = target.poisoned = 1;
    }
    if(!r && previous) memcpy(previous, before, n);
    return r;
}
static int write_memory_checked(uint64_t addr, const void* data, size_t n)
{
    return write_memory_transaction(addr, data, n, NULL);
}
static int plant_int3(unsigned long long addr)
{
    unsigned char insn = INT3;
    return write_memory_checked(addr, &insn, 1);
}
static int sw_index(unsigned long long addr)
{
    for(int i = 0; i < MAX_SWBREAK; i++)
        if(target.sw[i].used && target.sw[i].address == addr) return i;
    return -1;
}
static int memory_io(int op, unsigned long long addr, void* buf, size_t n)
{
    unsigned char* bytes = buf;
    if(n > MAX_MEMORY) return -EINVAL;
    if(n && (addr >= (1ull << 47) || n > (1ull << 47) - addr)) return -EFAULT;
    int overlap = 0;
    for(int i = 0; i < MAX_SWBREAK; i++)
        if(target.sw[i].used && target.sw[i].address >= addr &&
           target.sw[i].address - addr < n) overlap = 1;
    if(op == PIOD_WRITE_D && target.poisoned) return -EIO;
    if(op == PIOD_WRITE_D && overlap) {
        unsigned char desired[MAX_MEMORY];
        __builtin_memcpy(desired, bytes, n);
        /* Keep traps installed throughout the write; shadow bytes are committed
         * only after the entire physical write has been verified. */
        for(int i = 0; i < MAX_SWBREAK; i++)
            if(target.sw[i].used && target.sw[i].address >= addr &&
               target.sw[i].address - addr < n)
                desired[target.sw[i].address - addr] = INT3;
        int r = write_memory_checked(addr, desired, n);
        if(r < 0) return r;
        for(int i = 0; i < MAX_SWBREAK; i++)
            if(target.sw[i].used && target.sw[i].address >= addr &&
               target.sw[i].address - addr < n)
                target.sw[i].original = bytes[target.sw[i].address - addr];
        return 0;
    }
    int r = op == PIOD_WRITE_D ? write_memory_checked(addr, buf, n) : raw_memory_io(op, addr, buf, n);
    if(r < 0) return r;
    if(op == PIOD_READ_D) for(int i = 0; i < MAX_SWBREAK; i++)
        if(target.sw[i].used && target.sw[i].address >= addr &&
           target.sw[i].address - addr < n)
            bytes[target.sw[i].address - addr] = target.sw[i].original;
    return 0;
}
static int sw_breakpoint(int insert, unsigned long long addr, unsigned len)
{
    if(len != 0 && len != 1) return -EINVAL;
    if(addr >= (1ull << 47)) return -EINVAL;
    if(target.poisoned) return -EIO;
    int slot = sw_index(addr);
    if(insert) {
        if(slot >= 0) return 0;
        for(slot = 0; slot < MAX_SWBREAK; slot++) if(!target.sw[slot].used) break;
        if(slot == MAX_SWBREAK) return -ENOSPC;
        unsigned char original = 0, instruction = INT3;
        int r = write_memory_transaction(addr, &instruction, 1, &original);
        if(r < 0) return r;
        target.sw[slot] = (struct swbreak){addr, original, 1};
        return 0;
    }
    if(slot < 0) return 0;
    int r = write_memory_checked(addr, &target.sw[slot].original, 1);
    if(r < 0) { target.poisoned = 1; return r; }
    target.sw[slot].used = 0;
    if(target.sw_hit == slot) target.sw_hit = -1;
    return 0;
}
static int breakpoint(int insert, unsigned type, unsigned long long addr, unsigned len)
{
    if(type == 3 || type > 4) return 1; /* unsupported */
    if(type == 0) return sw_breakpoint(insert, addr, len);
    if(!hwbreak_valid(type, addr, len)) return -EINVAL;
#if !defined(PROCESS_DEBUGGER_TEST)
    /* The retail 13.60 data-watchpoint path did not pass console validation.
     * Never accept a watchpoint that is known not to fire through ptrace. */
    if(type != 1 && (kernel_get_fw_version() & 0xffff0000u) == 0x13600000u)
        return -ENOTSUP;
#endif
    if(target.poisoned) return -EIO;
    int r = refresh_threads();
    if(r < 0) return r;
    int slot = -1;
    for(int k = 0; k < 4; k++) if(target.bp[k].used && target.bp[k].type == type &&
        target.bp[k].address == addr && target.bp[k].length == len) {
        if(insert) return 0; /* Repeated insertion is idempotent. */
        slot = k; break;
    }
    if(!insert && slot < 0) return 0;
    if(insert) for(int k = 0; k < 4; k++) if(!target.bp[k].used) {
        int available = 1;
        for(int i = 0; i < target.count; i++) if(target.threads[i].baseline.dr[7] & (3ul << (2*k))) available = 0;
        if(available) { slot = k; break; }
    }
    if(slot < 0) return -ENOSPC;
    struct hwbreak old = target.bp[slot];
    target.bp[slot] = (struct hwbreak){addr, type, len, insert};
    r = apply_breakpoints();
    if(r < 0) target.bp[slot] = old;
    return r;
}
static int resume_run(int step, lwpid_t tid, int sig, const struct target_wait* wait)
{
    if(target.poisoned) return -EIO;
    int r = refresh_threads();
    if(r < 0) return r;
    if(!tid) tid = target.resume_thread > 0 ? target.resume_thread : target.selected;
    if(thread_index(tid) < 0) return -ESRCH;
    if((r = apply_breakpoints()) < 0) return r;
    for(int i = 0; i < target.count; i++) {
        struct thread_state* t = &target.threads[i];
        if((r = call(PT_CLEARSTEP, t->id, 0, 0)) < 0) goto undo;
        if(step && t->id != tid) {
            if((r = call(PT_SUSPEND, t->id, 0, 0)) < 0) goto undo;
            t->suspended = 1;
        }
    }
    if(step) {
        if((r = call(PT_SETSTEP, tid, 0, 0)) < 0) goto undo;
        target.threads[thread_index(tid)].stepped = 1;
    }
    /* RF permits continuing past a hardware execution breakpoint at RIP. */
    if(target.hit >= 0 && target.bp[target.hit].type == 1) {
        struct reg regs;
        if((r = call(PT_GETREGS, target.stopped_thread, &regs, 0)) < 0) goto undo;
        regs.r_rflags |= 0x10000;
        if((r = call(PT_SETREGS, target.stopped_thread, &regs, 0)) < 0) goto undo;
    }
    if((r = call(PT_CONTINUE, target.pid, (void*)1, sig)) < 0) goto undo;
    target.last_step = step;
    target.step_thread = step ? tid : 0;
    target.step_complete = 0;
    target.stopped = 0;
    return wait_stop(1, wait);
undo:
    if(restore_thread_control() < 0) target.poisoned = 1;
    return r;
}
static int resume_process(int step, lwpid_t tid, int sig, const struct target_wait* wait)
{
    if(target.poisoned) return -EIO;
    if(target.sw_hit >= 0 && target.sw[target.sw_hit].used) {
        int slot = target.sw_hit;
        lwpid_t hit_thread = target.stopped_thread;
        lwpid_t requested = tid ? tid : target.resume_thread > 0 ? target.resume_thread : target.selected;
        unsigned long long addr = target.sw[slot].address;
        struct reg regs;
        int r = call(PT_GETREGS, hit_thread, &regs, 0);
        if(r < 0) return r;
        /* A client may have moved RIP or asked to step another LWP. In either
         * case leave the trap installed and honor that explicit operation. */
        if((unsigned long long)regs.r_rip != addr || (step && requested != hit_thread))
            return resume_run(step, tid, sig, wait);
        unsigned char original = target.sw[slot].original;
        r = write_memory_checked(addr, &original, 1);
        if(r < 0) { target.poisoned = 1; return r; }
        target.sw_hit = -1;
        r = resume_run(1, hit_thread, 0, wait);
        if(r == 1) return r; /* The process exited; there is no byte to replant. */
        if(!target.stopped) { target.poisoned = 1; return r < 0 ? r : -EIO; }
        int planted = plant_int3(addr);
        if(planted < 0) { target.poisoned = 1; return planted; }
        if(r < 0 || step || !target.step_complete) return r;
        return resume_run(0, tid, sig, wait);
    }
    return resume_run(step, tid, sig, wait);
}

__attribute__((noinline)) static void validation_tick(void)
{
    test_value++;
    __asm__ volatile("" ::: "memory");
}
static int spawn_test(const struct target_child_setup* setup)
{
    if(test_pid || target.pid) return -EBUSY;
    pid_t pid = fork();
    if(pid < 0) return -errno;
    if(!pid) {
        if(setup && setup->close_resources) setup->close_resources(setup->ctx);
        for(;;) {
            if(test_done) _exit(0);
            validation_tick();
            struct timespec delay = {0, 1000000};
            nanosleep(&delay, 0);
        }
    }
    test_pid = pid;
    return 0;
}
static int cleanup_test(void)
{
    if(!test_pid) return 0;
    if(target.pid == test_pid) return -EBUSY;
    if(signal_process(test_pid, SIGKILL) < 0 && errno != ESRCH) return -errno;
    for(int poll = 0; poll < 5000; poll++) {
        int status;
        pid_t r = wait4(test_pid, &status, WNOHANG, 0);
        if(r == test_pid || (r < 0 && errno == ECHILD)) { test_pid = 0; return 0; }
        if(r < 0 && errno != EINTR) return -errno;
        struct timespec delay = {0, 1000000}; nanosleep(&delay, 0);
    }
    return -ETIMEDOUT;
}

static int provider_identity(void* ctx, struct target_identity* out)
{
    (void)ctx;
    if(!out) return -EINVAL;
    *out = (struct target_identity){(uint64_t)target.pid, TARGET_USER_PROCESS};
    return 0;
}
static int provider_state(void* ctx, struct target_state* out)
{
    (void)ctx;
    if(!out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    out->stopped = target.stopped;
    out->stop_id = target.stopped ? stop_serial : 0;
    out->poisoned = target.poisoned;
    out->memory_poisoned = target.memory_poisoned;
    out->selected_thread = target.selected;
    out->resume_thread = target.resume_thread;
    out->owned_child_pid = test_pid;
    out->stop.thread = target.stopped_thread;
    if(!target.pid) {
        out->stop.kind = WIFSIGNALED(target.status) ? TARGET_TERMINATED : TARGET_EXITED;
        if(out->stop.kind == TARGET_TERMINATED) out->stop.signal = WTERMSIG(target.status);
        else out->stop.exit_code = WEXITSTATUS(target.status);
    } else {
        out->stop.kind = TARGET_STOP_SIGNAL;
        out->stop.signal = WSTOPSIG(target.status);
        if(target.sw_hit >= 0 && target.sw[target.sw_hit].used) {
            out->stop.breakpoint = TARGET_BREAK_SOFTWARE;
            out->stop.address = target.sw[target.sw_hit].address;
        } else if(target.hit >= 0) {
            const struct hwbreak* bp = &target.bp[target.hit];
            out->stop.breakpoint = bp->type == 1 ? TARGET_BREAK_EXECUTE :
                bp->type == 2 ? TARGET_BREAK_WRITE : TARGET_BREAK_ACCESS;
            out->stop.address = bp->address;
        }
    }
    return 0;
}
static uint32_t backend_firmware(void)
{
#ifdef PROCESS_DEBUGGER_TEST
    return 0x13600000u;
#else
    return kernel_get_fw_version();
#endif
}
static int provider_capabilities(void* ctx, struct target_capabilities* out)
{
    (void)ctx;
    if(!out) return -EINVAL;
    *out = (struct target_capabilities){.firmware = backend_firmware(), .server_pid = getpid(),
        .implemented = TARGET_CAP_VERIFIED_WRITES | TARGET_CAP_PROCESS_INFO | TARGET_CAP_MAP_QUERY |
            TARGET_CAP_MODULE_LOOKUP | TARGET_CAP_SOFTWARE_BREAK | TARGET_CAP_HARDWARE_BREAK |
            TARGET_CAP_READ_RANGES | TARGET_CAP_STOP_ID};
#if defined(PT_GETFSBASE) && defined(PT_GETGSBASE)
    out->implemented |= TARGET_CAP_FS_GS_QUERY;
#endif
#if defined(PT_GETXSTATE_INFO) && defined(PT_GETXSTATE)
    out->implemented |= TARGET_CAP_XSAVE_QUERY;
#endif
    if((out->firmware & 0xffff0000u) != 0x13600000u) {
        out->implemented &= ~(TARGET_CAP_PROCESS_INFO | TARGET_CAP_MAP_QUERY);
        out->implemented |= TARGET_CAP_DATA_WATCH;
    }
    return 0;
}
static int provider_describe(void* ctx, struct target_process_info* out)
{
    (void)ctx;
    if(!target.pid || !target.stopped) return -ESRCH;
    return process_describe(target.pid, out);
}
static int provider_module(void* ctx, const char* name, struct target_module* out)
{
    (void)ctx;
    if(!target.pid || !target.stopped) return -ESRCH;
    return process_module(target.pid, name, out);
}
static int provider_maps(void* ctx, struct target_map* out, size_t capacity, size_t* count)
{
    (void)ctx;
    if(!count) return -EINVAL;
    *count = 0;
    if(!target.pid || !target.stopped) return -ESRCH;
    return process_maps(target.pid, out, capacity, count);
}
static int require_stopped(void)
{
    return target.pid && target.stopped ? 0 : -ESRCH;
}
static int provider_threads(void* ctx, uint64_t* out, size_t capacity, size_t* count)
{
    (void)ctx;
    if(!count || (!out && capacity)) return -EINVAL;
    *count = 0;
    int r = require_stopped();
    if(r < 0 || (r = refresh_threads()) < 0) return r;
    if(capacity < (size_t)target.count) return -ENOSPC;
    for(int i = 0; i < target.count; i++) out[i] = target.threads[i].id;
    *count = target.count;
    return 0;
}
static int provider_select(void* ctx, enum target_thread_role role, uint64_t thread)
{
    (void)ctx;
    if(role != TARGET_REGISTER_THREAD && role != TARGET_RESUME_THREAD) return -EINVAL;
    int r = require_stopped();
    if(r < 0 || (r = refresh_threads()) < 0) return r;
    if(thread > INT_MAX || (thread && thread_index((lwpid_t)thread) < 0)) return -ESRCH;
    if(role == TARGET_REGISTER_THREAD) target.selected = thread ? (lwpid_t)thread : target.stopped_thread;
    else target.resume_thread = (lwpid_t)thread;
    return 0;
}
static int provider_read_memory(void* ctx, uint64_t address, void* out, size_t length)
{
    (void)ctx;
    if(!out && length) return -EINVAL;
    return memory_io(PIOD_READ_D, address, out, length);
}
static int provider_read_ranges(void* ctx, const struct target_memory_range* ranges, size_t count,
        void* data, size_t capacity, struct target_memory_result* results)
{
    int r = require_stopped();
    if(r < 0) return r;
    return target_read_ranges(ctx, provider_read_memory, ranges, count, data, capacity, results);
}
static int provider_write_memory(void* ctx, uint64_t address, const void* data, size_t length)
{
    (void)ctx;
    if(!data && length) return -EINVAL;
    return memory_io(PIOD_WRITE_D, address, (void*)data, length);
}
static int provider_thread(uint64_t thread)
{
    int r = require_stopped();
    if(r < 0) return r;
    if(thread > INT_MAX || thread_index((lwpid_t)thread) < 0) return -ESRCH;
    return 0;
}
static int provider_read_registers(void* ctx, uint64_t thread, struct target_registers* out)
{
    (void)ctx;
    if(!out) return -EINVAL;
    int r = provider_thread(thread);
    if(r < 0) return r;
    struct reg native;
    if((r = call(PT_GETREGS, (int)thread, &native, 0)) < 0) return r;
    memset(out, 0, sizeof(*out));
    from_native(out, &native);
    return 0;
}
static int provider_write_registers(void* ctx, uint64_t thread, const struct target_registers* values)
{
    (void)ctx;
    if(!values) return -EINVAL;
    int r = provider_thread(thread);
    if(r < 0) return r;
    /* Preserve native fields absent from the public core-register snapshot. */
    struct reg native;
    if((r = call(PT_GETREGS, (int)thread, &native, 0)) < 0) return r;
    to_native(&native, values);
    return call(PT_SETREGS, (int)thread, &native, 0);
}
static int provider_read_debug_registers(void* ctx, uint64_t thread, struct target_debug_registers* out)
{
    (void)ctx;
    if(!out) return -EINVAL;
    int r = provider_thread(thread);
    if(r < 0) return r;
    struct dbreg db;
    if((r = call(PT_GETDBREGS, (int)thread, &db, 0)) < 0) return r;
    for(int i = 0; i < 4; i++) out->address[i] = db.dr[i];
    out->status = db.dr[6]; out->control = db.dr[7];
    return 0;
}
static int provider_register_bank(void* ctx, uint64_t thread, enum target_register_bank bank,
        struct target_register_data* out)
{
    (void)ctx;
    if(!out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    int r = provider_thread(thread);
    if(r < 0) return r;
    if(bank == TARGET_REG_FS_GS_BASE) {
#if defined(PT_GETFSBASE) && defined(PT_GETGSBASE)
        uint64_t bases[2] = {0};
        if((r = call(PT_GETFSBASE, (int)thread, &bases[0], 0)) < 0 ||
           (r = call(PT_GETGSBASE, (int)thread, &bases[1], 0)) < 0) return r;
        memcpy(out->bytes, bases, sizeof(bases)); out->length = sizeof(bases);
        return 0;
#else
        return -ENOTSUP;
#endif
    }
    if(bank == TARGET_REG_XSAVE) {
#if defined(PT_GETXSTATE_INFO) && defined(PT_GETXSTATE)
        struct ptrace_xstate_info info = {0};
        if((r = call(PT_GETXSTATE_INFO, (int)thread, &info, sizeof(info))) < 0) return r;
        if(info.xsave_len < 512 || !(info.xsave_mask & 1)) return -EPROTO;
        if(info.xsave_len > sizeof(out->bytes)) return -E2BIG;
        /* Do not use PT_GETFPREGS's firmware-dependent blob size or a PCB
         * fallback. Query the supported size before requesting the image. */
        if((r = call(PT_GETXSTATE, (int)thread, out->bytes, info.xsave_len)) < 0) {
            memset(out, 0, sizeof(*out)); return r;
        }
        out->length = info.xsave_len; out->features = info.xsave_mask;
        return 0;
#else
        return -ENOTSUP;
#endif
    }
    return -ENOTSUP;
}
static int provider_breakpoint(void* ctx, int insert, enum target_break_kind kind, uint64_t address, unsigned length)
{
    (void)ctx;
    int r = require_stopped();
    if(r < 0) return r;
    unsigned internal;
    switch(kind) {
    case TARGET_BREAK_SOFTWARE: internal = 0; break;
    case TARGET_BREAK_EXECUTE: internal = 1; break;
    case TARGET_BREAK_WRITE: internal = 2; break;
    case TARGET_BREAK_READ: internal = 3; break;
    case TARGET_BREAK_ACCESS: internal = 4; break;
    default: return -ENOSYS;
    }
    r = breakpoint(insert, internal, address, length);
    return r == 1 ? -ENOSYS : r;
}
static int provider_attach(void* ctx, uint64_t pid) { (void)ctx; return attach_process(pid); }
static int provider_detach(void* ctx) { (void)ctx; return detach_process(); }
static int provider_resume(void* ctx, enum target_execution action, uint64_t thread, int signal,
        const struct target_wait* wait)
{
    (void)ctx;
    if((action != TARGET_CONTINUE && action != TARGET_STEP) || thread > INT_MAX) return -EINVAL;
    int r = require_stopped();
    if(r < 0) return r;
    return resume_process(action == TARGET_STEP, (lwpid_t)thread, signal, wait);
}
static int provider_terminate(void* ctx)
{
    (void)ctx;
    int r = require_stopped();
    if(r < 0 || (r = call(PT_KILL, target.pid, 0, 0)) < 0) return r;
    target.stopped = 0;
    r = wait_stop(0, NULL);
    return r < 0 ? r : 0;
}
static int provider_spawn_test(void* ctx, const struct target_child_setup* setup, struct target_test_info* out)
{
    (void)ctx;
    if(!out) return -EINVAL;
    int r = spawn_test(setup);
    if(r < 0) return r;
    *out = (struct target_test_info){(uint64_t)test_pid, (uintptr_t)validation_tick,
        (uintptr_t)&test_value, (uintptr_t)&test_done};
    return 0;
}
static int provider_finish_test(void* ctx) { (void)ctx; return cleanup_test(); }
static int provider_lease_test_hardware(void* ctx)
{
    (void)ctx;
    int r = require_stopped();
    if(r < 0) return r;
    if(target.pid != test_pid || target.count != 1) return -EPERM;
    for(int k = 0; k < 4; k++) if(target.bp[k].used) return -EBUSY;
    struct dbreg old = target.threads[0].baseline;
    for(int k = 0; k < 4; k++) {
        target.threads[0].baseline.dr[k] = 0;
        target.threads[0].baseline.dr[7] &= ~hwbreak_mask(k);
    }
    r = apply_breakpoints();
    if(r < 0) target.threads[0].baseline = old;
    return r;
}
static const struct target_ops ptrace_ops = {
    .identity = provider_identity, .capabilities = provider_capabilities,
    .describe = provider_describe, .module = provider_module, .state = provider_state, .maps = provider_maps,
    .threads = provider_threads, .select_thread = provider_select,
    .read_memory = provider_read_memory, .read_memory_ranges = provider_read_ranges, .write_memory = provider_write_memory,
    .read_registers = provider_read_registers, .write_registers = provider_write_registers,
    .read_debug_registers = provider_read_debug_registers, .read_register_bank = provider_register_bank,
    .breakpoint = provider_breakpoint,
    .attach = provider_attach, .detach = provider_detach, .resume = provider_resume,
    .terminate = provider_terminate, .spawn_test = provider_spawn_test,
    .finish_test = provider_finish_test, .lease_test_hardware = provider_lease_test_hardware,
};
struct debug_target *process_debug_target(void)
{
    static struct debug_target backend = {&ptrace_ops, NULL};
    return &backend;
}
int process_backend_restore_credentials(void)
{
#ifdef PROCESS_DEBUGGER_TEST
    return 0;
#else
    return restore_credentials();
#endif
}

