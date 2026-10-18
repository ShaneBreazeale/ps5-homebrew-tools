/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A ptrace process backend using the existing stub's packet transport.
 * Usermode debugging only. Kernel access is used by SDK credential helpers;
 * debug-register state is managed through ptrace, never direct PCB writes.
 */
#include "../../vendor/prosper0gdb/rsp_transport.h"
#include "../../vendor/prosper0gdb/trap_state.h"
#include <signal.h>
#include <stdio.h>
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

#define MAX_THREADS 256
#define MAX_PACKET 4096
#define CORE_REG_BYTES 164
#ifndef PROCESS_DEBUG_PORT
#define PROCESS_DEBUG_PORT 1234
#endif

struct thread_state {
    lwpid_t id;
    struct dbreg original, baseline;
    int suspended, stepped;
};
static struct {
    pid_t pid;
    lwpid_t selected, resume_thread, stopped_thread;
    struct thread_state threads[MAX_THREADS];
    int count, stopped, status, poisoned, last_step;
    struct hwbreak bp[4];
    int hit;
} target;
static pid_t test_pid;
static int shutting_down;
static int listener_fd = -1;
static volatile unsigned long long test_value;
static volatile int test_done;

static int eq(const char* a, const char* b)
{
    while(*a && *a == *b) { a++; b++; }
    return *a == *b;
}
static int prefix(const char* a, const char* b)
{
    while(*b) if(*a++ != *b++) return 0;
    return 1;
}
static int hexnum(const char** p, unsigned long long* value)
{
    int n = 0;
    *value = 0;
    while((**p >= '0' && **p <= '9') || (**p >= 'a' && **p <= 'f') || (**p >= 'A' && **p <= 'F')) {
        if(++n > 16) return -1;
        *value = (*value << 4) | hex2int(*(*p)++);
    }
    return n ? 0 : -1;
}
static char* puthex(char* p, unsigned long long v)
{
    int shift = 60;
    while(shift && !(v >> shift)) shift -= 4;
    for(; shift >= 0; shift -= 4) *p++ = int2hex((v >> shift) & 15);
    *p = 0;
    return p;
}
static int reply(const char* s)
{
    pkt_opaque o;
    int n = 0;
    while(s[n]) n++;
    if(start_packet(o) || pkt_puts(o, (const unsigned char*)s, n)) return -1;
    return end_packet(o);
}
static int error_reply(int e)
{
    char b[4] = {'E', int2hex((e >> 4) & 15), int2hex(e & 15), 0};
    return reply(b);
}
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
static int wait_stop(int interruptible)
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
            if(WIFEXITED(status) || WIFSIGNALED(status)) {
                if(target.pid == test_pid) test_pid = 0;
                target.pid = 0; target.count = 0; target.stopped = 0;
                return 1;
            }
            if(!WIFSTOPPED(status)) continue;
            target.stopped = 1;
            struct ptrace_lwpinfo info = {0};
            int e = call(PT_LWPINFO, target.pid, &info, sizeof(info));
            if(e < 0) return e;
            target.stopped_thread = target.selected = info.pl_lwpid;
            if((e = restore_thread_control()) < 0) return e;
            if((e = refresh_threads()) < 0) return e;
            target.hit = -1;
            if(WSTOPSIG(status) == SIGTRAP) {
                struct dbreg db;
                if((e = call(PT_GETDBREGS, target.stopped_thread, &db, 0)) < 0) return e;
                struct reg event_regs;
                if((e = call(PT_GETREGS, target.stopped_thread, &event_regs, 0)) < 0) return e;
                printf("process-debugger: trap tid=%d code=%d rip=%llx dr6=%lx dr7=%lx\n",
                       target.stopped_thread, info.pl_siginfo.si_code,
                       (unsigned long long)event_regs.r_rip, db.dr[6], db.dr[7]);
                for(int k = 0; k < 4; k++) if((db.dr[6] & (1ul << k)) && target.bp[k].used) {
                    target.hit = k; break;
                }
            }
            /* PS5 retail PT_GETDBREGS exposes stale DR6 (observed BS set
             * after both stepping and hardware traps). Classify only events
             * that are unambiguous without those status bits. */
            if(target.hit < 0 && WSTOPSIG(status) == SIGTRAP && !target.last_step &&
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
            return apply_breakpoints();
        }
        if(interruptible && !interrupted) {
            fd_set set;
            FD_ZERO(&set); FD_SET(gdb_socket, &set);
            struct timeval tv = {0};
            if(select(gdb_socket+1, &set, 0, 0, &tv) > 0) {
                unsigned char c;
                int n = recvfrom(gdb_socket, &c, 1, MSG_PEEK, 0, 0);
                if(n <= 0) return -ECONNRESET;
                if(c != 3) return -EPROTO;
                if(read(gdb_socket, &c, 1) != 1) return -ECONNRESET;
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
    target.pid = pid; target.hit = -1;
    if(r < 0) return r; /* Preserve ownership for cleanup after restoration errors. */
    return wait_stop(0);
}
static int detach_process(void)
{
    if(!target.pid) return 0;
    int r;
    if(!target.stopped) {
        if(signal_process(target.pid, SIGSTOP) < 0) return -errno;
        r = wait_stop(0);
        if(r != 0) return r < 0 ? r : 0;
    }
    if((r = restore_thread_control()) < 0) return r;
    for(int i = 0; i < target.count; i++)
        if((r = write_dbregs_checked(target.threads[i].id, &target.threads[i].original)) < 0) return r;
    if((r = call(PT_DETACH, target.pid, (void*)1, 0)) < 0) return r;
    __builtin_memset(&target, 0, sizeof(target));
    return 0;
}
static int stopped_reply(void)
{
    char b[128];
    if(!target.pid) {
        int status = target.status;
        b[0] = WIFSIGNALED(status) ? 'X' : 'W';
        int v = WIFSIGNALED(status) ? WTERMSIG(status) : WEXITSTATUS(status);
        b[1] = int2hex((v >> 4) & 15); b[2] = int2hex(v & 15); b[3] = 0;
        return reply(b);
    }
    int sig = WSTOPSIG(target.status);
    /* FreeBSD SIGSTOP/SIGBUS differ from the GDB wire signal numbering. */
    if(sig == SIGSTOP) sig = 17;
    else if(sig == SIGBUS) sig = 10;
    b[0] = 'T'; b[1] = int2hex(sig >> 4); b[2] = int2hex(sig & 15);
    char* p = b+3;
    const char* t = "thread:";
    while(*t) *p++ = *t++;
    p = puthex(p, target.stopped_thread); *p++ = ';';
    if(target.hit >= 0) {
        struct hwbreak* bp = &target.bp[target.hit];
        t = bp->type == 1 ? "hwbreak:;" : bp->type == 2 ? "watch:" : "awatch:";
        while(*t) *p++ = *t++;
        if(bp->type != 1) { p = puthex(p, bp->address); *p++ = ';'; }
    }
    *p = 0;
    return reply(b);
}
static void from_native(struct regs* g, const struct reg* r)
{
#define R(n) g->n = r->r_##n
    R(rax); R(rbx); R(rcx); R(rdx); R(rsi); R(rdi); R(rbp); R(rsp);
    R(r8); R(r9); R(r10); R(r11); R(r12); R(r13); R(r14); R(r15); R(rip);
    R(cs); R(ss); R(ds); R(es); R(fs); R(gs);
#undef R
    g->eflags = r->r_rflags;
}
static void to_native(struct reg* r, const struct regs* g)
{
#define R(n) r->r_##n = g->n
    R(rax); R(rbx); R(rcx); R(rdx); R(rsi); R(rdi); R(rbp); R(rsp);
    R(r8); R(r9); R(r10); R(r11); R(r12); R(r13); R(r14); R(r15); R(rip);
    R(cs); R(ss); R(ds); R(es); R(fs); R(gs);
#undef R
    r->r_rflags = g->eflags;
}
static int memory_io(int op, unsigned long long addr, void* buf, size_t n)
{
    if(!target.pid || !target.stopped) return -ESRCH;
    if(n && (addr >= (1ull << 47) || n > (1ull << 47) - addr)) return -EFAULT;
    struct ptrace_io_desc io = {op, (void*)addr, buf, n};
    int r = call(PT_IO, target.pid, &io, 0);
    return r < 0 ? r : io.piod_len == n ? 0 : -EFAULT;
}
static int breakpoint(int insert, unsigned type, unsigned long long addr, unsigned len)
{
    if(type == 0 || type == 3 || type > 4) return 1; /* unsupported */
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
        if(insert) return 0; /* Z packets are idempotent. */
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
static int resume_process(int step, lwpid_t tid, int sig)
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
    target.stopped = 0;
    return wait_stop(1);
undo:
    if(restore_thread_control() < 0) target.poisoned = 1;
    return r;
}

__attribute__((noinline)) static void validation_tick(void)
{
    test_value++;
    __asm__ volatile("" ::: "memory");
}
static int spawn_test(void)
{
    if(test_pid || target.pid) return -EBUSY;
    pid_t pid = fork();
    if(pid < 0) return -errno;
    if(!pid) {
        close(gdb_socket);
        if(listener_fd >= 0) close(listener_fd);
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

/* Returns -1 on disconnected transport, 0 to keep serving, 1 to close cleanly. */
static int dispatch(const char* packet)
{
    const char* p = packet;
    unsigned long long a, b, c;
    int r = 0;
    if(prefix(p, "qSupported")) return reply("PacketSize=1000;qXfer:features:read+;vContSupported+;hwbreak+");
    if(eq(p, "!")) return reply("OK");
    if(eq(p, "vMustReplyEmpty")) return reply("");
    if(eq(p, "qAttached")) return reply(target.pid ? "1" : "0");
    if(eq(p, "vCont?")) return reply("vCont;c;s");
    if(eq(p, "qPS5:shutdown")) {
        if(target.pid || test_pid) return error_reply(EBUSY);
        shutting_down = 1;
        return reply("OK") ? -1 : 1;
    }
    if(eq(p, "qPS5:spawn-test")) {
        if((r = spawn_test()) < 0) return error_reply(-r);
        char out[160], *q = out;
        const char* names[] = {"pid:", ";pc:", ";watch:", ";done:"};
        unsigned long long values[] = {test_pid, (unsigned long long)validation_tick,
            (unsigned long long)&test_value, (unsigned long long)&test_done};
        for(int i = 0; i < 4; i++) {
            const char* s = names[i]; while(*s) *q++ = *s++;
            q = puthex(q, values[i]);
        }
        return reply(out);
    }
    if(eq(p, "qPS5:finish-test")) { r = cleanup_test(); return r < 0 ? error_reply(-r) : reply("OK"); }
    if(prefix(p, "vAttach;")) {
        p += 8;
        if(hexnum(&p, &a) || *p) return error_reply(EINVAL);
        r = attach_process(a);
        if(r < 0) return error_reply(-r);
        return stopped_reply();
    }
    if(prefix(p, "qXfer:features:read:target.xml:")) {
        static const char xml[] = "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\"><target><architecture>i386:x86-64</architecture><osabi>FreeBSD</osabi></target>";
        p += sizeof("qXfer:features:read:target.xml:")-1;
        if(hexnum(&p, &a) || *p++ != ',' || hexnum(&p, &b) || *p || !b || b > MAX_PACKET-2 || a > sizeof(xml)-1) return error_reply(EINVAL);
        size_t n = sizeof(xml)-1-a;
        if(n > b) n = b;
        pkt_opaque o;
        if(start_packet(o)) return -1;
        if(pkt_puts(o, (const unsigned char*)(a+n == sizeof(xml)-1 ? "l" : "m"), 1) ||
           pkt_puts(o, (const unsigned char*)xml+a, n)) return -1;
        return end_packet(o);
    }
    if(eq(p, "?")) return stopped_reply();
    if(!target.pid || !target.stopped) return error_reply(ESRCH);
    if(eq(p, "qPS5:test-hardware")) {
        /* Only our disposable child may borrow occupied slots. Arbitrary
         * targets preserve other owners' debug-register allocations. */
        if(target.pid != test_pid || target.count != 1) return error_reply(EPERM);
        for(int k = 0; k < 4; k++) if(target.bp[k].used) return error_reply(EBUSY);
        struct dbreg old = target.threads[0].baseline;
        for(int k = 0; k < 4; k++) {
            target.threads[0].baseline.dr[k] = 0;
            target.threads[0].baseline.dr[7] &= ~hwbreak_mask(k);
        }
        r = apply_breakpoints();
        if(r < 0) target.threads[0].baseline = old;
        return r < 0 ? error_reply(-r) : reply("OK");
    }
    if(eq(p, "qPS5:dbregs")) {
        struct dbreg db;
        if((r = call(PT_GETDBREGS, target.selected, &db, 0)) < 0) return error_reply(-r);
        char out[200], *q = out;
        int indices[] = {0, 1, 2, 3, 6, 7};
        for(int i = 0; i < 6; i++) {
            if(i) *q++ = ';';
            *q++ = 'd'; *q++ = 'r'; *q++ = '0'+indices[i]; *q++ = ':';
            q = puthex(q, db.dr[indices[i]]);
        }
        return reply(out);
    }
    if(prefix(p, "vKill;")) {
        p += 6;
        if(hexnum(&p, &a) || *p || a != (unsigned)target.pid) return error_reply(EINVAL);
        r = call(PT_KILL, target.pid, 0, 0);
        if(r < 0) return error_reply(-r);
        target.stopped = 0;
        r = wait_stop(0);
        return r < 0 ? error_reply(-r) : reply("OK");
    }
    if(eq(p, "D") || prefix(p, "D;")) {
        if(p[1]) { p += 2; if(hexnum(&p, &a) || *p || a != (unsigned)target.pid) return error_reply(EINVAL); }
        r = detach_process();
        return r < 0 ? error_reply(-r) : reply("OK");
    }
    if(eq(p, "qC")) {
        char out[32] = "QC"; puthex(out+2, target.selected); return reply(out);
    }
    if(eq(p, "qfThreadInfo")) {
        if((r = refresh_threads()) < 0) return error_reply(-r);
        char out[MAX_THREADS*9+2], *q = out; *q++ = 'm';
        for(int i = 0; i < target.count; i++) {
            if(i) *q++ = ',';
            q = puthex(q, target.threads[i].id);
        }
        return reply(out);
    }
    if(eq(p, "qsThreadInfo")) return reply("l");
    if(*p == 'T' || *p == 'H') {
        int mode = *p++;
        int kind = mode == 'H' ? *p++ : 0;
        if(kind && kind != 'g' && kind != 'c') return reply("");
        if(eq(p, "-1")) a = 0;
        else if(hexnum(&p, &a) || *p || a > 0x7fffffff) return error_reply(EINVAL);
        if((r = refresh_threads()) < 0) return error_reply(-r);
        if(a && thread_index(a) < 0) return error_reply(ESRCH);
        if(mode == 'H') {
            if(kind == 'g') target.selected = a ? a : target.stopped_thread;
            else target.resume_thread = a;
        }
        return reply("OK");
    }
    if(*p == 'g' || *p == 'G' || *p == 'p' || *p == 'P') {
        int mode = *p++;
        struct reg native;
        struct regs regs = {0};
        if((r = call(PT_GETREGS, target.selected, &native, 0)) < 0) return error_reply(-r);
        from_native(&regs, &native);
        unsigned char* bytes = (unsigned char*)&regs;
        int offset = 0, count = CORE_REG_BYTES;
        if(mode == 'p' || mode == 'P') {
            if(hexnum(&p, &a) || a > 23) return reply("");
            offset = a < 17 ? a*8 : 136+(a-17)*4;
            count = a < 17 ? 8 : 4;
        }
        if(mode == 'g' || mode == 'p') {
            if(*p) return error_reply(EINVAL);
            char out[1121];
            for(int i = 0; i < count; i++) {
                out[2*i] = int2hex(bytes[offset+i] >> 4);
                out[2*i+1] = int2hex(bytes[offset+i] & 15);
            }
            int n = count*2;
            if(mode == 'g') while(n < 1120) out[n++] = 'x';
            out[n] = 0;
            return reply(out);
        }
        if(mode == 'P' && *p++ != '=') return error_reply(EINVAL);
        for(int i = 0; i < count; i++) {
            for(int k = 0; k < 2; k++) {
                char ch = *p;
                if(!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) return error_reply(EINVAL);
                if(k == 0) bytes[offset+i] = hex2int(ch) << 4;
                else bytes[offset+i] |= hex2int(ch);
                p++;
            }
        }
        if(mode == 'G') {
            /* Ignore only unavailable FP/vector fields returned as x by g. */
            for(int i = CORE_REG_BYTES*2; i < 1120; i++) if(*p++ != 'x') return error_reply(EINVAL);
        }
        if(*p) return error_reply(EINVAL);
        to_native(&native, &regs);
        r = call(PT_SETREGS, target.selected, &native, 0);
        return r < 0 ? error_reply(-r) : reply("OK");
    }
    if(*p == 'm' || *p == 'M') {
        int mode = *p++;
        if(hexnum(&p, &a) || *p++ != ',' || hexnum(&p, &b) || b > 1024) return error_reply(EINVAL);
        unsigned char bytes[1024];
        char out[2049];
        if(mode == 'M') {
            if(*p++ != ':') return error_reply(EINVAL);
            for(size_t i = 0; i < b; i++) for(int k = 0; k < 2; k++) {
                char ch = *p;
                if(!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                     (ch >= 'A' && ch <= 'F'))) return error_reply(EINVAL);
                if(!k) bytes[i] = hex2int(*p) << 4; else bytes[i] |= hex2int(*p);
                p++;
            }
        }
        if(*p) return error_reply(EINVAL);
        r = memory_io(mode == 'm' ? PIOD_READ_D : PIOD_WRITE_D, a, bytes, b);
        if(r < 0) return error_reply(-r);
        if(mode == 'M') return reply("OK");
        for(size_t i = 0; i < b; i++) { out[2*i] = int2hex(bytes[i] >> 4); out[2*i+1] = int2hex(bytes[i] & 15); }
        out[2*b] = 0; return reply(out);
    }
    if(*p == 'Z' || *p == 'z') {
        int insert = *p++ == 'Z';
        if(hexnum(&p, &a) || *p++ != ',' || hexnum(&p, &b) || *p++ != ',' || hexnum(&p, &c) || *p || a > 4 || c > 8) return error_reply(EINVAL);
        r = breakpoint(insert, a, b, c);
        return r < 0 ? error_reply(-r) : reply(r ? "" : "OK");
    }
    if(*p == 'c' || *p == 's' || prefix(p, "vCont;")) {
        int step; lwpid_t tid = 0;
        if(prefix(p, "vCont;")) {
            p += 6; step = *p == 's';
            if(*p != 'c' && *p != 's') return error_reply(EINVAL);
            p++;
            if(*p == ':') {
                p++;
                if(eq(p, "-1")) p += 2;
                else { if(hexnum(&p, &a) || a > 0x7fffffff) return error_reply(EINVAL); tid = a; }
            }
            if(*p) return error_reply(EINVAL);
        } else {
            step = *p++ == 's';
            if(*p) {
                if(hexnum(&p, &a) || *p) return error_reply(EINVAL);
                struct reg regs;
                if((r = call(PT_GETREGS, target.selected, &regs, 0)) < 0) return error_reply(-r);
                regs.r_rip = a;
                if((r = call(PT_SETREGS, target.selected, &regs, 0)) < 0) return error_reply(-r);
            }
        }
        r = resume_process(step, tid, 0);
        if(r < 0) {
            if(!target.stopped && target.pid) return -1; /* clean up before accepting more commands */
            return error_reply(-r);
        }
        return stopped_reply();
    }
    return reply("");
}
static int serve(void)
{
    char packet[MAX_PACKET+1];
    for(;;) {
        pkt_opaque o;
        if(wait_for_packet(o)) return -1;
        int n = 0, c;
        while((c = pkt_getchar(o)) >= 0) {
            if(n == MAX_PACKET) return -1;
            /* Only ASCII commands are supported; never accept embedded NUL. */
            if(!c || c > 127) return -1;
            packet[n++] = c;
        }
        if(c != -2) return -1;
        packet[n] = 0;
        int r = dispatch(packet);
        if(r) return r;
    }
}
#ifndef PROCESS_DEBUGGER_TEST
int main(void)
{
    setvbuf(stdout, 0, _IONBF, 0);
    struct sigaction ignore = {.sa_handler = SIG_IGN};
    sigaction(SIGPIPE, &ignore, 0);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    listener_fd = listener;
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
        gdb_socket = accept(listener, 0, 0);
        if(gdb_socket < 0) { if(errno == EINTR) continue; break; }
        int nodelay = 1;
        setsockopt(gdb_socket, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
        serve();
        /* On disconnect, keep the server alive until detach succeeds. Exiting
         * while attached could kill the target on FreeBSD-derived kernels. */
        while(target.pid && detach_process() < 0) {
            const char failed[] = "process-debugger: detach failed; retrying without exiting\n";
            write(1, failed, sizeof(failed)-1);
            struct timespec delay = {1, 0}; nanosleep(&delay, 0);
        }
#ifndef PROCESS_DEBUGGER_TEST
        while(restore_credentials()) {
            const char failed[] = "process-debugger: credential restore failed; retrying\n";
            write(1, failed, sizeof(failed)-1);
            struct timespec delay = {1, 0}; nanosleep(&delay, 0);
        }
#endif
        close(gdb_socket);
        if(shutting_down) break;
    }
    cleanup_test();
    close(listener);
    return 0;
}
#endif
