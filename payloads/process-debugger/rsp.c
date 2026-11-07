/* SPDX-License-Identifier: GPL-3.0-or-later
 * GDB RSP adapter: framing, parsing, register encoding and controller interrupts.
 * All target mutations and inspection go through target_ops.
 */
#include "rsp.h"
#include "target_description.h"
#include "../../vendor/prosper0gdb/rsp_transport.h"
#include "../../vendor/prosper0gdb/trap_state.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef PROCESS_DEBUGGER_BUILD_ID
#define PROCESS_DEBUGGER_BUILD_ID "unrecorded"
#define PROCESS_DEBUGGER_LLVM "unrecorded"
#endif
#define MAX_PACKET 4096
#define MAX_MEMORY TARGET_MAX_MEMORY
#define CORE_REG_BYTES 164
struct rsp_session { struct debug_target* backend; int connection_fd, listener_fd; };
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

static int snapshot(struct rsp_session* s, struct target_identity* identity, struct target_state* state)
{
    int r = s->backend->ops->identity(s->backend->ctx, identity);
    return r < 0 ? r : s->backend->ops->state(s->backend->ctx, state);
}
static int poll_interrupt(void* ctx)
{
    struct rsp_session* s = ctx;
    fd_set set;
    FD_ZERO(&set); FD_SET(s->connection_fd, &set);
    struct timeval tv = {0};
    if(select(s->connection_fd+1, &set, 0, 0, &tv) > 0) {
        unsigned char c;
        int n = recvfrom(s->connection_fd, &c, 1, MSG_PEEK, 0, 0);
        if(n <= 0) return -ECONNRESET;
        if(c != 3) return -EPROTO;
        if(read(s->connection_fd, &c, 1) != 1) return -ECONNRESET;
        return 1;
    }
    return 0;
}
static void close_child_resources(void* ctx)
{
    struct rsp_session* s = ctx;
    close(s->connection_fd);
    if(s->listener_fd >= 0 && s->listener_fd != s->connection_fd) close(s->listener_fd);
}
static int stopped_reply(struct rsp_session* session)
{
    struct target_identity identity;
    struct target_state state;
    int r = snapshot(session, &identity, &state);
    if(r < 0) return error_reply(-r);
    const struct target_stop* stop = &state.stop;
    char b[128];
    if(!identity.pid) {
        b[0] = stop->kind == TARGET_TERMINATED ? 'X' : 'W';
        int v = stop->kind == TARGET_TERMINATED ? stop->signal : stop->exit_code;
        b[1] = int2hex((v >> 4) & 15); b[2] = int2hex(v & 15); b[3] = 0;
        return reply(b);
    }
    int sig = stop->signal;
    /* Native FreeBSD signal numbers are translated only at the wire boundary. */
    if(sig == SIGSTOP) sig = 17;
    else if(sig == SIGBUS) sig = 10;
    b[0] = 'T'; b[1] = int2hex(sig >> 4); b[2] = int2hex(sig & 15);
    char* p = b+3;
    const char* t = "thread:";
    while(*t) *p++ = *t++;
    p = puthex(p, stop->thread); *p++ = ';';
    if(stop->breakpoint == TARGET_BREAK_SOFTWARE) {
        t = "swbreak:;";
        while(*t) *p++ = *t++;
    } else if(stop->breakpoint != TARGET_BREAK_NONE) {
        t = stop->breakpoint == TARGET_BREAK_EXECUTE ? "hwbreak:;" :
            stop->breakpoint == TARGET_BREAK_WRITE ? "watch:" : "awatch:";
        while(*t) *p++ = *t++;
        if(stop->breakpoint != TARGET_BREAK_EXECUTE) { p = puthex(p, stop->address); *p++ = ';'; }
    }
    *p = 0;
    return reply(b);
}
static void target_to_wire(struct regs* g, const struct target_registers* r)
{
#define R(n) g->n = r->n
    R(rax); R(rbx); R(rcx); R(rdx); R(rsi); R(rdi); R(rbp); R(rsp);
    R(r8); R(r9); R(r10); R(r11); R(r12); R(r13); R(r14); R(r15); R(rip);
    R(cs); R(ss); R(ds); R(es); R(fs); R(gs);
#undef R
    g->eflags = r->rflags;
}
static void wire_to_target(struct target_registers* r, const struct regs* g)
{
#define R(n) r->n = g->n
    R(rax); R(rbx); R(rcx); R(rdx); R(rsi); R(rdi); R(rbp); R(rsp);
    R(r8); R(r9); R(r10); R(r11); R(r12); R(r13); R(r14); R(r15); R(rip);
    R(cs); R(ss); R(ds); R(es); R(fs); R(gs);
#undef R
    r->rflags = g->eflags;
}
/* Strings and opaque register images use hex so RSP framing bytes cannot
 * appear in target names/paths. No backend data is treated as a packet. */
static char* putbytes(char* out, const void* data, size_t size)
{
    const unsigned char* bytes = data;
    for(size_t i = 0; i < size; i++) { *out++ = int2hex(bytes[i] >> 4); *out++ = int2hex(bytes[i] & 15); }
    *out = 0; return out;
}
static int getname(const char* packet, char* out, size_t capacity)
{
    size_t n = 0;
    while(*packet) {
        if(!packet[1] || n+1 >= capacity) return -EINVAL;
        unsigned char byte = 0;
        for(int i = 0; i < 2; i++) {
            char c = *packet++;
            if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return -EINVAL;
            byte = (byte << 4) | hex2int(c);
        }
        if(byte < 32 || byte > 126) return -EINVAL;
        out[n++] = byte;
    }
    out[n] = 0; return n ? 0 : -EINVAL;
}
static uint64_t map_fingerprint(const struct target_map* maps, size_t count)
{
    uint64_t hash = 0xcbf29ce484222325ull;
    for(size_t i = 0; i < count; i++) {
        uint64_t values[] = {maps[i].start, maps[i].end, maps[i].offset,
            maps[i].permissions, maps[i].name_truncated};
        for(size_t j = 0; j < sizeof(values)/sizeof(*values); j++)
            for(int b = 0; b < 8; b++) { hash ^= (values[j] >> (8*b)) & 255; hash *= 0x100000001b3ull; }
        for(size_t b = 0; ; b++) { hash ^= (unsigned char)maps[i].name[b]; hash *= 0x100000001b3ull; if(!maps[i].name[b]) break; }
    }
    return hash;
}
/* -1: transport failed, 0: keep serving, 1: explicit clean shutdown. */
static int dispatch(struct rsp_session* session, const char* packet)
{
    const char* p = packet;
    unsigned long long a, b, c;
    int r = 0;
    struct debug_target* backend = session->backend;
    const struct target_ops* ops = backend->ops;
    struct target_identity identity;
    struct target_state state;
    if((r = snapshot(session, &identity, &state)) < 0) return error_reply(-r);
    if(prefix(p, "qSupported")) return reply("PacketSize=1000;qXfer:features:read+;vContSupported+;hwbreak+;swbreak+");
    if(eq(p, "qPS5:capabilities")) {
        struct target_capabilities caps;
        if((r = ops->capabilities(backend->ctx, &caps)) < 0) return error_reply(-r);
        char out[512];
        snprintf(out, sizeof(out), "schema:1;source:%s;llvm:%s;implemented:%llx;firmware:%x;server_pid:%llx;scope:user;hosting:standalone;validation:host;max_memory:%x;max_threads:%x;max_maps:%x;max_regset:%x;max_ranges:%x;dr_slots:4",
            PROCESS_DEBUGGER_BUILD_ID, PROCESS_DEBUGGER_LLVM, (unsigned long long)caps.implemented,
            caps.firmware, (unsigned long long)caps.server_pid, TARGET_MAX_MEMORY,
            TARGET_MAX_THREADS, TARGET_MAX_MAPS, TARGET_MAX_REGISTER_DATA, TARGET_MAX_RANGES);
        return reply(out);
    }
    if(eq(p, "!")) return reply("OK");
    if(eq(p, "vMustReplyEmpty")) return reply("");
    if(eq(p, "qAttached")) return reply(identity.pid ? "1" : "0");
    if(eq(p, "vCont?")) return reply("vCont;c;s");
    if(eq(p, "qPS5:shutdown")) {
        if(identity.pid || state.owned_child_pid) return error_reply(EBUSY);
        return reply("OK") ? -1 : 1;
    }
    if(eq(p, "qPS5:spawn-test")) {
        struct target_test_info info;
        struct target_child_setup child = {close_child_resources, session};
        if((r = ops->spawn_test(backend->ctx, &child, &info)) < 0) return error_reply(-r);
        char out[160], *q = out;
        const char* names[] = {"pid:", ";pc:", ";watch:", ";done:"};
        unsigned long long values[] = {info.pid, info.pc, info.watch, info.done};
        for(int i = 0; i < 4; i++) {
            const char* s = names[i]; while(*s) *q++ = *s++;
            q = puthex(q, values[i]);
        }
        return reply(out);
    }
    if(eq(p, "qPS5:finish-test")) { r = ops->finish_test(backend->ctx); return r < 0 ? error_reply(-r) : reply("OK"); }
    if(prefix(p, "vAttach;")) {
        p += 8;
        if(hexnum(&p, &a) || *p) return error_reply(EINVAL);
        r = ops->attach(backend->ctx, a);
        if(r < 0) return error_reply(-r);
        return stopped_reply(session);
    }
    if(prefix(p, "qXfer:features:read:target.xml:")) {
        p += sizeof("qXfer:features:read:target.xml:")-1;
        if(hexnum(&p, &a) || *p++ != ',' || hexnum(&p, &b) || *p || !b || b > MAX_PACKET-2 || a > sizeof(rsp_target_xml)-1) return error_reply(EINVAL);
        size_t n = sizeof(rsp_target_xml)-1-a;
        if(n > b) n = b;
        pkt_opaque o;
        if(start_packet(o)) return -1;
        if(pkt_puts(o, (const unsigned char*)(a+n == sizeof(rsp_target_xml)-1 ? "l" : "m"), 1) ||
           pkt_puts(o, (const unsigned char*)rsp_target_xml+a, n)) return -1;
        return end_packet(o);
    }
    if(eq(p, "qPS5:state")) {
        char out[320];
        snprintf(out, sizeof(out), "pid:%llx;stopped:%x;stop_id:%llx;selected:%llx;resume:%llx;thread:%llx;kind:%x;signal:%x;exit:%x;break:%x;address:%llx;poisoned:%x;memory_poisoned:%x",
            (unsigned long long)identity.pid, state.stopped, (unsigned long long)state.stop_id,
            (unsigned long long)state.selected_thread, (unsigned long long)state.resume_thread,
            (unsigned long long)state.stop.thread, state.stop.kind, state.stop.signal, state.stop.exit_code,
            state.stop.breakpoint, (unsigned long long)state.stop.address, state.poisoned, state.memory_poisoned);
        return reply(out);
    }
    if(eq(p, "?")) return stopped_reply(session);
    if(!identity.pid || !state.stopped) return error_reply(ESRCH);
    if(prefix(p, "qPS5:readv:")) {
        p += sizeof("qPS5:readv:")-1;
        struct target_memory_range ranges[TARGET_MAX_RANGES];
        struct target_memory_result results[TARGET_MAX_RANGES];
        size_t count = 0, total = 0;
        do {
            if(count == TARGET_MAX_RANGES || hexnum(&p, &a) || *p++ != ',' ||
                hexnum(&p, &b) || !b || b > TARGET_MAX_MEMORY-total) return error_reply(EINVAL);
            ranges[count++] = (struct target_memory_range){a, b}; total += b;
            if(!*p) break;
            if(*p++ != ';' || !*p) return error_reply(EINVAL);
        } while(1);
        unsigned char data[TARGET_MAX_MEMORY];
        if((r = ops->read_memory_ranges(backend->ctx, ranges, count, data, sizeof(data), results)) < 0) return error_reply(-r);
        char out[2*TARGET_MAX_MEMORY+32*TARGET_MAX_RANGES+32];
        int n = snprintf(out, sizeof(out), "count:%zx", count);
        char* q = out+n;
        size_t offset = 0;
        for(size_t i = 0; i < count; i++) {
            const struct target_memory_result* result = results+i;
            if(result->error > 0 || result->error < -255 || result->offset != offset ||
                (result->error ? result->length != 0 : result->length != ranges[i].length)) return error_reply(EPROTO);
            n = snprintf(q, sizeof(out)-(size_t)(q-out), ";%zx:%x,%zx,", i, -result->error, result->length);
            q = putbytes(q+n, data+result->offset, result->length);
            offset += ranges[i].length;
        }
        return reply(out);
    }
    if(eq(p, "qPS5:process")) {
        struct target_process_info info;
        if((r = ops->describe(backend->ctx, &info)) < 0) return error_reply(-r);
        if(!memchr(info.name, 0, sizeof(info.name)) || !memchr(info.path, 0, sizeof(info.path)) ||
            !memchr(info.title_id, 0, sizeof(info.title_id))) return error_reply(EPROTO);
        char out[256+2*(sizeof(info.name)+sizeof(info.path)+sizeof(info.title_id))];
        int n = snprintf(out, sizeof(out), "pid:%llx;ppid:%llx;start_sec:%llx;start_usec:%x;fields:%x;app_id:%x;app_type:%x;name:",
            (unsigned long long)info.pid, (unsigned long long)info.parent_pid,
            (unsigned long long)info.start_seconds, info.start_microseconds, info.fields, info.app_id, info.app_type);
        char* q = putbytes(out+n, info.name, strlen(info.name));
        memcpy(q, ";path:", 6); q = putbytes(q+6, info.path, strlen(info.path));
        memcpy(q, ";title:", 7); putbytes(q+7, info.title_id, strlen(info.title_id));
        return reply(out);
    }
    if(prefix(p, "qPS5:module:")) {
        char name[256]; struct target_module module;
        if(getname(p+12, name, sizeof(name)) < 0) return error_reply(EINVAL);
        if((r = ops->module(backend->ctx, name, &module)) < 0) return error_reply(-r);
        char out[100];
        snprintf(out, sizeof(out), "handle:%x;base:%llx;entry:%llx", module.handle,
            (unsigned long long)module.base, (unsigned long long)module.entry);
        return reply(out);
    }
    if(prefix(p, "qPS5:maps:")) {
        p += 10;
        if(hexnum(&p, &a) || *p || a >= TARGET_MAX_MAPS) return error_reply(EINVAL);
        struct target_map* maps = calloc(TARGET_MAX_MAPS, sizeof(*maps));
        if(!maps) return error_reply(ENOMEM);
        size_t count = 0;
        r = ops->maps(backend->ctx, maps, TARGET_MAX_MAPS, &count);
        if(r >= 0 && count > TARGET_MAX_MAPS) r = -EOVERFLOW;
        for(size_t i = 0; r >= 0 && i < count; i++)
            if(!memchr(maps[i].name, 0, sizeof(maps[i].name))) r = -EPROTO;
        if(r >= 0 && a >= count) r = -EINVAL;
        if(r < 0) { free(maps); return error_reply(-r); }
        const struct target_map* map = maps+a;
        char out[256+2*sizeof(map->name)];
        int n = snprintf(out, sizeof(out), "index:%llx;count:%zx;snapshot:%llx;start:%llx;end:%llx;offset:%llx;permissions:%x;truncated:%x;name:",
            a, count, (unsigned long long)map_fingerprint(maps, count), (unsigned long long)map->start,
            (unsigned long long)map->end, (unsigned long long)map->offset, map->permissions, !!map->name_truncated);
        putbytes(out+n, map->name, strlen(map->name));
        free(maps); return reply(out);
    }
    if(prefix(p, "qPS5:regset:")) {
        p += 12;
        enum target_register_bank bank;
        if(prefix(p, "fsgs:")) { bank = TARGET_REG_FS_GS_BASE; p += 5; }
        else if(prefix(p, "xsave:")) { bank = TARGET_REG_XSAVE; p += 6; }
        else return error_reply(ENOTSUP);
        if(hexnum(&p, &a) || *p++ != ',' || hexnum(&p, &b) || *p || !b || b > MAX_MEMORY) return error_reply(EINVAL);
        struct target_register_data data;
        if((r = ops->read_register_bank(backend->ctx, state.selected_thread, bank, &data)) < 0) return error_reply(-r);
        if(data.length > sizeof(data.bytes) || a > data.length) return error_reply(EPROTO);
        size_t length = data.length-a; if(length > b) length = b;
        char out[100+2*MAX_MEMORY];
        int n = snprintf(out, sizeof(out), "size:%zx;features:%llx;offset:%llx;data:", data.length,
            (unsigned long long)data.features, a);
        putbytes(out+n, data.bytes+a, length);
        return reply(out);
    }
    if(eq(p, "qPS5:test-hardware")) {
        r = ops->lease_test_hardware(backend->ctx);
        return r < 0 ? error_reply(-r) : reply("OK");
    }
    if(eq(p, "qPS5:dbregs")) {
        struct target_debug_registers db;
        if((r = ops->read_debug_registers(backend->ctx, state.selected_thread, &db)) < 0) return error_reply(-r);
        char out[200], *q = out;
        int indices[] = {0, 1, 2, 3, 6, 7};
        uint64_t values[] = {db.address[0], db.address[1], db.address[2], db.address[3], db.status, db.control};
        for(int i = 0; i < 6; i++) {
            if(i) *q++ = ';';
            *q++ = 'd'; *q++ = 'r'; *q++ = '0'+indices[i]; *q++ = ':';
            q = puthex(q, values[i]);
        }
        return reply(out);
    }
    if(prefix(p, "vKill;")) {
        p += 6;
        if(hexnum(&p, &a) || *p || a != (unsigned)identity.pid) return error_reply(EINVAL);
        r = ops->terminate(backend->ctx);
        return r < 0 ? error_reply(-r) : reply("OK");
    }
    if(eq(p, "D") || prefix(p, "D;")) {
        if(p[1]) { p += 2; if(hexnum(&p, &a) || *p || a != (unsigned)identity.pid) return error_reply(EINVAL); }
        r = ops->detach(backend->ctx);
        return r < 0 ? error_reply(-r) : reply("OK");
    }
    if(eq(p, "qC")) {
        char out[32] = "QC"; puthex(out+2, state.selected_thread); return reply(out);
    }
    if(eq(p, "qfThreadInfo")) {
        uint64_t ids[TARGET_MAX_THREADS]; size_t count = 0;
        if((r = ops->threads(backend->ctx, ids, TARGET_MAX_THREADS, &count)) < 0) return error_reply(-r);
        if(count > TARGET_MAX_THREADS) return error_reply(EOVERFLOW);
        char out[TARGET_MAX_THREADS*17+2], *q = out; *q++ = 'm';
        for(size_t i = 0; i < count; i++) {
            if(i) *q++ = ',';
            q = puthex(q, ids[i]);
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
        if(mode == 'H') {
            r = ops->select_thread(backend->ctx, kind == 'g' ? TARGET_REGISTER_THREAD : TARGET_RESUME_THREAD, a);
            if(r < 0) return error_reply(-r);
        } else {
            uint64_t ids[TARGET_MAX_THREADS]; size_t count = 0;
            if((r = ops->threads(backend->ctx, ids, TARGET_MAX_THREADS, &count)) < 0) return error_reply(-r);
            if(count > TARGET_MAX_THREADS) return error_reply(EOVERFLOW);
            int found = !a;
            for(size_t i = 0; i < count; i++) if(ids[i] == a) found = 1;
            if(!found) return error_reply(ESRCH);
        }
        return reply("OK");
    }
    if(*p == 'g' || *p == 'G' || *p == 'p' || *p == 'P') {
        int mode = *p++;
        struct target_registers native;
        struct regs regs = {0};
        if((r = ops->read_registers(backend->ctx, state.selected_thread, &native)) < 0) return error_reply(-r);
        target_to_wire(&regs, &native);
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
        wire_to_target(&native, &regs);
        r = ops->write_registers(backend->ctx, state.selected_thread, &native);
        return r < 0 ? error_reply(-r) : reply("OK");
    }
    if(*p == 'm' || *p == 'M') {
        int mode = *p++;
        if(hexnum(&p, &a) || *p++ != ',' || hexnum(&p, &b) || b > MAX_MEMORY) return error_reply(EINVAL);
        unsigned char bytes[MAX_MEMORY];
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
        r = mode == 'm' ? ops->read_memory(backend->ctx, a, bytes, b) : ops->write_memory(backend->ctx, a, bytes, b);
        if(r < 0) return error_reply(-r);
        if(mode == 'M') return reply("OK");
        for(size_t i = 0; i < b; i++) { out[2*i] = int2hex(bytes[i] >> 4); out[2*i+1] = int2hex(bytes[i] & 15); }
        out[2*b] = 0; return reply(out);
    }
    if(*p == 'Z' || *p == 'z') {
        int insert = *p++ == 'Z';
        if(hexnum(&p, &a) || *p++ != ',' || hexnum(&p, &b) || *p++ != ',' || hexnum(&p, &c) || *p || a > 4 || c > 8) return error_reply(EINVAL);
        enum target_break_kind kinds[] = {TARGET_BREAK_SOFTWARE, TARGET_BREAK_EXECUTE,
            TARGET_BREAK_WRITE, TARGET_BREAK_READ, TARGET_BREAK_ACCESS};
        r = ops->breakpoint(backend->ctx, insert, kinds[a], b, c);
        return r == -ENOSYS ? reply("") : r < 0 ? error_reply(-r) : reply("OK");
    }
    if(*p == 'c' || *p == 's' || prefix(p, "vCont;")) {
        int step; uint64_t tid = 0;
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
                struct target_registers regs;
                if((r = ops->read_registers(backend->ctx, state.selected_thread, &regs)) < 0) return error_reply(-r);
                regs.rip = a;
                if((r = ops->write_registers(backend->ctx, state.selected_thread, &regs)) < 0) return error_reply(-r);
            }
        }
        struct target_wait wait = {poll_interrupt, session};
        r = ops->resume(backend->ctx, step ? TARGET_STEP : TARGET_CONTINUE, tid, 0, &wait);
        if(snapshot(session, &identity, &state) < 0) return -1;
        if(r < 0) {
            if(!state.stopped && identity.pid) return -1; /* clean up before accepting more commands */
            return error_reply(-r);
        }
        return stopped_reply(session);
    }
    return reply("");
}
int rsp_serve(struct debug_target* backend, int connection_fd, int listener_fd)
{
    struct rsp_session session = {backend, connection_fd, listener_fd};
    gdb_socket = connection_fd;
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
        int r = dispatch(&session, packet);
        if(r) return r;
    }
}
