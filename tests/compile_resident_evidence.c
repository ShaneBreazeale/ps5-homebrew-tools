/* SPDX-License-Identifier: GPL-3.0-or-later
 * Freestanding SDK compile check; not an installer, device driver or payload.
 */
#include "../residents/evidence/evidence.h"
int re_fixture_init(struct re_store *s, const uint64_t id[2], const unsigned char build[32]) {
    return re_init(s, id, build, 0xffff, UINT64_MAX, 4096);
}
int re_fixture_trace(struct re_store *s, unsigned cpu, uint64_t now, const uint64_t args[4]) {
    return re_trace(s, cpu, 0, 1, 100, PE_BEFORE, now, args);
}
int re_fixture_trace_context(struct re_store *s, unsigned cpu, uint64_t now,
        const uint64_t args[4], const uint64_t regs[18]) {
    return re_trace_context(s, cpu, 0, 77, 1, 100, PE_POINT, now, args, regs);
}
int re_fixture_panic(struct re_store *s, unsigned cpu, uint64_t now,
        const uint64_t args[4], const uint64_t regs[18]) {
    return re_panic(s, cpu, 77, 1, 200, now, args, regs);
}
int re_fixture_export_init(struct re_export *e, unsigned panic, uint64_t now) {
    return re_export_init(e, panic, RE_MAX_POLLS, now, now+1000);
}
int re_fixture_poll(struct re_store *s, struct re_export *e, uint64_t now, re_try_write write, void *ctx) {
    return re_export_poll(s, e, now, write, ctx);
}
