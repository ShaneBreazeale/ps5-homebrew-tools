/* SPDX-License-Identifier: GPL-3.0-or-later
 * Fixed little-endian evidence records. No pointers or native struct wire ABI.
 */
#ifndef PS5_EVIDENCE_H
#define PS5_EVIDENCE_H
#include <stddef.h>
#include <stdint.h>

#define PE_SIZE 288u
#define PE_ACK_SIZE 32u
#define PE_SCHEMA 1u
#define PE_HELLO 1u
#define PE_CHECKPOINT 2u
#define PE_TRACE 3u
#define PE_PANIC 4u
#define PE_END 5u
#define PE_POINT 0u
#define PE_BEFORE 1u
#define PE_AFTER 2u
#define PE_REGISTERS_VALID 1u
#define PE_NO_CPU UINT32_MAX

struct pe_record {
    uint32_t kind, cpu, thread, site, phase, flags, dropped, subject_pid;
    uint64_t session[2], sequence, ticks, arguments[4], registers[18];
    unsigned char build_id[32];
};
static inline void pe_zero(void *p, size_t n) {
    volatile unsigned char *b = (volatile unsigned char *)p;
    for (size_t i = 0; i < n; ++i) b[i] = 0;
}
static inline void pe_put32(unsigned char *p, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(v >> (8*i));
}
static inline void pe_put64(unsigned char *p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(v >> (8*i));
}
static inline uint64_t pe_get64(const unsigned char *p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8*i);
    return v;
}
static inline uint32_t pe_crc32(const unsigned char *p, size_t n) {
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < n; ++i) {
        crc ^= p[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (0u - (crc & 1u)));
    }
    return ~crc;
}
static inline void pe_encode(const struct pe_record *r, unsigned char out[PE_SIZE]) {
    static const unsigned char magic[8] = {'P','S','5','E','V','I','D','1'};
    pe_zero(out, PE_SIZE);
    for (unsigned i = 0; i < 8; ++i) out[i] = magic[i];
    pe_put32(out+8, PE_SCHEMA); pe_put32(out+12, r->kind);
    pe_put64(out+16, r->session[0]); pe_put64(out+24, r->session[1]);
    pe_put64(out+32, r->sequence); pe_put64(out+40, r->ticks);
    pe_put32(out+48, r->cpu); pe_put32(out+52, r->thread);
    pe_put32(out+56, r->site); pe_put32(out+60, r->phase);
    for (unsigned i = 0; i < 32; ++i) out[64+i] = r->build_id[i];
    for (unsigned i = 0; i < 4; ++i) pe_put64(out+96+8*i, r->arguments[i]);
    for (unsigned i = 0; i < 18; ++i) pe_put64(out+128+8*i, r->registers[i]);
    pe_put32(out+272, r->flags); pe_put32(out+276, r->dropped);
    pe_put32(out+280, r->subject_pid);
    pe_put32(out+284, pe_crc32(out, 284));
}
static inline void pe_ack(const struct pe_record *r, unsigned char out[PE_ACK_SIZE]) {
    static const unsigned char magic[8] = {'P','S','5','A','C','K','0','1'};
    for (unsigned i = 0; i < 8; ++i) out[i] = magic[i];
    pe_put64(out+8, r->session[0]); pe_put64(out+16, r->session[1]);
    pe_put64(out+24, r->sequence);
}
#endif
