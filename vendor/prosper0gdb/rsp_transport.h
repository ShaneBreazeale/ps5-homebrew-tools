/* Packet transport adapted from local kstuff-lite/gdb_stub/dbg.c.
 * See docs/debugger-imports.json for source hashes and adaptation details. */
#pragma once
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#define PAGE_SIZE 16384ull
#define MEM_XFER_CHUNK 256

static int hex2int(char c)
{
    if(c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else if(c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else
        return c - '0';
}

static char int2hex(int c)
{
    if(c >= 10)
        return c + 'A' - 10;
    else
        return c + '0';
}

static int gdb_socket, pipe_r, pipe_w;

typedef unsigned char pkt_opaque[1];

static int wait_for_packet(pkt_opaque o)
{
    unsigned char c = 0;
    while(c != '$')
        if(read(gdb_socket, &c, 1) != 1)
            return -1;
    o[0] = 0;
    return 0;
}

static int pkt_getchar(pkt_opaque o)
{
    unsigned char c;
    if(read(gdb_socket, &c, 1) != 1)
        return -1;
    if(c == '#')
    {
        unsigned char cc[2];
        if(read(gdb_socket, cc, 1) != 1 || read(gdb_socket, cc+1, 1) != 1)
            return -1;
        int cs = hex2int(cc[0]) << 4 | hex2int(cc[1]);
        if(cs != o[0])
            return -1;
        unsigned char ack = '+';
        if(write(gdb_socket, &ack, 1) != 1)
            return -1;
        return -2;
    }
    o[0] += c;
    return c;
}

#ifdef PKT_NO_BUFFERING

static int start_packet(pkt_opaque o)
{
    unsigned char c = '$';
    if(write(gdb_socket, &c, 1) != 1)
        return -1;
    o[0] = 0;
    return 0;
}

static int pkt_puts(pkt_opaque o, const unsigned char* s, int l)
{
    const unsigned char* cur = s;
    int ll = l;
    while(ll)
    {
        int chk = write(gdb_socket, cur, ll);
        if(chk <= 0)
            return -1;
        cur += chk;
        ll -= chk;
    }
    for(int i = 0; i < l; i++)
        o[0] += s[i];
    return 0;
}

static int end_packet(pkt_opaque o)
{
    unsigned char c[3] = {'#', int2hex(o[0] >> 4), int2hex(o[0] & 15)};
    if(pkt_puts(o, c, 3))
        return -1;
    unsigned char ack;
    if(read(gdb_socket, &ack, 1) != 1 || ack != '+')
        return -1;
    return 0;
}

#else

static unsigned char* pkt_buf = 0;
static size_t pkt_len = 0;
static size_t pkt_cap = 0;

static int start_packet(pkt_opaque o)
{
    if(!pkt_cap)
    {
        pkt_buf = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if(pkt_buf == MAP_FAILED) { pkt_buf = 0; return -1; }
        pkt_cap = PAGE_SIZE;
    }
    pkt_buf[0] = '$';
    pkt_len = 1;
    o[0] = 0;
    return 0;
}

static int pkt_puts(pkt_opaque o, const unsigned char* s, int l)
{
    size_t pkt_cap_2 = pkt_cap;
    while(pkt_len + l > pkt_cap_2)
        pkt_cap_2 <<= 1;
    if(pkt_cap_2 != pkt_cap)
    {
        unsigned char* pkt_buf_2 = mmap(NULL, pkt_cap_2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if(pkt_buf_2 == MAP_FAILED) return -1;
        for(size_t i = 0; i < pkt_len; i++)
            pkt_buf_2[i] = pkt_buf[i];
        munmap(pkt_buf, pkt_cap);
        pkt_buf = pkt_buf_2;
        pkt_cap = pkt_cap_2;
    }
    for(int i = 0; i < l; i++)
    {
        pkt_buf[pkt_len++] = s[i];
        o[0] += s[i];
    }
    return 0;
}

static int end_packet(pkt_opaque o)
{
    unsigned char c[3] = {'#', int2hex(o[0] >> 4), int2hex(o[0] & 15)};
    if(pkt_puts(o, c, 3))
        return -1;
    unsigned char* p = pkt_buf;
    size_t sz = pkt_len;
    while(sz > 0)
    {
        ssize_t chk = write(gdb_socket, p, sz);
        if(chk <= 0)
            return -1;
        sz -= chk;
        p += chk;
    }
    unsigned char ack;
    if(read(gdb_socket, &ack, 1) != 1 || ack != '+')
        return -1;
    return 0;
}

#endif

#define PKT_PUTS(o, s) pkt_puts(o, s, sizeof(s)-1)
