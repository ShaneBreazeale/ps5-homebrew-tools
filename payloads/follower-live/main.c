#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "freebsd/sys/ioccom.h"
#include "uelf/shared_area.h"
#include "uelf/fself.h"
#include "uelf/syscall_fixes.h"

#define KEKCALL_SHARED_AREA_SNAPSHOT 0x600000027
#define KEKCALL_CHECK                0xffffffff00000027

static char g_stdout_buf[8192];

static int64_t kekcall(uint64_t a, uint64_t b, uint64_t c,
                       uint64_t d, uint64_t e, uint64_t f, uint64_t g)
{
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    uint64_t ret;
    unsigned char is_error;

    __asm__ __volatile__(
        "syscall"
        : "=a"(ret), "=@ccc"(is_error), "+r"(r10), "+r"(r8), "+r"(r9)
        : "a"(g), "D"(a), "S"(b), "d"(c)
        : "rcx", "r11", "memory");

    return is_error ? -(int64_t)ret : (int64_t)ret;
}


static void tee_printf(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

static void tee_errprintf(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void tee_putc(int ch)
{
    fputc(ch, stdout);
}

static void tee_write(const void* ptr, size_t size)
{
    fwrite(ptr, 1, size, stdout);
}

static void tee_flush(void)
{
    fflush(stdout);
    fflush(stderr);
}

static int snapshot_shared_area(struct kstuff_snapshot* snapshot)
{
    memset(snapshot, 0, sizeof(*snapshot));
    return (int)kekcall((uint64_t)(uintptr_t)snapshot, sizeof(*snapshot), 0, 0, 0, 0, KEKCALL_SHARED_AREA_SNAPSHOT);
}


static void print_new_word_log(const struct kstuff_snapshot* snapshot, uint64_t* last_seq)
{
    uint64_t cur = snapshot->word_log.next_seq;
    uint64_t start = *last_seq;

    if(cur - start > SHARED_LOG_WORD_CAP)
        start = cur - SHARED_LOG_WORD_CAP;

    for(uint64_t seq = start; seq < cur; seq++)
    {
        const struct kstuff_word_log_entry* entry = &snapshot->word_log.entries[seq % SHARED_LOG_WORD_CAP];
        if(entry->seq != seq + 1)
            continue;
        tee_printf("log-word[%" PRIu64 "]=0x%016" PRIx64 "\n", seq, entry->word);
    }

    *last_seq = cur;
}

static void print_new_msg_log(const struct kstuff_snapshot* snapshot, uint64_t* last_seq)
{
    uint64_t cur = snapshot->msg_log.next_seq;
    uint64_t start = *last_seq;

    if(cur - start > SHARED_LOG_MSG_CAP)
        start = cur - SHARED_LOG_MSG_CAP;
    if(start == cur)
        return;

    tee_printf("log-msg: ");
    while(start < cur)
    {
        size_t off = start % SHARED_LOG_MSG_CAP;
        size_t chunk = SHARED_LOG_MSG_CAP - off;
        if(chunk > cur - start)
            chunk = (size_t)(cur - start);
        tee_write(snapshot->msg_log.bytes + off, chunk);
        start += chunk;
    }

    if(snapshot->msg_log.bytes[(cur - 1) % SHARED_LOG_MSG_CAP] != '\n')
        tee_putc('\n');

    *last_seq = cur;
}


#define KEKCALL_KREAD 0x800000027

static int g_ppr_dumped;
static uint64_t g_seen_ioctl_com[SHARED_IOCTL_COM_TRACK_CAP];
static uint8_t g_seen_ioctl_valid[SHARED_IOCTL_COM_TRACK_CAP];
static uint64_t g_seen_ioctl_overflows;
static int g_ioctl_overflows_init;

static const char* ioctl_dir_name(uint64_t com)
{
    switch(com & IOC_DIRMASK)
    {
        case IOC_VOID: return "VOID";
        case IOC_OUT: return "OUT";
        case IOC_IN: return "IN";
        case IOC_INOUT: return "INOUT";
        default: return "UNKNOWN";
    }
}

/* Print a tracked ioctl command the first time its slot is filled.
 * Later hit-count changes stay off this stream; resident-snapshot dumps
 * the whole table. Group 0x32 is the 13.60 pfs SM transport. */
static void print_new_ioctl_coms(const struct kstuff_snapshot* snapshot)
{
    const struct kstuff_ioctl_com_table* table = &snapshot->ioctl_com_table;

    if(!g_ioctl_overflows_init)
    {
        g_seen_ioctl_overflows = table->overflows;
        g_ioctl_overflows_init = 1;
        if(table->overflows)
            tee_printf("ioctl-com-overflow overflows=%" PRIu64 "\n", table->overflows);
    }
    else if(table->overflows != g_seen_ioctl_overflows)
    {
        g_seen_ioctl_overflows = table->overflows;
        tee_printf("ioctl-com-overflow overflows=%" PRIu64 "\n", table->overflows);
    }

    for(size_t i = 0; i < SHARED_IOCTL_COM_TRACK_CAP; i++)
    {
        const struct kstuff_ioctl_com_entry* entry = &table->entries[i];
        if(entry->com == 0 && entry->total_hits == 0 && entry->emulated_hits == 0)
            continue;
        if(g_seen_ioctl_valid[i] && g_seen_ioctl_com[i] == entry->com)
            continue;
        g_seen_ioctl_valid[i] = 1;
        g_seen_ioctl_com[i] = entry->com;
        tee_printf("ioctl-com-new slot=%zu com=0x%016" PRIx64
                   " group=0x%02x num=0x%02x dir=%s len=%u total=%" PRIu32
                   " emu=%" PRIu32 "\n",
                   i,
                   entry->com,
                   (unsigned)IOCGROUP(entry->com),
                   (unsigned)(entry->com & 0xffu),
                   ioctl_dir_name(entry->com),
                   (unsigned)IOCPARM_LEN(entry->com),
                   entry->total_hits,
                   entry->emulated_hits);
    }
}

static void dump_bytes(const char* label, uint64_t addr, size_t len)
{
    unsigned char buf[0x100];
    if(len > sizeof(buf))
        len = sizeof(buf);
    int err = (int)kekcall((uint64_t)(uintptr_t)buf, addr, len, 0, 0, 0, KEKCALL_KREAD);
    if(err)
    {
        tee_printf("follower: %s read 0x%016" PRIx64 " err=%d\n", label, addr, err);
        return;
    }
    tee_printf("follower: %s 0x%016" PRIx64 " len=0x%zx\n", label, addr, len);
    for(size_t off = 0; off < len; off += 16)
    {
        size_t n = len - off;
        if(n > 16)
            n = 16;
        tee_printf("follower: %s+%03zx ", label, off);
        for(size_t i = 0; i < n; i++)
            tee_printf("%02x", buf[off + i]);
        tee_printf("  ");
        for(size_t i = 0; i < n; i++)
        {
            unsigned char c = buf[off + i];
            tee_putc(c >= 0x20 && c < 0x7f ? c : (int)0x2e);
        }
        tee_putc(0x0a);
    }
}

static int find_pprmap(const struct kstuff_snapshot* s, uint64_t* dest,
                       uint64_t* src, uint64_t* packed)
{
    uint64_t cur = s->word_log.next_seq;
    uint64_t start = cur > SHARED_LOG_WORD_CAP ? cur - SHARED_LOG_WORD_CAP : 0;

    for(uint64_t seq = start; seq + 3 < cur; seq++)
    {
        const struct kstuff_word_log_entry* e = &s->word_log.entries[seq % SHARED_LOG_WORD_CAP];
        const struct kstuff_word_log_entry* e1 = &s->word_log.entries[(seq + 1) % SHARED_LOG_WORD_CAP];
        const struct kstuff_word_log_entry* e2 = &s->word_log.entries[(seq + 2) % SHARED_LOG_WORD_CAP];
        const struct kstuff_word_log_entry* e3 = &s->word_log.entries[(seq + 3) % SHARED_LOG_WORD_CAP];

        if(e->seq != seq + 1 || e->word != 0x5050524d41503031ull)
            continue;
        if(e1->seq != seq + 2 || e2->seq != seq + 3 || e3->seq != seq + 4)
            continue;

        *dest = e1->word;
        *src = e2->word;
        *packed = e3->word;
        return 1;
    }
    return 0;
}

int main(void)
{
    struct kstuff_snapshot snapshot;
    /* Keep the host-side trace close enough to retain the last PPR event when
     * an early-firmware kernel panics immediately after verifyImage. */

    const char ready[] = "debug-reader: ready\n";

    /* Print before any file open. A hung fopen on /data used to swallow
     * the snapshot while elfldr was still inside this process. */
    setvbuf(stderr, NULL, _IONBF, 0);
    write(STDERR_FILENO, ready, sizeof(ready) - 1);
    setvbuf(stdout, g_stdout_buf, _IOLBF, sizeof(g_stdout_buf));
    tee_errprintf("debug-reader: start\n");
    tee_flush();

    if(kekcall(0, 0, 0, 0, 0, 0, KEKCALL_CHECK))
    {
        tee_errprintf("debug-reader: ps5-kstuff is not loaded\n");
        tee_flush();
        return 1;
    }

    tee_errprintf("debug-reader: attached\n");
    tee_flush();

    /* LIVE variant: stream new ring words continuously (~4 Hz) so the
     * host log holds everything up to a quarter second before a panic
     * power-off. A hard cap keeps a forgotten process from running
     * forever; the kekcall liveness check below exits earlier if kstuff
     * goes away. Metrics print one summary line every 20 passes.
     * Ring cursors live across passes so each entry prints once. */
    const struct timespec fast = {0, 250 * 1000 * 1000};
    uint64_t word_seq = 0;
    uint64_t msg_seq = 0;
    for(uint64_t pass = 0; pass < 20ull * 60 * 10; pass++)
    {
        int err = snapshot_shared_area(&snapshot);
        if(err)
        {
            tee_errprintf("debug-reader: shared_area snapshot failed: %d\n", err);
            tee_flush();
            return 1;
        }
        if(kekcall(0, 0, 0, 0, 0, 0, KEKCALL_CHECK))
        {
            tee_errprintf("follower-live: kstuff gone\n");
            tee_flush();
            return 0;
        }

        print_new_msg_log(&snapshot, &msg_seq);
        print_new_word_log(&snapshot, &word_seq);
        print_new_ioctl_coms(&snapshot);
        if(!g_ppr_dumped)
        {
            uint64_t dest = 0, src = 0, packed = 0;
            if(find_pprmap(&snapshot, &dest, &src, &packed))
            {
                g_ppr_dumped = 1;
                tee_printf("follower: PPRMAP01 dest=0x%016" PRIx64 " src=0x%016" PRIx64 " packed=0x%016" PRIx64 "\n",
                           dest, src, packed);
                dump_bytes("src", src, 0x88);
                dump_bytes("dst", dest, 0x40);
            }
        }
        /* One compact liveness line per ~5 s instead of the full dump. */
        if((pass % 20) == 0)
        {
            tee_printf("LIVE pass=%" PRIu64 " kek=%llu ioctl=%llu ioctl_trap=%llu "
                       "nmount_trap=%llu fself_traps=%llu fpkg_traps=%llu "
                       "mbx=%llu mbx_fpkg=%llu fpkg_disp=%llu lw_writes=%llu "
                       "outstanding=%llu next_seq=%" PRIu64 "\n",
                       pass,
                       (unsigned long long)snapshot.metrics.syscall_kekcall_dispatches,
                       (unsigned long long)snapshot.metrics.syscall_ioctl_dispatches,
                       (unsigned long long)snapshot.metrics.syscall_ioctl_trap,
                       (unsigned long long)snapshot.metrics.syscall_nmount_trap,
                       (unsigned long long)snapshot.metrics.fself_traps,
                       (unsigned long long)snapshot.metrics.fpkg_traps,
                       (unsigned long long)snapshot.metrics.mailbox_traps,
                       (unsigned long long)snapshot.metrics.mailbox_fpkg,
                       (unsigned long long)snapshot.metrics.syscall_fpkg_dispatches,
                       (unsigned long long)snapshot.metrics.log_word_writes,
                       (unsigned long long)snapshot.ppr_plaintext_key_pairs_outstanding,
                       snapshot.word_log.next_seq);
        }

        tee_flush();

        nanosleep(&fast, NULL);
    }
    return 0;
}
