/* SPDX-License-Identifier: GPL-3.0-or-later
 * PS5 Pro 13.60 kernel-text collector. No kernel writes or sleep requests.
 * Pmap and cave addresses: PS5Dev/Byepervisor-Reborn ea04f71,
 * cross-checked with EchoStretch/kstuff-lite 48cd2c4 offsets/13_60.h.
 */
#include <ps5/kernel.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "paging.h"
int sceKernelGetMainSocId(void);
#include "profile_13_60_pro.h"
#ifndef CAPTURE_ROOT
#define CAPTURE_ROOT "/data"
#endif
static unsigned char buffer[4096];
static int read64(void *unused, uint64_t address, uint64_t *value) {
    (void)unused;
    *value = 0;
    return kernel_copyout((intptr_t)address, value, sizeof(*value));
}
static int kernel_pointer(uint64_t value) {
    return (value >> 48) == 0xffff && !(value & 7);
}
static int write_all(int fd, const void *data, size_t len) {
    const unsigned char *p = data;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}
static uint32_t crc_update(uint32_t crc, const void *data, size_t len) {
    const unsigned char *p = data;
    while (len--) {
        crc ^= *p++;
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (0u - (crc & 1)));
    }
    return crc;
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint32_t fw = kernel_get_fw_version();
    int soc = sceKernelGetMainSocId();
    uint64_t text = KERNEL_ADDRESS_TEXT_BASE, data = KERNEL_ADDRESS_DATA_BASE;
    printf("Kernel capture v1: fw=%08x soc=%x\n", fw, soc);
    if ((fw & 0xffff0000u) != PROFILE_FIRMWARE || soc != PROFILE_SOC
        || !kernel_pointer(text) || !kernel_pointer(data)
        || data - text != TEXT_LENGTH || (text & 4095)) {
        puts("Unsupported firmware/model/base layout. No kernel code read.");
        return 1;
    }
    uint64_t pmap = data + PMAP_OFFSET, pml4 = 0, cr3 = 0;
    if (read64(NULL, pmap + PMAP_PML4_OFFSET, &pml4)
        || read64(NULL, pmap + PMAP_CR3_OFFSET, &cr3)
        || !kernel_pointer(pml4) || (pml4 & 4095)
        || !cr3 || (cr3 & 4095) || cr3 >= CAP_PHYS_LIMIT
        || !kernel_pointer(pml4 - cr3)) {
        puts("Kernel pmap could not be verified. No kernel code read.");
        return 1;
    }
    uint64_t dmap = pml4 - cr3, cookie = 0, hook_state = 0;
    if (read64(NULL, data + CAVE_OFFSET + COOKIE_OFFSET, &cookie)
        || read64(NULL, data + CAVE_OFFSET + HOOK_STATE_OFFSET, &hook_state)) {
        puts("Cannot read resume evidence. No kernel code read.");
        return 1;
    }
    unsigned counts[5] = {0};
    for (uint64_t offset = 0; offset < TEXT_LENGTH; offset += 4096) {
        enum cap_page_status s = cap_check_page(cr3, dmap, text + offset, read64, NULL);
        ++counts[s];
    }
    printf("Page audit: readable=%u missing=%u XOTEXT=%u invalid=%u read_errors=%u\n",
           counts[0], counts[1], counts[2], counts[3], counts[4]);
    printf("Resume cookie=%016llx hook_state=%016llx\n",
           (unsigned long long)cookie, (unsigned long long)hook_state);
    char dir[160], path[200], final_path[200], manifest[200];
    int dir_len = snprintf(dir, sizeof(dir), CAPTURE_ROOT "/capture-%lld-%d",
             (long long)time(NULL), getpid());
    if (dir_len < 0 || (size_t)dir_len >= sizeof(dir)) { puts("Capture path too long"); return 1; }
    if (mkdir(dir, 0700)) { perror("mkdir"); return 1; }
    snprintf(path, sizeof(path), "%s/kernel_text.bin.partial", dir);
    snprintf(final_path, sizeof(final_path), "%s/kernel_text.bin", dir);
    snprintf(manifest, sizeof(manifest), "%s/manifest.json", dir);
    const char *status = "skipped_protected_or_unverified";
    uint64_t written = 0;
    uint32_t crc = UINT32_MAX;
    int completed = 0;
    if (cookie == RESUME_COOKIE && hook_state == 0
        && counts[CAP_OK] == TEXT_LENGTH / 4096) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) { perror("open"); status = "file_open_failed"; }
        else {
            status = "partial_read_or_write_failure";
            while (written < TEXT_LENGTH) {
                /* Recheck this mapping immediately before every read. */
                if (cap_check_page(cr3, dmap, text + written, read64, NULL) != CAP_OK
                    || kernel_copyout((intptr_t)(text + written), buffer, sizeof(buffer))
                    || write_all(fd, buffer, sizeof(buffer))) break;
                crc = crc_update(crc, buffer, sizeof(buffer));
                written += sizeof(buffer);
                if (!(written & 0xfffff)) printf("Captured %llu bytes\n", (unsigned long long)written);
            }
            int sync_ok = fsync(fd) == 0;
            int close_ok = close(fd) == 0;
            if (written == TEXT_LENGTH && sync_ok && close_ok
                && rename(path, final_path) == 0) {
                completed = 1;
                status = "complete";
            }
        }
    }
    FILE *f = fopen(manifest, "wx");
    if (!f) { perror("manifest"); return 1; }
    int n = fprintf(f,
        "{\n  \"collector\": \"kernel-capture-v1\",\n"
        "  \"firmware_raw\": \"0x%08x\", \"soc_id\": \"0x%x\",\n"
        "  \"kernel_text_va\": \"0x%016llx\", \"kernel_data_va\": \"0x%016llx\",\n"
        "  \"kernel_pmap_va\": \"0x%016llx\", \"cr3\": \"0x%llx\",\n"
        "  \"resume_cookie\": \"0x%016llx\", \"hook_state\": \"0x%llx\",\n"
        "  \"pages\": {\"readable\": %u, \"missing\": %u, \"protected\": %u, \"invalid\": %u, \"read_error\": %u},\n"
        "  \"status\": \"%s\", \"expected_bytes\": %llu, \"written_bytes\": %llu,\n"
        "  \"crc32_of_written_bytes\": \"%08x\", \"complete\": %s\n}\n",
        fw, soc, (unsigned long long)text, (unsigned long long)data,
        (unsigned long long)pmap, (unsigned long long)cr3,
        (unsigned long long)cookie, (unsigned long long)hook_state,
        counts[0], counts[1], counts[2], counts[3], counts[4], status,
        (unsigned long long)TEXT_LENGTH, (unsigned long long)written, crc ^ UINT32_MAX,
        completed ? "true" : "false");
    int flush_ok = fflush(f) == 0 && fsync(fileno(f)) == 0;
    int close_ok = fclose(f) == 0;
    if (n < 0 || !flush_ok || !close_ok) { puts("Manifest write failed"); return 1; }
    printf("CAPTURE_DIR=%s\nSTATUS=%s\n", dir, status);
    return completed ? 0 : 2;
}
