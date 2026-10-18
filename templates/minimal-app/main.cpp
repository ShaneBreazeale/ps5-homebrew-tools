/* SPDX-License-Identifier: GPL-3.0-or-later
 * Native controller/logging starter.
 * Controller ABI adapted from ps5-homebrew-ui, Copyright (C) 2026 BlackBearReloaded.
 * Notification ABI from PS5 Payload SDK sample, Copyright (C) 2023 John Törnblom.
 */
#include <cstddef>
#include <cstdint>
#include <cstdio>

struct PadSample {
    std::uint32_t buttons;
    std::uint8_t left_x, left_y, right_x, right_y, l2, r2;
    std::uint8_t reserved0[66];
    std::int32_t connected;
    std::uint64_t timestamp_us;
    std::uint8_t extension[16], connected_count, reserved1[15];
};
static_assert(sizeof(PadSample) == 120);
static_assert(offsetof(PadSample, connected) == 0x4c);
struct Notification { char reserved[45]; char message[3075]; };
extern "C" {
int sceUserServiceInitialize(const void *);
int sceUserServiceTerminate();
int sceUserServiceGetInitialUser(int *);
int scePadInit();
int scePadOpen(int, int, int, const void *);
int scePadRead(int, PadSample *, int);
int scePadClose(int);
int sceKernelUsleep(unsigned);
int sceKernelDebugOutText(int, const char *);
int sceKernelSendNotificationRequest(int, Notification *, std::size_t, int);
int sceSystemServiceLoadExec(const char *, const char **);
}
static void log(const char *text) {
    std::puts(text);
    sceKernelDebugOutText(0, text);
}
static void notify(const char *text) {
    Notification request{};
    std::snprintf(request.message, sizeof(request.message), "%s", text);
    int result = sceKernelSendNotificationRequest(0, &request, sizeof(request), 0);
    if (result != 0) log("[starter] notification unavailable\n");
}
int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    log("[starter] Native homebrew started\n");
    const int init = sceUserServiceInitialize(nullptr);
    const bool owns_users = init == 0;
    int user = -1, pad = -1, status = 1;
    if (init != 0 && init != static_cast<int>(0x80960003)) {
        log("[starter] User service failed\n");
    } else if (sceUserServiceGetInitialUser(&user) != 0 || scePadInit() != 0) {
        log("[starter] Controller initialization failed\n");
    } else {
        for (int attempt = 0; attempt < 20 && pad < 0; ++attempt) {
            pad = scePadOpen(user, 0, 0, nullptr);
            if (pad < 0) sceKernelUsleep(50000);
        }
        if (pad < 0) log("[starter] Controller open failed\n");
        else {
            notify("Homebrew Starter: Cross logs a marker; Circle or Options exits.");
            std::uint32_t previous = 0;
            bool running = true;
            while (running) {
                PadSample samples[64]{};
                const int count = scePadRead(pad, samples, 64);
                if (count < 0 || count > 64) { log("[starter] Controller read failed\n"); break; }
                for (int i = 0; i < count; ++i) {
                    if (!samples[i].connected) { previous = 0; continue; }
                    const auto pressed = samples[i].buttons & ~previous;
                    previous = samples[i].buttons;
                    if (pressed & 0x00004000u) log("[starter] MARKER cross\n");
                    if (pressed & (0x00002000u | 0x00000008u)) { running = false; status = 0; }
                }
                sceKernelUsleep(16000);
            }
            scePadClose(pad);
        }
    }
    if (owns_users) sceUserServiceTerminate();
    log("[starter] Exit requested\n");
    sceSystemServiceLoadExec("exit", nullptr);
    return status;
}
