/* SPDX-License-Identifier: GPL-3.0-or-later
 * PS5 Pro 13.60 only. Original offsets: PS5Dev/Byepervisor-Reborn ea04f71,
 * checked against EchoStretch/kstuff-lite 48cd2c4 offsets/13_60.h.
 * Cookie/state assumptions require the matching resume instrumentation.
 */
#ifndef KERNEL_CAPTURE_PROFILE_H
#define KERNEL_CAPTURE_PROFILE_H
#define PROFILE_FIRMWARE 0x13600000u
#define PROFILE_SOC 0x840fd0
#define TEXT_LENGTH UINT64_C(0xcc0000)
#define PMAP_OFFSET UINT64_C(0x2e88ff8)
#define CAVE_OFFSET UINT64_C(0x2079000)
#define PMAP_PML4_OFFSET 0x20
#define PMAP_CR3_OFFSET 0x28
#define COOKIE_OFFSET 0x440
#define HOOK_STATE_OFFSET 0x600
#define RESUME_COOKIE UINT64_C(0xcafedead00001337)
#endif
