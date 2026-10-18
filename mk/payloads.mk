# SPDX-License-Identifier: GPL-3.0-or-later
.DEFAULT_GOAL := all

ifndef PS5_PAYLOAD_SDK
$(error Set PS5_PAYLOAD_SDK to an installed PS5 Payload SDK)
endif
ifeq ($(wildcard $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk),)
$(error PS5_PAYLOAD_SDK must contain toolchain/prospero.mk)
endif
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra
TOOLS := resident-snapshot process-watch process-snapshot thread-probe-v1 thread-probe-v2 kernel-capture capture-export

.PHONY: all
all: $(addprefix out/,$(addsuffix .elf,$(TOOLS))) out/minimal-payload.elf

out:
	mkdir -p $@

out/resident-snapshot.elf: payloads/resident-snapshot/main.c vendor/kstuff/uelf/shared_area.h vendor/kstuff/uelf/fself.h vendor/kstuff/uelf/syscall_fixes.h vendor/freebsd/sys/ioccom.h | out
	$(CC) $(CPPFLAGS) $(CFLAGS) -Ivendor -Ivendor/kstuff $(LDFLAGS) -o $@ $< $(LDLIBS)

$(addprefix out/,$(addsuffix .elf,process-watch process-snapshot thread-probe-v1 thread-probe-v2 kernel-capture capture-export)): out/%.elf: payloads/%/main.c | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

out/kernel-capture.elf: payloads/kernel-capture/paging.h payloads/kernel-capture/profile_13_60_pro.h

out/minimal-payload.elf: templates/minimal-payload/main.c | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)
