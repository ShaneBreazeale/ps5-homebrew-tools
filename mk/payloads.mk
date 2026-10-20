# SPDX-License-Identifier: GPL-3.0-or-later
.DEFAULT_GOAL := all

ifndef PS5_PAYLOAD_SDK
$(error Set PS5_PAYLOAD_SDK to an installed PS5 Payload SDK)
endif
ifeq ($(wildcard $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk),)
$(error PS5_PAYLOAD_SDK must contain toolchain/prospero.mk)
endif
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

# Same source + same LLVM release must give the same bytes on any host.
# Host shells often export CFLAGS (for example -march=native), which would
# silently retarget the payload, so only explicit command-line flags apply.
ifeq ($(origin CFLAGS),environment)
$(warning Ignoring CFLAGS from the environment; pass it on the make command line instead)
CFLAGS := -O2 -g
endif
$(foreach var,CPPFLAGS LDFLAGS LDLIBS,$(if $(filter environment,$(origin $(var))),$(warning Ignoring $(var) from the environment; pass it on the make command line instead)$(eval $(var) :=)))

# The SDK uses whichever LLVM prospero-llvm-config finds first, and codegen
# differs between releases. LLVM 20+ also switches the SDK to a different
# startup/link path. The SDK's own libraries are built with LLVM 18, so that
# major version is required; PS5_LLVM_VERSION additionally pins an exact release.
PS5_LLVM_MAJOR ?= 18
LLVM_VERSION := $(shell $(PS5_PAYLOAD_SDK)/bin/prospero-llvm-config --version 2>/dev/null)
ifeq ($(LLVM_VERSION),)
$(error prospero-llvm-config found no LLVM; set LLVM_CONFIG as described in docs/BUILDING.md)
endif
ifneq ($(PS5_LLVM_MAJOR),)
ifneq ($(firstword $(subst ., ,$(LLVM_VERSION))),$(PS5_LLVM_MAJOR))
$(error LLVM $(LLVM_VERSION) found; payloads require LLVM $(PS5_LLVM_MAJOR). Set LLVM_CONFIG to an LLVM $(PS5_LLVM_MAJOR) llvm-config, or use make container-build)
endif
endif
ifneq ($(PS5_LLVM_VERSION),)
ifneq ($(LLVM_VERSION),$(PS5_LLVM_VERSION))
$(error LLVM $(LLVM_VERSION) does not match PS5_LLVM_VERSION=$(PS5_LLVM_VERSION))
endif
endif
$(info Building with LLVM $(LLVM_VERSION) from $(shell $(PS5_PAYLOAD_SDK)/bin/prospero-llvm-config --bindir))

# Keep checkout path, SDK location, and compiler vendor string out of the
# output. Recipes add these after CFLAGS, so overriding CFLAGS keeps them.
REPRO_FLAGS := -ffile-prefix-map=$(CURDIR)=. \
	-ffile-prefix-map=$(realpath $(PS5_PAYLOAD_SDK))=/ps5-payload-sdk \
	-fno-ident

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra

# The linker still records its vendor build in .comment; drop it after linking.
define link_cleanup
$(OBJCOPY) --remove-section=.comment $@
endef
TOOLS := kernel-offset process-debugger resident-snapshot process-watch process-snapshot thread-probe-v1 thread-probe-v2 kernel-capture capture-export

.DELETE_ON_ERROR:
.PHONY: all
all: $(addprefix out/,$(addsuffix .elf,$(TOOLS))) out/minimal-payload.elf

out:
	mkdir -p $@

out/resident-snapshot.elf: payloads/resident-snapshot/main.c vendor/kstuff/uelf/shared_area.h vendor/kstuff/uelf/fself.h vendor/kstuff/uelf/syscall_fixes.h vendor/freebsd/sys/ioccom.h | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) -Ivendor -Ivendor/kstuff $(LDFLAGS) -o $@ $< $(LDLIBS)
	$(link_cleanup)

$(addprefix out/,$(addsuffix .elf,process-watch process-snapshot thread-probe-v1 thread-probe-v2 kernel-capture capture-export)): out/%.elf: payloads/%/main.c | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)
	$(link_cleanup)

out/kernel-capture.elf: payloads/kernel-capture/paging.h payloads/kernel-capture/profile_13_60_pro.h

out/minimal-payload.elf: templates/minimal-payload/main.c | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)
	$(link_cleanup)

out/process-debugger.elf: payloads/process-debugger/main.c payloads/process-debugger/hwbreak.h vendor/prosper0gdb/rsp_transport.h vendor/prosper0gdb/trap_state.h | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)
	$(link_cleanup)

# Provider source is explicitly chosen by the operator/integrator. Empty means
# the normal build fails closed; a legacy-only build requires an explicit flag.
KERNEL_OFFSET_PROVIDER ?=
out/kernel-offset.elf: payloads/kernel-offset/main.c payloads/kernel-offset/backend.h payloads/kernel-offset/readiness.h payloads/kernel-capture/paging.h payloads/kernel-capture/profile_13_60_pro.h $(KERNEL_OFFSET_PROVIDER) | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(if $(strip $(KERNEL_OFFSET_PROVIDER)),-DKERNEL_OFFSET_HAS_PROVIDER=1) $(LDFLAGS) -o $@ $< $(KERNEL_OFFSET_PROVIDER) $(LDLIBS)
	$(link_cleanup)
