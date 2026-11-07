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
TOOLS := kernel-offset process-debugger resident-snapshot process-watch process-snapshot thread-probe-v1 thread-probe-v2 thread-probe-v3 follower-live kernel-capture capture-export dev-control

.DELETE_ON_ERROR:
.PHONY: all
all: $(addprefix out/,$(addsuffix .elf,$(TOOLS))) out/minimal-payload.elf

out:
	mkdir -p $@

# Explicit compile-only check. This object is not a payload or live adapter.
out/kernel-execution-core-check.o: tests/compile_kernel_execution.c residents/execution/control.h residents/execution/mailbox.h residents/capture/capture.h | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) -c -o $@ $<

out/kernel-patch-core-check.o: tests/compile_kernel_patch.c residents/patch/patch.h residents/patch/probe.h | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) -ffreestanding -fno-builtin -mno-red-zone -mgeneral-regs-only -c -o $@ $<

# Stage 2 is opt-in and is excluded from all/bundle: configured ELFs contain a
# private bearer credential. Use a fresh output/build directory when configuring.
KERNEL_PATCH_STAGE2_CONFIG ?=
KERNEL_PATCH_STAGE2_OVERLAY ?=
KPS2_HEADERS := $(wildcard residents/patch/*.h)
.PHONY: FORCE_KPS2_CLIENT KPS2_VERIFY_OVERLAY
out/kernel-patch-stage2.elf: FORCE_KPS2_CLIENT payloads/kernel-patch-stage2/main.c residents/patch/stage2_client.c $(KPS2_HEADERS) $(if $(strip $(KERNEL_PATCH_STAGE2_CONFIG)),$(KERNEL_PATCH_STAGE2_CONFIG)/kp_stage2_config.h) | out
	$(if $(strip $(KERNEL_PATCH_STAGE2_CONFIG)),python3 tooling/verify_kernel_patch_stage2.py --stage 2 --overlay $(KERNEL_PATCH_STAGE2_CONFIG)/..,@true)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(if $(strip $(KERNEL_PATCH_STAGE2_CONFIG)),-DKERNEL_PATCH_STAGE2_HAS_PROVIDER=1 -I$(KERNEL_PATCH_STAGE2_CONFIG)) $(LDFLAGS) -o $@ payloads/kernel-patch-stage2/main.c $(if $(strip $(KERNEL_PATCH_STAGE2_CONFIG)),residents/patch/stage2_client.c) $(LDLIBS)
	$(link_cleanup)

ifneq ($(strip $(KERNEL_PATCH_STAGE2_OVERLAY)),)
KPS2_SOURCE := $(KERNEL_PATCH_STAGE2_OVERLAY)/source
KPS2_UELF := $(KPS2_SOURCE)/ps5-kstuff/uelf
KPS2_FREESTANDING := -ffreestanding -fno-builtin -mno-red-zone -mgeneral-regs-only -fno-stack-protector
KPS2_VERIFY_OVERLAY:
	python3 tooling/verify_kernel_patch_stage2.py --stage 2 --overlay $(KERNEL_PATCH_STAGE2_OVERLAY)
out/kernel-patch-stage2-resident-check.o: $(KPS2_UELF)/kp_stage2_bridge.c $(wildcard $(KPS2_UELF)/kp_stage2/*.h) | out KPS2_VERIFY_OVERLAY
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(KPS2_FREESTANDING) -nostdinc -isystem $(KPS2_SOURCE)/freebsd-headers -I$(KPS2_UELF) -c -o $@ $<
out/kernel-patch-stage2-dispatch-check.o: $(KPS2_UELF)/kekcall.c $(wildcard $(KPS2_UELF)/kp_stage2/*.h) | out KPS2_VERIFY_OVERLAY
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(KPS2_FREESTANDING) -nostdinc -isystem $(KPS2_SOURCE)/freebsd-headers -I$(KPS2_UELF) -c -o $@ $<
out/kernel-patch-stage2-loader-check.o: tests/compile_kernel_patch_stage2.c $(wildcard $(KPS2_UELF)/kp_stage2/*.h) | out KPS2_VERIFY_OVERLAY
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(KPS2_FREESTANDING) -I$(KPS2_UELF) -c -o $@ $<
else
out/kernel-patch-stage2-resident-check.o out/kernel-patch-stage2-dispatch-check.o out/kernel-patch-stage2-loader-check.o:
	$(error Set KERNEL_PATCH_STAGE2_OVERLAY to a freshly prepared private overlay)
endif

out/resident-evidence-core-check.o: tests/compile_resident_evidence.c residents/evidence/evidence.h common/evidence.h | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) -ffreestanding -fno-builtin -mno-red-zone -mgeneral-regs-only -c -o $@ $<

out/checkpoint-demo.elf: examples/checkpoint-demo/main.c lib/checkpoint/checkpoint.c lib/checkpoint/checkpoint.h common/evidence.h | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(LDFLAGS) -o $@ examples/checkpoint-demo/main.c lib/checkpoint/checkpoint.c $(LDLIBS)
	$(link_cleanup)

out/resident-snapshot.elf: payloads/resident-snapshot/main.c vendor/kstuff/uelf/shared_area.h vendor/kstuff/uelf/fself.h vendor/kstuff/uelf/syscall_fixes.h vendor/freebsd/sys/ioccom.h | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) -Ivendor -Ivendor/kstuff $(LDFLAGS) -o $@ $< $(LDLIBS)
	$(link_cleanup)

$(addprefix out/,$(addsuffix .elf,process-watch process-snapshot thread-probe-v1 thread-probe-v2 thread-probe-v3 kernel-capture capture-export dev-control)): out/%.elf: payloads/%/main.c | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)
	$(link_cleanup)

out/follower-live.elf: payloads/follower-live/main.c vendor/kstuff/uelf/shared_area.h vendor/kstuff/uelf/fself.h vendor/kstuff/uelf/syscall_fixes.h vendor/freebsd/sys/ioccom.h | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) -Ivendor -Ivendor/kstuff $(LDFLAGS) -o $@ $< $(LDLIBS)
	$(link_cleanup)

out/kernel-capture.elf: payloads/kernel-capture/paging.h payloads/kernel-capture/profile_13_60_pro.h

out/minimal-payload.elf: templates/minimal-payload/main.c | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)
	$(link_cleanup)

PROCESS_DEBUGGER_SOURCES := payloads/process-debugger/main.c payloads/process-debugger/ptrace_backend.c payloads/process-debugger/rsp.c payloads/process-debugger/inspection.c
.PHONY: FORCE_PROCESS_DEBUGGER_ID
out/process-debugger-build.h: FORCE_PROCESS_DEBUGGER_ID | out
	python3 tooling/debugger_build_id.py --llvm-version $(LLVM_VERSION) --output $@

out/process-debugger.elf: out/process-debugger-build.h payloads/process-debugger/target_description.h payloads/process-debugger/target_memory.h payloads/process-debugger/inspection.h $(PROCESS_DEBUGGER_SOURCES) payloads/process-debugger/target.h payloads/process-debugger/ptrace_backend.h payloads/process-debugger/rsp.h payloads/process-debugger/hwbreak.h vendor/prosper0gdb/rsp_transport.h vendor/prosper0gdb/trap_state.h | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(LDFLAGS) -include out/process-debugger-build.h -o $@ $(PROCESS_DEBUGGER_SOURCES) $(LDLIBS)
	$(link_cleanup)

# Provider source is explicitly chosen by the operator/integrator. Empty means
# the normal build fails closed; a legacy-only build requires an explicit flag.
KERNEL_OFFSET_PROVIDER ?=
out/kernel-offset.elf: payloads/kernel-offset/main.c payloads/kernel-offset/backend.h payloads/kernel-offset/readiness.h payloads/kernel-capture/paging.h payloads/kernel-capture/profile_13_60_pro.h $(KERNEL_OFFSET_PROVIDER) | out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(if $(strip $(KERNEL_OFFSET_PROVIDER)),-DKERNEL_OFFSET_HAS_PROVIDER=1) $(LDFLAGS) -o $@ $< $(KERNEL_OFFSET_PROVIDER) $(LDLIBS)
	$(link_cleanup)

# Private stage 3 owned-cell client. Excluded from all and public bundles.
KERNEL_PATCH_STAGE3_CONFIG ?=
KERNEL_PATCH_STAGE3_OVERLAY ?=
.PHONY: FORCE_KPS3_CLIENT KPS3_VERIFY_OVERLAY
out/kernel-patch-stage3.elf out/kernel-patch-stage3-query.elf: FORCE_KPS3_CLIENT payloads/kernel-patch-stage3/main.c residents/patch/stage3_client.c $(KPS2_HEADERS) | out
	$(if $(strip $(KERNEL_PATCH_STAGE3_CONFIG)),python3 tooling/verify_kernel_patch_stage2.py --stage 3 --overlay $(KERNEL_PATCH_STAGE3_CONFIG)/..,@true)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(if $(filter out/kernel-patch-stage3-query.elf,$@),-DKERNEL_PATCH_STAGE3_QUERY_ONLY=1) $(if $(strip $(KERNEL_PATCH_STAGE3_CONFIG)),-DKERNEL_PATCH_STAGE3_HAS_PROVIDER=1 -I$(KERNEL_PATCH_STAGE3_CONFIG)) $(LDFLAGS) -o $@ payloads/kernel-patch-stage3/main.c $(if $(strip $(KERNEL_PATCH_STAGE3_CONFIG)),residents/patch/stage3_client.c) $(LDLIBS)
	$(link_cleanup)

ifneq ($(strip $(KERNEL_PATCH_STAGE3_OVERLAY)),)
KPS3_SOURCE := $(KERNEL_PATCH_STAGE3_OVERLAY)/source
KPS3_UELF := $(KPS3_SOURCE)/ps5-kstuff/uelf
KPS3_FLAGS := -ffreestanding -fno-builtin -mno-red-zone -mgeneral-regs-only -fno-stack-protector
KPS3_VERIFY_OVERLAY:
	python3 tooling/verify_kernel_patch_stage2.py --stage 3 --overlay $(KERNEL_PATCH_STAGE3_OVERLAY)
out/kernel-patch-stage3-resident-check.o: $(KPS3_UELF)/kp_stage2_bridge.c $(wildcard $(KPS3_UELF)/kp_stage2/*.h) | out KPS3_VERIFY_OVERLAY
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(KPS3_FLAGS) -nostdinc -isystem $(KPS3_SOURCE)/freebsd-headers -I$(KPS3_UELF) -c -o $@ $<
out/kernel-patch-stage3-dispatch-check.o: $(KPS3_UELF)/kekcall.c $(wildcard $(KPS3_UELF)/kp_stage2/*.h) | out KPS3_VERIFY_OVERLAY
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(KPS3_FLAGS) -nostdinc -isystem $(KPS3_SOURCE)/freebsd-headers -I$(KPS3_UELF) -c -o $@ $<
out/kernel-patch-stage3-loader-check.o: tests/compile_kernel_patch_stage3.c $(wildcard $(KPS3_UELF)/kp_stage2/*.h) | out KPS3_VERIFY_OVERLAY
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REPRO_FLAGS) $(KPS3_FLAGS) -I$(KPS3_UELF) -c -o $@ $<
else
out/kernel-patch-stage3-resident-check.o out/kernel-patch-stage3-dispatch-check.o out/kernel-patch-stage3-loader-check.o:
	$(error Set KERNEL_PATCH_STAGE3_OVERLAY to a freshly prepared stage 3 overlay)
endif
