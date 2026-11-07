.DEFAULT_GOAL := help
PYTHON ?= python3
HOST_CC ?= cc
CONTAINER ?= docker
CONTAINER_IMAGE ?= ps5-homebrew-tools-build
TOOLS := kernel-offset process-debugger resident-snapshot process-watch process-snapshot thread-probe-v1 thread-probe-v2 thread-probe-v3 follower-live kernel-capture capture-export dev-control minimal-payload

.PHONY: help all checksums container-build check check-python check-debugger-analysis check-paging kernel-execution-check kernel-patch-check kernel-patch-host kernel-patch-stage2 kernel-patch-stage2-check kernel-patch-stage3 kernel-patch-stage3-query kernel-patch-stage3-check evidence-check native-check native-app clean bundle reader3 procwatch shellshot $(TOOLS)

help:
	@echo 'PS5 Homebrew Tools'
	@echo '  make all                 Build every payload into out/'
	@echo '  make process-watch       Build a selected tool'
	@echo '  make dev-control         Build the development-control payload'
	@echo '  make bundle              Build and package tools with source/checksums'
	@echo '  make container-build     Build all payloads with the pinned reference toolchain'
	@echo '  make checksums           Write out/SHA256SUMS for built payloads'
	@echo '  make native-app          Build the native starter app folder and ZIP'
	@echo '  make check               Run host tests (no SDK or console required)'
	@echo '  make check-debugger-analysis  Require the pinned optional decoder and test analysis'
	@echo '  make kernel-execution-check  SDK-compile the portable SMP core (object only)'
	@echo '  make kernel-patch-host   Build the offline patch transaction simulator'
	@echo '  make kernel-patch-check  SDK-compile the patch core (object only)'
	@echo '  make kernel-patch-stage2  SDK-build the read-only stage 2 client (provider-free default)'
	@echo '  make kernel-patch-stage2-check  Compile a prepared private resident overlay'
	@echo '  make kernel-patch-stage3  SDK-build the owned-cell exercise client (provider-free default)'
	@echo '  make kernel-patch-stage3-query  SDK-build a strictly read-only recovery client'
	@echo '  make kernel-patch-stage3-check  Compile a prepared private stage 3 overlay'
	@echo '  make kernel-patch-resident  Link a private resident and compile its actual installer'
	@echo '  make kernel-patch-campaign  Run the host-only transfer-fault experiment'
	@echo '  make evidence-check      SDK-compile checkpoint example and resident evidence core'
	@echo '  make native-check        Rebuild the native runtime and verify pinned checksums (no SDK)'
	@echo '  make clean               Remove generated payloads'
	@echo 'Historical names: make reader3, procwatch, shellshot copy the renamed tools.'
	@echo 'Set PS5_PAYLOAD_SDK to an installed PS5 Payload SDK before building payloads.'

all:
	$(MAKE) -f mk/payloads.mk all

$(TOOLS):
	$(MAKE) -f mk/payloads.mk out/$@.elf

kernel-execution-check:
	$(MAKE) -f mk/payloads.mk out/kernel-execution-core-check.o

kernel-patch-check:
	$(MAKE) -f mk/payloads.mk out/kernel-patch-core-check.o

kernel-patch-stage2:
	$(MAKE) -f mk/payloads.mk out/kernel-patch-stage2.elf

kernel-patch-stage2-check:
	$(MAKE) -f mk/payloads.mk out/kernel-patch-stage2-resident-check.o out/kernel-patch-stage2-dispatch-check.o out/kernel-patch-stage2-loader-check.o

kernel-patch-stage3:
	$(MAKE) -f mk/payloads.mk out/kernel-patch-stage3.elf

kernel-patch-stage3-query:
	$(MAKE) -f mk/payloads.mk out/kernel-patch-stage3-query.elf

kernel-patch-stage3-check:
	$(MAKE) -f mk/payloads.mk out/kernel-patch-stage3-resident-check.o out/kernel-patch-stage3-dispatch-check.o out/kernel-patch-stage3-loader-check.o

kernel-patch-host: out/host/kernel-patch-sim

KERNEL_PATCH_CAMPAIGN_OUTPUT ?=
.PHONY: kernel-patch-campaign
kernel-patch-campaign: export HOST_CC := $(HOST_CC)
kernel-patch-campaign:
	$(PYTHON) host/kernel_patch_campaign.py $(if $(strip $(KERNEL_PATCH_CAMPAIGN_OUTPUT)),--output "$(KERNEL_PATCH_CAMPAIGN_OUTPUT)")

# Private complete resident link; never part of all, bundle or deployment.
KERNEL_PATCH_RESIDENT_OBS ?= 0
.PHONY: kernel-patch-resident
kernel-patch-resident:
	$(if $(strip $(KERNEL_PATCH_RESIDENT_OVERLAY)),,$(error Set KERNEL_PATCH_RESIDENT_OVERLAY to an overlay prepared with --link-inputs))
	$(if $(strip $(KERNEL_PATCH_RESIDENT_OUTPUT)),,$(error Set KERNEL_PATCH_RESIDENT_OUTPUT to a new private build directory))
	$(PYTHON) tooling/build_kernel_patch_resident.py --overlay "$(KERNEL_PATCH_RESIDENT_OVERLAY)" --output "$(KERNEL_PATCH_RESIDENT_OUTPUT)" --obs "$(KERNEL_PATCH_RESIDENT_OBS)"

out/host/kernel-patch-sim: tooling/kernel_patch_sim.c tooling/kernel_patch_sim.h residents/patch/patch.h
	mkdir -p $(@D)
	$(HOST_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -o $@ $<

evidence-check:
	$(MAKE) -f mk/payloads.mk out/checkpoint-demo.elf out/resident-evidence-core-check.o

reader3: resident-snapshot
	cp out/resident-snapshot.elf out/reader3.elf
procwatch: process-watch
	cp out/process-watch.elf out/procwatch.elf
shellshot: process-snapshot
	cp out/process-snapshot.elf out/shellshot.elf

bundle: all
	$(PYTHON) host/package_tools.py --output dist/ps5-homebrew-tools.tar.gz \
		--toolchain "LLVM $$($(PS5_PAYLOAD_SDK)/bin/prospero-llvm-config --version); SDK $${PS5_SDK_VERSION:-unrecorded}" \
		$(foreach tool,$(TOOLS),--artifact out/$(tool).elf)

checksums:
	cd out && $(PYTHON) -c "import glob, hashlib; [print(hashlib.sha256(open(p, 'rb').read()).hexdigest() + '  ' + p) for p in sorted(glob.glob('*.elf'))]" > SHA256SUMS
	cat out/SHA256SUMS

# Reference build: Ubuntu 24.04 clang 18.1.3 and a checksum-pinned SDK. The
# image is amd64 so every host, including Apple silicon, runs the same binaries.
container-build:
	$(CONTAINER) build --platform linux/amd64 -t $(CONTAINER_IMAGE) tooling/container
	$(CONTAINER) run --rm --platform linux/amd64 -u "$$(id -u):$$(id -g)" \
		-v "$(CURDIR):/src" $(CONTAINER_IMAGE) make clean all checksums

native-app:
	$(PYTHON) tooling/native/build.py

check: check-python check-paging

check-debugger-analysis:
	$(PYTHON) -c 'import capstone; assert capstone.__version__ == "5.0.7", "install host/requirements-debugger.txt"'
	$(PYTHON) -m unittest discover -s tests -p test_debugger_tools.py -v

check-python:
	$(PYTHON) -m unittest discover -s tests -v

# The paging walker is plain C shared with the kernel-capture payload, so its
# mock test builds with the host compiler and needs no SDK.
check-paging: out/host/test_capture_paging
	out/host/test_capture_paging

out/host/test_capture_paging: tests/test_capture_paging.c payloads/kernel-capture/paging.h
	mkdir -p $(@D)
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -o $@ $<

native-check:
	$(PYTHON) tooling/native/build.py --runtime-only

clean:
	rm -rf out templates/minimal-payload/out
