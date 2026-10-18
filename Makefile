.DEFAULT_GOAL := help
PYTHON ?= python3
HOST_CC ?= cc
CONTAINER ?= docker
CONTAINER_IMAGE ?= ps5-homebrew-tools-build
TOOLS := resident-snapshot process-watch process-snapshot thread-probe-v1 thread-probe-v2 kernel-capture capture-export minimal-payload

.PHONY: help all checksums container-build check check-python check-paging native-check native-app clean bundle reader3 procwatch shellshot $(TOOLS)

help:
	@echo 'PS5 Homebrew Tools'
	@echo '  make all                 Build every payload into out/'
	@echo '  make process-watch       Build a selected tool'
	@echo '  make bundle              Build and package tools with source/checksums'
	@echo '  make container-build     Build all payloads with the pinned reference toolchain'
	@echo '  make checksums           Write out/SHA256SUMS for built payloads'
	@echo '  make native-app          Build the native starter app folder and ZIP'
	@echo '  make check               Run host tests (no SDK or console required)'
	@echo '  make native-check        Rebuild the native runtime and verify pinned checksums (no SDK)'
	@echo '  make clean               Remove generated payloads'
	@echo 'Historical names: make reader3, procwatch, shellshot copy the renamed tools.'
	@echo 'Set PS5_PAYLOAD_SDK to an installed PS5 Payload SDK before building payloads.'

all:
	$(MAKE) -f mk/payloads.mk all

$(TOOLS):
	$(MAKE) -f mk/payloads.mk out/$@.elf

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
