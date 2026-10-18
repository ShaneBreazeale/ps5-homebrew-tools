.DEFAULT_GOAL := help
PYTHON ?= python3
HOST_CC ?= cc
TOOLS := resident-snapshot process-watch process-snapshot thread-probe-v1 thread-probe-v2 kernel-capture capture-export minimal-payload

.PHONY: help all check check-python check-paging native-check native-app clean bundle reader3 procwatch shellshot $(TOOLS)

help:
	@echo 'PS5 Homebrew Tools'
	@echo '  make all                 Build every payload into out/'
	@echo '  make process-watch       Build a selected tool'
	@echo '  make bundle              Build and package tools with source/checksums'
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
	$(PYTHON) host/package_tools.py --output dist/ps5-homebrew-tools.tar.gz $(foreach tool,$(TOOLS),--artifact out/$(tool).elf)

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
