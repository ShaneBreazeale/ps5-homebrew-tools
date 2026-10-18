.DEFAULT_GOAL := help
PYTHON ?= python3
TOOLS := resident-snapshot process-watch process-snapshot thread-probe-v1 thread-probe-v2 kernel-capture capture-export minimal-payload

.PHONY: help all check clean bundle reader3 procwatch shellshot $(TOOLS)

help:
	@echo 'PS5 Homebrew Tools'
	@echo '  make all                 Build every payload into out/'
	@echo '  make process-watch      Build a selected tool'
	@echo '  make bundle             Build and package tools with source/checksums'
	@echo '  make check               Run host tests (no SDK or console required)'
	@echo '  make clean               Remove generated payloads'
	@echo 'Set PS5_PAYLOAD_SDK to an installed PS5 Payload SDK before building.'

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

check:
	$(PYTHON) -m unittest discover -s tests -v

clean:
	rm -rf out templates/minimal-payload/out
