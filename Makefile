.DEFAULT_GOAL := help
PYTHON ?= python3
TOOLS := reader3 procwatch shellshot thread-probe-v1 thread-probe-v2 minimal-payload

.PHONY: help all check clean $(TOOLS)

help:
	@echo 'PS5 Homebrew Tools'
	@echo '  make all                 Build every payload into out/'
	@echo '  make reader3 procwatch   Build selected tools'
	@echo '  make check               Run host tests (no SDK or console required)'
	@echo '  make clean               Remove generated payloads'
	@echo 'Set PS5_PAYLOAD_SDK to an installed PS5 Payload SDK before building.'

all:
	$(MAKE) -f mk/payloads.mk all

$(TOOLS):
	$(MAKE) -f mk/payloads.mk out/$@.elf

check:
	$(PYTHON) -m unittest discover -s tests -v

clean:
	rm -rf out templates/minimal-payload/out
