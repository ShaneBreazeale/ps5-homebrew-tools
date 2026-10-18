.DEFAULT_GOAL := all
ifndef PS5_PAYLOAD_SDK
$(error Set PS5_PAYLOAD_SDK to an installed PS5 Payload SDK)
endif
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra

.PHONY: all clean
all: out/minimal-payload.elf

out/minimal-payload.elf: main.c
	mkdir -p out
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -rf out
