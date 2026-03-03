# SPDX-License-Identifier: GPL-2.0-only
#
# guest/Makefile — build the trivial guest flat binary
#
# The binary is assembled position-independently at text offset 0x0
# and loaded by the host at GPA 0x10000.  The host module also contains
# an inline machine-code copy of the same program so the external binary
# is for reference and cross-checking only.
#
# Targets:
#   all           — build trivial_guest.bin
#   clean         — remove build artefacts
#   verify        — show objdump disassembly for review

AS	:= as
LD	:= ld
OBJCOPY	:= objcopy
OBJDUMP	:= objdump

ASFLAGS	:= --64
LDFLAGS	:= -Ttext=0x0 --oformat=binary -m elf_x86_64

.PHONY: all clean verify

all: trivial_guest.bin

trivial_guest.o: trivial_guest.S
	$(AS) $(ASFLAGS) -o $@ $<

trivial_guest.elf: trivial_guest.o
	$(LD) $(LDFLAGS) -o $@ $<

trivial_guest.bin: trivial_guest.elf
	$(OBJCOPY) -O binary $< $@
	@echo "trivial_guest.bin: $$(wc -c < trivial_guest.bin) bytes"

verify: trivial_guest.elf
	$(OBJDUMP) -d -M att $<

clean:
	rm -f trivial_guest.o trivial_guest.elf trivial_guest.bin
