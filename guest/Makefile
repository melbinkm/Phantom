# SPDX-License-Identifier: GPL-2.0-only
#
# guest/Makefile — build guest flat binaries for Phantom
#
# Targets:
#   all                  — build trivial_guest.bin + libxml2_harness.bin.flat
#   trivial_guest.bin    — assembly guest for task 1.2 smoke tests
#   libxml2_harness.bin  — C guest harness for libxml2 2.9.4 fuzzing
#   clean                — remove build artefacts
#   verify               — show objdump disassembly for review

AS	:= as
LD	:= ld
CC	:= gcc
# musl-gcc produces truly static binaries without glibc static-PIE baggage.
# Required for libxml2_harness because glibc 2.38+ forcibly links
# dl-reloc-static-pie.o even with -no-pie, breaking -nostartfiles builds.
CC_MUSL	:= musl-gcc
OBJCOPY	:= objcopy
OBJDUMP	:= objdump

ASFLAGS	:= --64
LDFLAGS	:= -Ttext=0x0 --oformat=binary -m elf_x86_64

# libxml2 static build compiled with musl-gcc, threading and stack-protection
# disabled.  -fno-stack-protector is required: stack-canary reads use
# %fs:0x28; the VMCS sets FS.base=0x7000 so canary is at GPA 0x7028 (=0)
# which is readable.  Older builds with FS.base=0 caused false-positive
# null-guard EPT violations (task-2.4 root cause analysis, fixed in kernel).
# Build: cd /root/phantom/libxml2-2.9.4 &&
#        CC=musl-gcc CFLAGS='-O2 -fno-stack-protector' ./configure
#        --disable-shared --without-python --without-readline
#        --without-zlib --without-lzma --without-threads
#        --prefix=/root/phantom/libxml2-musl-nothreads
#        && make -j4 && make install
LIBXML2_PREFIX = /root/phantom/libxml2-musl-nothreads
LIBXML2_INC    = $(LIBXML2_PREFIX)/include/libxml2
LIBXML2_LIB    = $(LIBXML2_PREFIX)/lib/libxml2.a

.PHONY: all clean verify

all: trivial_guest.bin libxml2_harness.bin.flat libxml2_trampoline.bin

trivial_guest.o: trivial_guest.S
	$(AS) $(ASFLAGS) -o $@ $<

trivial_guest.elf: trivial_guest.o
	$(LD) $(LDFLAGS) -o $@ $<

trivial_guest.bin: trivial_guest.elf
	$(OBJCOPY) -O binary $< $@
	@echo "trivial_guest.bin: $$(wc -c < trivial_guest.bin) bytes"

verify: trivial_guest.elf
	$(OBJDUMP) -d -M att $<

# libxml2 harness: static non-PIE ELF, custom _start, text at 0x1000.
#
# libxml2 pulls in the full libc (malloc, fprintf, etc.) so we cannot use
# -nodefaultlibs.  We use -nostartfiles to skip CRT and supply our own
# _start directly.  sbrk/brk/write are intercepted via --wrap so our
# bare-guest shims replace the glibc syscall wrappers.
#
# objcopy -O binary produces the raw flat image loaded at GPA 0x1000.
# Trampoline: 4KB stub at GUEST_CODE_GPA (0x10000) that jumps to 0x400000.
# Avoids overwriting guest page tables at 0x13000–0x15000.
libxml2_trampoline.o: libxml2_trampoline.S
	$(AS) $(ASFLAGS) -o $@ $<

libxml2_trampoline.elf: libxml2_trampoline.o
	$(LD) -Ttext=0x10000 --oformat=elf64-x86-64 -m elf_x86_64 \
	    --build-id=none -e _trampoline_start -o $@ $<

libxml2_trampoline.bin: libxml2_trampoline.elf
	$(OBJCOPY) -O binary $< $@
	@echo "libxml2_trampoline.bin: $$(wc -c < libxml2_trampoline.bin) bytes"

# libxml2 harness: loaded at GPA 0x400000 (above page tables at 0x13000).
# Text base 0x400000 matches PAYLOAD_GPA=0x600000 in libxml2_harness.c.
libxml2_entry.o: libxml2_entry.S
	$(AS) $(ASFLAGS) -o $@ $<

# libxml2_entry.o is forced to the start of .text via libxml2_harness.ld
# so that phantom_entry lands at exactly 0x400000 (where the trampoline jumps).
libxml2_harness.o: libxml2_harness.c
	$(CC_MUSL) -Os -fno-stack-protector \
	    -I$(LIBXML2_INC) \
	    -c -o $@ $<

libxml2_harness.bin: libxml2_entry.o libxml2_harness.o libxml2_harness.ld
	$(CC_MUSL) -static -nostartfiles -no-pie \
	    -fno-stack-protector \
	    -o $@ \
	    -Wl,-T,libxml2_harness.ld \
	    -Wl,--build-id=none \
	    -Wl,--wrap=__mmap,--wrap=__munmap \
	    -Wl,--wrap=sbrk,--wrap=brk,--wrap=write \
	    -Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc \
	    libxml2_entry.o libxml2_harness.o $(LIBXML2_LIB)
	@echo "libxml2_harness.bin: $$(wc -c < libxml2_harness.bin) bytes"
	@echo "libxml2_harness.bin: $$(wc -c < libxml2_harness.bin) bytes"

libxml2_harness.bin.flat: libxml2_harness.bin
	$(OBJCOPY) -O binary $< $@
	@echo "libxml2_harness.bin.flat: $$(wc -c < libxml2_harness.bin.flat) bytes"

clean:
	rm -f trivial_guest.o trivial_guest.elf trivial_guest.bin
	rm -f libxml2_entry.o libxml2_harness.o
	rm -f libxml2_harness.bin libxml2_harness.bin.flat
	rm -f libxml2_trampoline.o libxml2_trampoline.elf libxml2_trampoline.bin
