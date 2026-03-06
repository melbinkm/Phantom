# SPDX-License-Identifier: GPL-2.0-only
# Phantom Class B guest kernel build instructions.
#
# Downloads and builds a minimal Linux kernel with the Phantom harness.
#
# Usage (on phantom-bench):
#   make setup         — download and extract kernel source
#   make bzImage       — configure and build
#   make install       — copy bzImage to /root/phantom/bzImage-guest
#   make clean         — remove build artifacts
#
# Prerequisites:
#   apt-get install bc flex bison libssl-dev libelf-dev wget

LINUX_VERSION := 6.1.90
LINUX_TARBALL := linux-$(LINUX_VERSION).tar.xz
LINUX_URL     := https://cdn.kernel.org/pub/linux/kernel/v6.x/$(LINUX_TARBALL)
LINUX_SRC     := /root/phantom/linux-$(LINUX_VERSION)
BZIMAGE_OUT   := /root/phantom/bzImage-guest
JOBS          := $(shell nproc)

.PHONY: all setup bzImage install clean help

all: bzImage

help:
	@echo "Phantom Class B guest kernel build"
	@echo "  make setup    — download + extract Linux $(LINUX_VERSION)"
	@echo "  make bzImage  — build kernel"
	@echo "  make install  — copy bzImage to $(BZIMAGE_OUT)"
	@echo "  make clean    — clean build"

setup:
	@if [ ! -d "$(LINUX_SRC)" ]; then \
		echo "Downloading Linux $(LINUX_VERSION)..."; \
		wget -c "$(LINUX_URL)" -O /tmp/$(LINUX_TARBALL); \
		tar -xf /tmp/$(LINUX_TARBALL) -C /root/phantom/; \
		echo "Extracted to $(LINUX_SRC)"; \
	else \
		echo "$(LINUX_SRC) already exists, skipping download"; \
	fi
	@echo "Copying defconfig and harness..."
	@cp defconfig $(LINUX_SRC)/.config
	@cp init_harness.c $(LINUX_SRC)/init/phantom_harness.c
	@# Add harness to kernel init/Makefile if not already there
	@grep -q phantom_harness $(LINUX_SRC)/init/Makefile || \
		echo "obj-y += phantom_harness.o" >> $(LINUX_SRC)/init/Makefile
	@$(MAKE) -C $(LINUX_SRC) olddefconfig
	@echo "Setup complete. Run 'make bzImage' to build."

bzImage: $(LINUX_SRC)/.config
	$(MAKE) -C $(LINUX_SRC) bzImage -j$(JOBS)
	@echo "Built: $(LINUX_SRC)/arch/x86/boot/bzImage"

install: bzImage
	cp $(LINUX_SRC)/arch/x86/boot/bzImage $(BZIMAGE_OUT)
	@echo "Installed to $(BZIMAGE_OUT)"

clean:
	$(MAKE) -C $(LINUX_SRC) clean
