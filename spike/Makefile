# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile — out-of-tree kernel module for the VMX feasibility spike.
#
# Build against the running kernel on the server (6.8.0-90-generic).
# Usage:
#   make              — build spike.ko
#   make clean        — remove build artefacts
#   make KDIR=...     — build against a specific kernel tree
#
# The guest_code.S object is linked directly into the spike module so that
# the guest_code_start symbol is visible at runtime and its physical address
# can be used as the guest RIP (identity-mapped via EPT).

obj-m := spike.o
spike-objs := spike_main.o spike_ept.o guest_code.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
