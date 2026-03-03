# SPDX-License-Identifier: GPL-2.0-only
#
# phantom.ko — bare-metal hypervisor fuzzer
# Out-of-tree build for kernel 6.8.0-90-generic and later (6.8–6.14)
#

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Static analysis via sparse (C=1) — zero warnings required
check:
	$(MAKE) -C $(KDIR) M=$(PWD) C=1 modules

# Install into running kernel (for testing only — not used in CI)
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

.PHONY: all clean check install
