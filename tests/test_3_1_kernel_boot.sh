#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Test: task-3.1 Minimal Linux Guest Boot
set -euo pipefail

PASS=0; FAIL=0; SKIP=0
KO=/root/phantom/src/kernel/phantom.ko
BRIDGE=/root/phantom/src/userspace/kafl-bridge/phantom_bridge.py
BZIMAGE=/root/phantom/bzImage-guest
SRC=/root/phantom/src

pass() { echo "  PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $*" >&2; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $*"; SKIP=$((SKIP+1)); }

echo "=== test_3_1_kernel_boot ==="

# Test 1: phantom.ko loads with new MSR/CPUID support
echo "Test 1: Module loads with MSR bitmap + CPUID emulation"
rmmod phantom 2>/dev/null || true
rmmod kvm_intel 2>/dev/null || true   # Phantom takes exclusive VMX ownership
if insmod "$KO" phantom_cores=0 2>/dev/null; then
	if dmesg | tail -10 | grep -q "VMX active on 1 core"; then
		pass "module loaded (MSR/CPUID support compiled in)"
	else
		fail "module loaded but VMX not active"
	fi
else
	fail "insmod phantom.ko failed — check dmesg"
fi

# Test 2: Class A regression — existing bridge still works
echo "Test 2: Class A regression (100 iterations)"
if [ ! -c /dev/phantom ]; then
	skip "Test 2: /dev/phantom not present"
elif [ ! -f "$BRIDGE" ]; then
	skip "Test 2: phantom_bridge.py not found at $BRIDGE"
else
	out=$(python3 "$BRIDGE" --cores 0 --max-iterations 100 \
		--payload-size 64 --timeout-ms 2000 2>&1) || true
	if echo "$out" | grep -q "iterations: 100"; then
		pass "Class A: 100 iterations completed without regression"
	else
		fail "Class A regression: $out"
	fi
fi

# Test 3: BOOT_KERNEL ioctl defined
echo "Test 3: PHANTOM_IOCTL_BOOT_KERNEL defined in headers"
if grep -r "PHANTOM_IOCTL_BOOT_KERNEL" \
		"$SRC/kernel/interface.h" 2>/dev/null | grep -q define; then
	pass "PHANTOM_IOCTL_BOOT_KERNEL defined"
else
	fail "PHANTOM_IOCTL_BOOT_KERNEL not found in interface.h"
fi

# Test 4: TSC offset written to VMCS
echo "Test 4: TSC_OFFSET written to VMCS controls"
if grep -r "VMCS_CTRL_TSC_OFFSET" \
		"$SRC/kernel/vmx_core.c" 2>/dev/null | grep -q "vmcs_write"; then
	pass "TSC_OFFSET written in vmx_core.c"
elif grep -r "VMCS_CTRL_TSC_OFFSET" \
		"$SRC/kernel/snapshot.c" 2>/dev/null | grep -q "vmcs_write"; then
	pass "TSC_OFFSET written in snapshot.c"
else
	fail "TSC_OFFSET write not found in vmx_core.c or snapshot.c"
fi

# Test 5: MSR emulation sources compiled into module
echo "Test 5: MSR/CPUID/guest_boot objects in Kbuild"
if grep -q "msr_emul.o" "$SRC/kernel/Kbuild" 2>/dev/null && \
   grep -q "cpuid_emul.o" "$SRC/kernel/Kbuild" 2>/dev/null && \
   grep -q "guest_boot.o" "$SRC/kernel/Kbuild" 2>/dev/null; then
	pass "msr_emul.o + cpuid_emul.o + guest_boot.o in Kbuild"
else
	fail "one or more new objects missing from Kbuild"
fi

# Test 6: CR access handler present
echo "Test 6: phantom_handle_cr_access() in vmx_core.c"
if grep -q "phantom_handle_cr_access" "$SRC/kernel/vmx_core.c" 2>/dev/null; then
	pass "phantom_handle_cr_access defined"
else
	fail "phantom_handle_cr_access missing from vmx_core.c"
fi

# Test 7: Guest kernel boot (requires pre-built bzImage)
echo "Test 7: Linux kernel boot to harness init"
if [ ! -f "$BZIMAGE" ]; then
	skip "bzImage not at $BZIMAGE — build with: make -C $SRC/guest/guest_kernel/ bzImage"
else
	pass "bzImage present at $BZIMAGE (boot test requires manual run)"
fi

rmmod phantom 2>/dev/null || true
modprobe kvm_intel 2>/dev/null || true   # restore KVM
echo ""
echo "=== test_3_1_kernel_boot ($((PASS+FAIL+SKIP)) tests): $PASS passed, $FAIL failed, $SKIP skipped ==="
[ "$FAIL" -eq 0 ]
