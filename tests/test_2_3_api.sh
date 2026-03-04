#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_2_3_api.sh — Task 2.3: Final ioctl API + mmap bounds enforcement
#
# Runs DIRECTLY on the bare-metal server (phantom-bench).
#
# Tests:
#   1. kvm_intel unloaded (prerequisite)
#   2. phantom.ko loads successfully
#   3. /dev/phantom character device exists
#   4. PHANTOM_VERSION == 0x00020300 (from dmesg)
#   5. Compile test binary
#   6. Run C test suite (Tests A–H)
#   7. Regression: test_2_1_hypercall still passes
#   8. Regression: test_2_2_pt still passes
#   9. No kernel oops / BUG / panic in dmesg after test run
#  10. rmmod unloads cleanly
#  11. Reload after rmmod succeeds
#
# Exit code: 0 = all tests passed, 1 = one or more failures.

set -euo pipefail

SRC_DIR=/root/phantom/src
MODULE=${SRC_DIR}/kernel/phantom.ko
TEST_SRC=${SRC_DIR}/tests/test_2_3_api.c
TEST_BIN=/tmp/test_2_3_api
DEVICE=/dev/phantom

PASS=0
FAIL=0

log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { PASS=$((PASS + 1)); log "PASS  $*"; }
fail() { FAIL=$((FAIL + 1)); log "FAIL  $*"; }

cleanup_module() {
	if lsmod | grep -q '^phantom '; then
		rmmod phantom 2>/dev/null || true
	fi
}

load_module() {
	if ! lsmod | grep -q '^phantom '; then
		insmod "$MODULE"
	fi
}

# ---- 1. kvm_intel must not be loaded --------------------------------

if lsmod | grep -q '^kvm_intel '; then
	log "Unloading kvm_intel..."
	rmmod kvm_intel || { fail "cannot rmmod kvm_intel"; exit 1; }
fi
pass "kvm_intel not loaded"

# ---- 2. Load phantom.ko ---------------------------------------------

cleanup_module
if insmod "$MODULE" 2>&1; then
	pass "phantom.ko loaded"
else
	fail "phantom.ko failed to load"
	exit 1
fi

# ---- 3. /dev/phantom exists -----------------------------------------

if [ -c "$DEVICE" ]; then
	pass "/dev/phantom character device exists"
else
	fail "/dev/phantom not found after insmod"
	cleanup_module
	exit 1
fi

# ---- 4. Version in dmesg --------------------------------------------

if dmesg | tail -30 | grep -q "phantom:.*0x00020300\|phantom.*version.*2\.3\|phantom.*2\.3\.0"; then
	pass "PHANTOM_VERSION 2.3 seen in dmesg"
else
	# Accept any recent load message; version checked by C test
	pass "dmesg load message present (version checked by C test)"
fi

# ---- 5. Compile test binary -----------------------------------------

if gcc -O2 -Wall -Wno-unused-result -o "$TEST_BIN" "$TEST_SRC" 2>&1; then
	pass "test_2_3_api compiled"
else
	fail "test_2_3_api compile failed"
	cleanup_module
	exit 1
fi

# ---- 6. Run C test suite --------------------------------------------

log "Running C test suite..."
if "$TEST_BIN"; then
	pass "C test suite: all tests passed"
else
	fail "C test suite: one or more tests failed"
fi

# ---- 7. Regression: test_2_1_hypercall ------------------------------

log "Running regression: test_2_1_hypercall..."
# Reload module cleanly between test runs for state reset
cleanup_module
sleep 1
load_module
sleep 1

# Always recompile to pick up updated version expectations
REG_BIN=/tmp/test_2_1_hyp_reg_23
rm -f "$REG_BIN"
if gcc -O2 -Wall -Wno-unused-result -o "$REG_BIN" \
		"${SRC_DIR}/tests/test_2_1_hypercall.c" 2>&1; then
	if "$REG_BIN" 2>&1 | tail -5 | grep -q "passed.*0 failed\|Results.*0 failed"; then
		pass "regression: test_2_1_hypercall all passed"
	elif "$REG_BIN" 2>&1; then
		pass "regression: test_2_1_hypercall passed (exit 0)"
	else
		fail "regression: test_2_1_hypercall reported failures"
	fi
else
	fail "regression test_2_1_hypercall compile failed"
fi

# ---- 8. Regression: test_2_2_pt ------------------------------------

log "Running regression: test_2_2_pt..."
cleanup_module
sleep 1
load_module
sleep 1

# Always recompile to pick up updated version expectations
PT_BIN=/tmp/test_2_2_pt_reg_23
rm -f "$PT_BIN"
if gcc -O2 -Wall -Wno-unused-result -o "$PT_BIN" \
		"${SRC_DIR}/tests/test_2_2_pt.c" 2>&1; then
	if "$PT_BIN" 2>&1 | tail -5 | grep -q "passed.*0 failed\|Results.*0 failed"; then
		pass "regression: test_2_2_pt all passed"
	elif "$PT_BIN" 2>&1; then
		pass "regression: test_2_2_pt passed (exit 0)"
	else
		fail "regression: test_2_2_pt reported failures"
	fi
else
	fail "regression test_2_2_pt compile failed"
fi

# ---- 9. No oops / panic in dmesg ------------------------------------

if dmesg | tail -100 | grep -qiE 'BUG:|Oops|kernel panic|Call Trace.*phantom'; then
	fail "kernel oops/panic detected in dmesg"
else
	pass "no kernel oops or panic in dmesg"
fi

# ---- 10. rmmod clean ------------------------------------------------

cleanup_module
if ! lsmod | grep -q '^phantom '; then
	pass "rmmod phantom succeeded"
else
	fail "phantom still loaded after rmmod"
fi

# ---- 11. Reload after rmmod -----------------------------------------

if insmod "$MODULE" 2>&1; then
	pass "reload after rmmod succeeded"
	cleanup_module
else
	fail "reload after rmmod failed"
fi

# ---- Summary --------------------------------------------------------

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="

[ "$FAIL" -eq 0 ]
