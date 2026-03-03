#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_1_1_basic.sh — Task 1.1 in-guest test suite
#
# Runs inside the QEMU guest where phantom.ko is mounted via 9p at
# /mnt/phantom.  All test artefacts (module, test binary) come from
# the 9p share so no rsync into the guest is needed.
#
# Exit code: 0 = all tests passed, 1 = one or more failures.

set -euo pipefail

MODULE=/mnt/phantom/kernel/phantom.ko
TEST_SRC=/mnt/phantom/tests/test_ioctl.c
TEST_BIN=/tmp/test_ioctl
DEVICE=/dev/phantom

PASS=0
FAIL=0

# ---- helpers --------------------------------------------------------

log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { PASS=$((PASS + 1)); log "PASS  $*"; }
fail() { FAIL=$((FAIL + 1)); log "FAIL  $*"; }

run_test() {
	local label="$1"
	shift
	if "$@" >/dev/null 2>&1; then
		pass "$label"
	else
		fail "$label"
	fi
}

cleanup_module() {
	rmmod phantom 2>/dev/null || true
}

# Ensure we start clean
cleanup_module

# ---- Test 1: insmod loads without error -----------------------------

log "--- Test 1: insmod ---"
if insmod "$MODULE"; then
	pass "insmod $MODULE"
else
	fail "insmod $MODULE"
	# Cannot continue without the module
	log "ABORT: insmod failed; cannot continue"
	exit 1
fi

# ---- Test 2: dmesg shows successful load message --------------------

log "--- Test 2: dmesg load message ---"
# Allow up to 2 seconds for messages to flush
sleep 0.5
if dmesg | tail -50 | grep -q "phantom: loaded"; then
	pass "dmesg shows 'phantom: loaded'"
else
	fail "dmesg shows 'phantom: loaded'"
	dmesg | tail -20
fi

# ---- Test 3: /dev/phantom device node exists -------------------------

log "--- Test 3: device node exists ---"
if [ -c "$DEVICE" ]; then
	pass "/dev/phantom is a character device"
else
	fail "/dev/phantom does not exist or is not a character device"
fi

# ---- Test 4: compile and run ioctl test binary ----------------------
#
# gcc may not be available in the minimal guest.  Fall back to the
# pre-compiled binary shipped in tests/ (compiled on the server host).

log "--- Test 4: ioctl GET_VERSION ---"
PREBUILT=/mnt/phantom/tests/test_ioctl
if gcc -O2 -Wall -o "$TEST_BIN" "$TEST_SRC" 2>/dev/null; then
	pass "compiled test_ioctl.c"
elif [ -x "$PREBUILT" ]; then
	log "      gcc unavailable — using pre-compiled binary"
	TEST_BIN="$PREBUILT"
	pass "pre-compiled test_ioctl binary available"
else
	fail "no test_ioctl binary available (gcc failed and no pre-built)"
fi

if [ -x "$TEST_BIN" ]; then
	if "$TEST_BIN"; then
		pass "ioctl test binary: all assertions passed"
	else
		fail "ioctl test binary: one or more assertions failed"
		"$TEST_BIN" || true
	fi
fi

# ---- Test 5: rmmod unloads without error ----------------------------

log "--- Test 5: rmmod ---"
if rmmod phantom; then
	pass "rmmod phantom"
else
	fail "rmmod phantom"
fi

if dmesg | tail -20 | grep -q "phantom: unloaded"; then
	pass "dmesg shows 'phantom: unloaded'"
else
	fail "dmesg shows 'phantom: unloaded'"
fi

# ---- Test 6: double insmod is rejected ------------------------------

log "--- Test 6: double insmod rejected ---"
insmod "$MODULE" >/dev/null 2>&1 || true

if insmod "$MODULE" 2>&1 | grep -qiE "already loaded|File exists|EEXIST"; then
	pass "second insmod correctly rejected"
else
	# The kernel already prevents loading the same module twice;
	# insmod will fail with EEXIST.  If the grep didn't match, check
	# the exit code — non-zero means rejection.
	if insmod "$MODULE" 2>/dev/null; then
		fail "second insmod unexpectedly succeeded"
		rmmod phantom 2>/dev/null || true
	else
		pass "second insmod correctly rejected (non-zero exit)"
	fi
fi

# Ensure module is unloaded after test 6
cleanup_module

# ---- Test 7: insmod after rmmod (clean state) -----------------------

log "--- Test 7: reload after clean unload ---"
if insmod "$MODULE"; then
	pass "reload after rmmod succeeded"
	rmmod phantom
else
	fail "reload after rmmod failed"
fi

# ---- Summary --------------------------------------------------------

echo ""
echo "========================================="
echo " RESULTS: $PASS passed, $FAIL failed"
echo "========================================="

if [ "$FAIL" -eq 0 ]; then
	log "All tests passed."
	exit 0
else
	log "One or more tests FAILED."
	exit 1
fi
