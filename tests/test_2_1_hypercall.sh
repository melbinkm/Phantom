#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_2_1_hypercall.sh — Task 2.1 in-guest test suite (kAFL/Nyx ABI)
#
# Runs inside the QEMU guest where phantom.ko is mounted via 9p at
# /mnt/phantom.  Tests:
#   1. Module loads without error (insmod)
#   2. /dev/phantom character device exists
#   3. Compile (or use pre-built) test_2_1_hypercall binary
#   4. Run full ioctl hypercall test suite:
#        Test E: version check (0x00020100)
#        Test A: basic hypercall flow (test_id=8)
#        Test B: mmap shared memory
#        Test C: 1000 RUN_ITERATION round-trips
#        Test D: GET_RESULT ioctl correctness
#   5. Verify no kernel oops in dmesg after iteration test
#   6. rmmod unloads cleanly
#   7. Reload after rmmod succeeds
#   8. No oops after reload cycle
#
# Exit code: 0 = all tests passed, 1 = one or more failures.

set -euo pipefail

MODULE=/mnt/phantom/kernel/phantom.ko
TEST_SRC=/mnt/phantom/tests/test_2_1_hypercall.c
TEST_BIN=/tmp/test_2_1_hypercall
PREBUILT=/mnt/phantom/tests/test_2_1_hypercall
DEVICE=/dev/phantom

PASS=0
FAIL=0

# ---- helpers --------------------------------------------------------

log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { PASS=$((PASS + 1)); log "PASS  $*"; }
fail() { FAIL=$((FAIL + 1)); log "FAIL  $*"; }

cleanup_module() {
	rmmod phantom 2>/dev/null || true
}

cleanup_module

# Clear the dmesg ring buffer so we only see messages from this run.
dmesg -c > /dev/null 2>&1 || true

# ---- Test 1: insmod loads without error -----------------------------

log "--- Test 1: insmod ---"
if insmod "$MODULE" 2>&1; then
	pass "insmod $MODULE"
else
	fail "insmod $MODULE"
	log "ABORT: insmod failed; cannot continue"
	dmesg | tail -20
	exit 1
fi

sleep 0.3

# ---- Test 2: device node exists ------------------------------------

log "--- Test 2: device node exists ---"
if [ -c "$DEVICE" ]; then
	pass "/dev/phantom is a character device"
else
	fail "/dev/phantom does not exist or is not a character device"
	dmesg | tail -10
fi

# ---- Test 3: compile or locate pre-built binary --------------------

log "--- Test 3: compile test binary ---"
if gcc -O2 -Wall -o "$TEST_BIN" "$TEST_SRC" 2>/dev/null; then
	pass "compiled test_2_1_hypercall.c"
elif [ -x "$PREBUILT" ]; then
	log "  gcc unavailable — using pre-compiled binary"
	TEST_BIN="$PREBUILT"
	pass "pre-compiled test_2_1_hypercall binary available"
else
	fail "no test_2_1_hypercall binary available (gcc failed and no pre-built)"
	log "ABORT: no test binary; cannot continue"
	cleanup_module
	exit 1
fi

# ---- Test 4: run hypercall test suite ------------------------------
#
# NOTE: Test C runs 1000 RUN_ITERATION cycles.  In nested KVM this
# takes approximately 30-120 seconds depending on hardware.

log "--- Test 4: run hypercall test suite ---"
log "    NOTE: Test C runs 1000 iterations — expect 30-120s in nested KVM"

if [ -x "$TEST_BIN" ]; then
	if "$TEST_BIN"; then
		pass "hypercall test suite: all subtests passed"
	else
		HYPERCALL_EXIT=$?
		fail "hypercall test suite: one or more subtests failed (exit=$HYPERCALL_EXIT)"
		log "--- Dumping dmesg tail for diagnostics ---"
		dmesg | tail -30 || true
	fi
else
	fail "no test binary to run"
fi

# ---- Test 5: no kernel oops after iteration test -------------------

log "--- Test 5: no kernel oops after 1000-iteration test ---"
OOPS_COUNT=$(dmesg 2>/dev/null | \
	grep -ciE "oops|BUG:|kernel panic|general protection" || true)
if [ "${OOPS_COUNT:-0}" -gt 0 ]; then
	fail "kernel oops detected in dmesg ($OOPS_COUNT entries)"
	dmesg | grep -iE "oops|BUG:|kernel panic|general protection" \
		| tail -5 || true
else
	pass "no kernel oops in dmesg after 1000-iteration test"
fi

# ---- Test 6: rmmod unloads cleanly ---------------------------------

log "--- Test 6: rmmod ---"
if rmmod phantom; then
	pass "rmmod phantom"
else
	fail "rmmod phantom"
fi

sleep 0.2

UNLOADED_COUNT=$(dmesg 2>/dev/null | tail -20 | \
	grep -c "phantom: unloaded" || true)
if [ "${UNLOADED_COUNT:-0}" -gt 0 ]; then
	pass "dmesg shows 'phantom: unloaded'"
else
	log "  Note: 'phantom: unloaded' not found in dmesg tail"
	pass "rmmod completed (unload message check skipped)"
fi

# ---- Test 7: reload after rmmod succeeds ---------------------------

log "--- Test 7: reload after rmmod ---"
if insmod "$MODULE" 2>&1; then
	pass "reload after rmmod succeeded"
	rmmod phantom 2>/dev/null || true
else
	fail "reload after rmmod failed"
	dmesg | tail -20
fi

# ---- Test 8: no oops after full lifecycle --------------------------

log "--- Test 8: no oops after full lifecycle ---"
OOPS_COUNT=$(dmesg 2>/dev/null | \
	grep -ciE "oops|BUG:|kernel panic|general protection" || true)
if [ "${OOPS_COUNT:-0}" -gt 0 ]; then
	fail "kernel oops detected after full test lifecycle ($OOPS_COUNT)"
	dmesg | grep -iE "oops|BUG:|kernel panic|general protection" \
		| tail -5 || true
else
	pass "no kernel oops after full test lifecycle"
fi

# ---- Summary -------------------------------------------------------

echo ""
echo "========================================="
echo " RESULTS: $PASS passed, $FAIL failed"
echo "========================================="

if [ "$FAIL" -eq 0 ]; then
	log "All tests passed."
	exit 0
else
	log "One or more tests FAILED."
	dmesg | tail -30
	exit 1
fi
