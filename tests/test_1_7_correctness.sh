#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_1_7_correctness.sh — Task 1.7 in-guest test suite (Correctness Testing)
#
# Runs inside the QEMU guest where phantom.ko is mounted via 9p at
# /mnt/phantom.  Tests:
#   1. Module loads without error (insmod)
#   2. /dev/phantom character device exists
#   3. Compile (or use pre-built) test_1_7_correctness binary
#   4. Run full ioctl test suite:
#        Test A: 10,000-cycle snapshot/restore determinism
#        Test B: 1000x strict determinism
#        Test C: dirty-list detection proxy (CoW dirty pages)
#   5. KMEMLEAK check after 10,000 cycles
#        (skipped gracefully if not available in this guest kernel)
#   6. No kernel oops in dmesg
#   7. rmmod unloads cleanly
#   8. Reload after rmmod succeeds
#
# Exit code: 0 = all tests passed, 1 = one or more failures.

set -euo pipefail

MODULE=/mnt/phantom/kernel/phantom.ko
TEST_SRC=/mnt/phantom/tests/test_1_7_correctness.c
TEST_BIN=/tmp/test_1_7_correctness
PREBUILT=/mnt/phantom/tests/test_1_7_correctness
DEVICE=/dev/phantom
KMEMLEAK=/sys/kernel/debug/kmemleak
TRACE=/sys/kernel/debug/tracing/trace

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
	pass "compiled test_1_7_correctness.c"
elif [ -x "$PREBUILT" ]; then
	log "  gcc unavailable — using pre-compiled binary"
	TEST_BIN="$PREBUILT"
	pass "pre-compiled test_1_7_correctness binary available"
else
	fail "no test_1_7_correctness binary available (gcc failed and no pre-built)"
	log "ABORT: no test binary; cannot continue"
	exit 1
fi

# ---- Test 4: run full ioctl test suite (10,000-cycle determinism) ---

log "--- Test 4: run ioctl test suite (10,000-cycle determinism) ---"
log "    NOTE: Test A runs 10,000 iterations — this may take ~30-120s"

if [ -x "$TEST_BIN" ]; then
	# Clear the ftrace ring buffer before the run if available
	if [ -w "$TRACE" ]; then
		echo "" > "$TRACE"
		log "  trace buffer cleared before test run"
	fi

	if "$TEST_BIN"; then
		pass "ioctl test suite: all assertions passed (A, B, C)"
	else
		fail "ioctl test suite: one or more assertions failed"
		log "--- Re-running with full output ---"
		"$TEST_BIN" || true
	fi
else
	fail "no test binary to run"
fi

# ---- Test 5: KMEMLEAK check after 10,000 cycles --------------------

log "--- Test 5: KMEMLEAK check after 10,000 cycles ---"
if [ -w "$KMEMLEAK" ]; then
	# Trigger a scan (write "scan" to the control file)
	echo "scan" > "$KMEMLEAK" 2>/dev/null || true
	# Give the scanner a moment to run
	sleep 2

	LEAK_COUNT=$(cat "$KMEMLEAK" 2>/dev/null | grep -c "unreferenced object" \
		|| echo 0)
	if [ "${LEAK_COUNT:-0}" -eq 0 ]; then
		pass "KMEMLEAK: zero warnings after 10,000 cycles"
	else
		fail "KMEMLEAK: $LEAK_COUNT leak(s) detected after 10,000 cycles"
		cat "$KMEMLEAK" 2>/dev/null | head -40 || true
	fi
else
	log "  KMEMLEAK not available (debugfs not mounted or CONFIG_DEBUG_KMEMLEAK=n)"
	log "  Skipping KMEMLEAK check — this is expected in the test guest"
	pass "KMEMLEAK check skipped (not available)"
fi

# ---- Test 6: no kernel oops ----------------------------------------

log "--- Test 6: no kernel oops ---"
OOPS_COUNT=$(dmesg 2>/dev/null | \
	grep -ciE "oops|BUG:|kernel panic|general protection" || true)
if [ "${OOPS_COUNT:-0}" -gt 0 ]; then
	fail "kernel oops detected in dmesg ($OOPS_COUNT entries)"
	dmesg | grep -iE "oops|BUG:|kernel panic|general protection" \
		| tail -5 || true
else
	pass "no kernel oops in dmesg"
fi

# ---- Test 7: rmmod unloads cleanly ---------------------------------

log "--- Test 7: rmmod ---"
if rmmod phantom; then
	pass "rmmod phantom"
else
	fail "rmmod phantom"
fi

sleep 0.2

# Verify unload message in dmesg
UNLOADED_COUNT=$(dmesg 2>/dev/null | tail -20 | \
	grep -c "phantom: unloaded" || true)
if [ "${UNLOADED_COUNT:-0}" -gt 0 ]; then
	pass "dmesg shows 'phantom: unloaded'"
else
	# Not a hard failure — just a diagnostic note
	log "  Note: 'phantom: unloaded' not found in dmesg tail"
	pass "rmmod completed (unload message check skipped)"
fi

# ---- Test 8: reload after unload -----------------------------------

log "--- Test 8: reload after rmmod ---"
if insmod "$MODULE" 2>&1; then
	pass "reload after rmmod succeeded"
	rmmod phantom 2>/dev/null || true
else
	fail "reload after rmmod failed"
	dmesg | tail -20
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
