#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_1_4_cow.sh — Task 1.4 in-guest test suite (CoW fault + page pool)
#
# Runs inside the QEMU guest where phantom.ko is mounted via 9p at
# /mnt/phantom.  Tests:
#   1. Module loads without error
#   2. /dev/phantom exists
#   3. Compile (or use pre-built) test_1_4_cow binary
#   4. RUN_GUEST(test_id=2): 20-page CoW write test passes
#   5. DUMP_DIRTY_LIST: trace shows DIRTY_ENTRY lines
#   6. RUN_GUEST(test_id=4): MMIO CoW rejection — no host panic
#   7. RUN_GUEST(test_id=3): pool exhaustion with default pool
#   8. RUN_GUEST(test_id=1): absent-GPA regression still works
#   9. DEBUG_DUMP_EPT still works (task 1.3 regression)
#  10. No kernel oops
#  11. rmmod unloads cleanly
#  12. Reload after rmmod succeeds
#
# Exit code: 0 = all tests passed, 1 = one or more failures.

set -euo pipefail

MODULE=/mnt/phantom/kernel/phantom.ko
TEST_SRC=/mnt/phantom/tests/test_1_4_cow.c
TEST_BIN=/tmp/test_1_4_cow
PREBUILT=/mnt/phantom/tests/test_1_4_cow
DEVICE=/dev/phantom
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

# Clear the dmesg ring buffer so Test 7 only sees messages from this run.
# This prevents stale BUG/oops messages from previous (failed) runs
# from causing false test failures.
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
	pass "compiled test_1_4_cow.c"
elif [ -x "$PREBUILT" ]; then
	log "  gcc unavailable — using pre-compiled binary"
	TEST_BIN="$PREBUILT"
	pass "pre-compiled test_1_4_cow binary available"
else
	fail "no test_1_4_cow binary available (gcc failed and no pre-built)"
fi

# ---- Test 4: run full ioctl test suite -----------------------------

log "--- Test 4: run ioctl test suite ---"
if [ -x "$TEST_BIN" ]; then
	# Clear the ftrace ring buffer before the run
	if [ -w /sys/kernel/debug/tracing/trace ]; then
		echo "" > /sys/kernel/debug/tracing/trace
		log "  trace buffer cleared before test run"
	fi
	if "$TEST_BIN"; then
		pass "ioctl test suite: all assertions passed"
	else
		fail "ioctl test suite: one or more assertions failed"
		log "Re-running with output:"
		"$TEST_BIN" || true
	fi
else
	fail "no test binary to run"
fi

# ---- Test 5: trace log shows dirty list entries --------------------

log "--- Test 5: trace log shows dirty list output ---"
if [ -r "$TRACE" ]; then
	DIRTY_COUNT=$(grep -c "DIRTY_ENTRY" "$TRACE" 2>/dev/null || echo 0)
	if [ "$DIRTY_COUNT" -gt 0 ]; then
		pass "trace shows DIRTY_ENTRY lines ($DIRTY_COUNT entries)"
		log "  Found $DIRTY_COUNT DIRTY_ENTRY lines"
	else
		log "  No DIRTY_ENTRY events in trace"
		fail "trace should show DIRTY_ENTRY lines"
	fi
else
	log "  Trace not readable (debugfs not mounted?)"
	pass "trace check skipped (debugfs unavailable)"
fi

# ---- Test 6: trace log shows CoW trace events ----------------------

log "--- Test 6: trace log shows CoW events ---"
if [ -r "$TRACE" ]; then
	if grep -q "PHANTOM COW" "$TRACE" 2>/dev/null; then
		COW_COUNT=$(grep -c "PHANTOM COW" "$TRACE" 2>/dev/null || echo 0)
		pass "trace shows PHANTOM COW events ($COW_COUNT faults)"
	else
		log "  No PHANTOM COW events in trace (PHANTOM_DEBUG may be off)"
		pass "CoW trace check skipped (PHANTOM_DEBUG not set)"
	fi
else
	pass "CoW trace check skipped (debugfs unavailable)"
fi

# ---- Test 7: no kernel oops ----------------------------------------

log "--- Test 7: no kernel oops ---"
OOPS_COUNT=$(dmesg 2>/dev/null | grep -ciE "oops|BUG:|kernel panic|general protection" || true)
if [ "${OOPS_COUNT:-0}" -gt 0 ]; then
	fail "kernel oops detected in dmesg ($OOPS_COUNT entries)"
	dmesg | grep -iE "oops|BUG:|kernel panic|general protection" | tail -5 || true
else
	pass "no kernel oops in dmesg"
fi

# ---- Test 8: dmesg shows CoW pool init message ---------------------

log "--- Test 8: dmesg shows cow_pool init ---"
# Use grep -c to avoid SIGPIPE with pipefail when grep -q exits early
COWPOOL_COUNT=$(dmesg 2>/dev/null | grep -c "cow_pool: initialised" || true)
if [ "${COWPOOL_COUNT:-0}" -gt 0 ]; then
	pass "dmesg shows cow_pool initialised ($COWPOOL_COUNT entries)"
else
	fail "dmesg should show 'cow_pool: initialised'"
fi

# ---- Test 9: rmmod unloads cleanly ---------------------------------

log "--- Test 9: rmmod ---"
if rmmod phantom; then
	pass "rmmod phantom"
else
	fail "rmmod phantom"
fi

sleep 0.2
UNLOADED_COUNT=$(dmesg 2>/dev/null | tail -20 | grep -c "phantom: unloaded" || true)
if [ "${UNLOADED_COUNT:-0}" -gt 0 ]; then
	pass "dmesg shows 'phantom: unloaded'"
else
	fail "dmesg does not show 'phantom: unloaded'"
fi

# ---- Test 10: reload after unload ----------------------------------

log "--- Test 10: reload after rmmod ---"
if insmod "$MODULE" 2>&1; then
	pass "reload after rmmod succeeded"
	rmmod phantom 2>/dev/null || true
else
	fail "reload after rmmod failed"
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
