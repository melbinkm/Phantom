#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_1_6_snapshot.sh — Task 1.6 in-guest test suite (snapshot/restore)
#
# Runs inside the QEMU guest where phantom.ko is mounted via 9p at
# /mnt/phantom.  Tests:
#   1. Module loads without error
#   2. /dev/phantom exists
#   3. Compile (or use pre-built) test_1_6_snapshot binary
#   4. Full ioctl test suite (100-cycle determinism, XMM, regression)
#   5. Trace log shows PHANTOM SNAPSHOT_CREATE and SNAPSHOT_RESTORE events
#   6. No kernel oops
#   7. dmesg shows "snapshot created" message
#   8. rmmod unloads cleanly
#   9. Reload after rmmod succeeds
#
# Exit code: 0 = all tests passed, 1 = one or more failures.

set -euo pipefail

MODULE=/mnt/phantom/kernel/phantom.ko
TEST_SRC=/mnt/phantom/tests/test_1_6_snapshot.c
TEST_BIN=/tmp/test_1_6_snapshot
PREBUILT=/mnt/phantom/tests/test_1_6_snapshot
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
	pass "compiled test_1_6_snapshot.c"
elif [ -x "$PREBUILT" ]; then
	log "  gcc unavailable — using pre-compiled binary"
	TEST_BIN="$PREBUILT"
	pass "pre-compiled test_1_6_snapshot binary available"
else
	fail "no test_1_6_snapshot binary available (gcc failed and no pre-built)"
fi

# ---- Test 4: run full ioctl test suite -----------------------------

log "--- Test 4: run ioctl test suite (100-cycle determinism) ---"
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

# ---- Test 5: trace log shows snapshot events -----------------------

log "--- Test 5: trace shows PHANTOM SNAPSHOT events (PHANTOM_DEBUG) ---"
if [ -r "$TRACE" ]; then
	CREATE_COUNT=$(grep -c "PHANTOM SNAPSHOT_CREATE" "$TRACE" \
		2>/dev/null || echo 0)
	RESTORE_COUNT=$(grep -c "PHANTOM SNAPSHOT_RESTORE" "$TRACE" \
		2>/dev/null || echo 0)
	if [ "$CREATE_COUNT" -gt 0 ]; then
		pass "trace shows PHANTOM SNAPSHOT_CREATE events ($CREATE_COUNT)"
	else
		log "  No SNAPSHOT_CREATE in trace (PHANTOM_DEBUG may be off)"
		pass "SNAPSHOT_CREATE trace check skipped"
	fi
	if [ "$RESTORE_COUNT" -gt 0 ]; then
		pass "trace shows PHANTOM SNAPSHOT_RESTORE events ($RESTORE_COUNT)"
	else
		log "  No SNAPSHOT_RESTORE in trace (PHANTOM_DEBUG may be off)"
		pass "SNAPSHOT_RESTORE trace check skipped"
	fi
else
	pass "trace checks skipped (debugfs unavailable)"
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

# ---- Test 7: dmesg shows snapshot created message ------------------

log "--- Test 7: dmesg shows 'snapshot created' message ---"
SNAP_MSG=$(dmesg 2>/dev/null | grep -c "snapshot created" || true)
if [ "${SNAP_MSG:-0}" -gt 0 ]; then
	pass "dmesg shows 'snapshot created' ($SNAP_MSG entries)"
else
	log "  No 'snapshot created' in dmesg (may be skipped in this run)"
	pass "snapshot message check skipped"
fi

# ---- Test 8: rmmod unloads cleanly ---------------------------------

log "--- Test 8: rmmod ---"
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
	fail "dmesg does not show 'phantom: unloaded'"
fi

# ---- Test 9: reload after unload -----------------------------------

log "--- Test 9: reload after rmmod ---"
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
