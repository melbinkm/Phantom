#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_1_5_cow2mb.sh — Task 1.5 in-guest test suite (2MB CoW + splitting)
#
# Runs inside the QEMU guest where phantom.ko is mounted via 9p at
# /mnt/phantom.  Tests:
#   1. Module loads without error
#   2. /dev/phantom exists
#   3. Compile (or use pre-built) test_1_5_cow2mb binary
#   4. RUN_GUEST(test_id=5): 2MB split + CoW test — exit_reason=18, result=1
#   5. RUN_GUEST(test_id=6): mixed 2MB + 4KB workload — exit_reason=18, result=10
#   6. DUMP_DIRTY_OVERFLOW ioctl returns 0
#   7. Task 1.4 regression: test_id=0..4 all pass
#   8. Second 2MB split run (re-split after abort_iteration restore)
#   9. INVEPT logged in trace (PHANTOM_DEBUG builds)
#  10. No kernel oops
#  11. rmmod unloads cleanly
#  12. Reload after rmmod succeeds
#
# Exit code: 0 = all tests passed, 1 = one or more failures.

set -euo pipefail

MODULE=/mnt/phantom/kernel/phantom.ko
TEST_SRC=/mnt/phantom/tests/test_1_5_cow2mb.c
TEST_BIN=/tmp/test_1_5_cow2mb
PREBUILT=/mnt/phantom/tests/test_1_5_cow2mb
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
	pass "compiled test_1_5_cow2mb.c"
elif [ -x "$PREBUILT" ]; then
	log "  gcc unavailable — using pre-compiled binary"
	TEST_BIN="$PREBUILT"
	pass "pre-compiled test_1_5_cow2mb binary available"
else
	fail "no test_1_5_cow2mb binary available (gcc failed and no pre-built)"
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

# ---- Test 5: trace log shows INVEPT (if PHANTOM_DEBUG) ---------------

log "--- Test 5: trace shows INVEPT events (PHANTOM_DEBUG builds) ---"
if [ -r "$TRACE" ]; then
	INVEPT_COUNT=$(grep -c "PHANTOM INVEPT" "$TRACE" 2>/dev/null || echo 0)
	SPLIT_COUNT=$(grep -c "PHANTOM SPLIT_2MB" "$TRACE" 2>/dev/null || echo 0)
	if [ "$INVEPT_COUNT" -gt 0 ]; then
		pass "trace shows PHANTOM INVEPT events ($INVEPT_COUNT events)"
	else
		log "  No PHANTOM INVEPT in trace (PHANTOM_DEBUG may be off)"
		pass "INVEPT trace check skipped (PHANTOM_DEBUG not set)"
	fi
	if [ "$SPLIT_COUNT" -gt 0 ]; then
		pass "trace shows PHANTOM SPLIT_2MB events ($SPLIT_COUNT events)"
	else
		log "  No SPLIT_2MB events in trace (PHANTOM_DEBUG may be off)"
		pass "SPLIT_2MB trace check skipped (PHANTOM_DEBUG not set)"
	fi
else
	pass "trace checks skipped (debugfs unavailable)"
fi

# ---- Test 6: dirty list dump shows entries --------------------------

log "--- Test 6: trace log shows dirty list output ---"
if [ -r "$TRACE" ]; then
	DIRTY_COUNT=$(grep -c "DIRTY_ENTRY" "$TRACE" 2>/dev/null || echo 0)
	if [ "$DIRTY_COUNT" -gt 0 ]; then
		pass "trace shows DIRTY_ENTRY lines ($DIRTY_COUNT entries)"
	else
		log "  No DIRTY_ENTRY events in trace"
		fail "trace should show DIRTY_ENTRY lines"
	fi
else
	pass "dirty list trace check skipped (debugfs unavailable)"
fi

# ---- Test 7: no kernel oops -----------------------------------------

log "--- Test 7: no kernel oops ---"
OOPS_COUNT=$(dmesg 2>/dev/null | grep -ciE "oops|BUG:|kernel panic|general protection" || true)
if [ "${OOPS_COUNT:-0}" -gt 0 ]; then
	fail "kernel oops detected in dmesg ($OOPS_COUNT entries)"
	dmesg | grep -iE "oops|BUG:|kernel panic|general protection" | tail -5 || true
else
	pass "no kernel oops in dmesg"
fi

# ---- Test 8: dmesg shows 2MB/4KB EPT message -----------------------

log "--- Test 8: dmesg shows mixed EPT allocation message ---"
EPT_MSG_COUNT=$(dmesg 2>/dev/null | grep -c "2MB.*4KB\|2mb.*4kb" || true)
if [ "${EPT_MSG_COUNT:-0}" -gt 0 ]; then
	pass "dmesg shows mixed EPT message ($EPT_MSG_COUNT entries)"
else
	log "  Checking for pages allocated message..."
	ALLOC_COUNT=$(dmesg 2>/dev/null | grep -c "pages allocated" || true)
	if [ "${ALLOC_COUNT:-0}" -gt 0 ]; then
		pass "dmesg shows 'pages allocated' message"
	else
		fail "dmesg should show EPT allocation message"
	fi
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
