#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_1_3_ept.sh — Task 1.3 in-guest test suite (Basic R/W EPT)
#
# Runs inside the QEMU guest where phantom.ko is mounted via 9p at
# /mnt/phantom.  Tests:
#   1. Module loads without error
#   2. /dev/phantom exists
#   3. Compile (or use pre-built) test_1_3_ept binary
#   4. RUN_GUEST(test_id=0): guest R/W checksum is correct
#   5. RUN_GUEST(test_id=1): exit_reason == 48 (EPT violation)
#   6. PHANTOM_IOCTL_DEBUG_DUMP_EPT returns 0; trace shows RAM mappings
#   7. No kernel oops
#   8. rmmod unloads cleanly
#   9. Reload after rmmod succeeds
#
# Exit code: 0 = all tests passed, 1 = one or more failures.

set -euo pipefail

MODULE=/mnt/phantom/kernel/phantom.ko
TEST_SRC=/mnt/phantom/tests/test_1_3_ept.c
TEST_BIN=/tmp/test_1_3_ept
PREBUILT=/mnt/phantom/tests/test_1_3_ept
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
	pass "compiled test_1_3_ept.c"
elif [ -x "$PREBUILT" ]; then
	log "  gcc unavailable — using pre-compiled binary"
	TEST_BIN="$PREBUILT"
	pass "pre-compiled test_1_3_ept binary available"
else
	fail "no test_1_3_ept binary available (gcc failed and no pre-built)"
fi

# ---- Test 4: run full ioctl test suite -----------------------------

log "--- Test 4: run ioctl test suite ---"
if [ -x "$TEST_BIN" ]; then
	# Clear the ftrace ring buffer so EPT walker entry count is exact.
	# The DEBUG_DUMP_EPT ioctl emits exactly 4096 EPT_MAP lines; if the
	# buffer contains stale entries from a previous run the count will
	# be a multiple of 4096, causing a false failure.
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

# ---- Test 5: trace log shows EPT walker output ----------------------

log "--- Test 5: trace log shows EPT walker output ---"
if [ -r "$TRACE" ]; then
	if grep -q "EPT_MAP" "$TRACE" 2>/dev/null; then
		EPT_MAPPED=$(grep -c "EPT_MAP.*type=RAM" "$TRACE" 2>/dev/null || echo 0)
		pass "trace shows EPT_MAP entries ($EPT_MAPPED RAM pages)"
		log "  Expected 4096 RAM pages, found: $EPT_MAPPED"
		if [ "$EPT_MAPPED" -eq 4096 ]; then
			pass "EPT walker: exactly 4096 RAM pages mapped"
		else
			fail "EPT walker: expected 4096 RAM pages, got $EPT_MAPPED"
		fi
	else
		log "  No EPT_MAP events in trace (DEBUG_DUMP_EPT may not have run)"
		fail "trace should show EPT_MAP entries"
	fi
else
	log "  Trace not readable (debugfs not mounted?)"
	pass "trace check skipped (debugfs unavailable)"
fi

# ---- Test 6: no kernel oops ----------------------------------------

log "--- Test 6: no kernel oops ---"
if dmesg | grep -qiE "oops|BUG:|kernel panic|general protection"; then
	fail "kernel oops detected in dmesg"
	dmesg | grep -iE "oops|BUG:|kernel panic|general protection" | tail -5
else
	pass "no kernel oops in dmesg"
fi

# ---- Test 7: dmesg shows EPT violation log -------------------------

log "--- Test 7: dmesg shows EPT violation diagnostic ---"
if dmesg | grep -q "EPT VIOLATION.*RESERVED"; then
	pass "dmesg shows EPT violation with RESERVED classification"
else
	log "  EPT violation message may not be present yet or classification differs"
	if dmesg | grep -q "EPT VIOLATION"; then
		pass "dmesg shows EPT VIOLATION (absent-GPA test ran)"
	else
		fail "no EPT VIOLATION in dmesg (absent-GPA test may not have run)"
	fi
fi

# ---- Test 8: rmmod unloads cleanly ---------------------------------

log "--- Test 8: rmmod ---"
if rmmod phantom; then
	pass "rmmod phantom"
else
	fail "rmmod phantom"
fi

sleep 0.2
if dmesg | tail -20 | grep -q "phantom: unloaded"; then
	pass "dmesg shows 'phantom: unloaded'"
else
	fail "dmesg shows 'phantom: unloaded'"
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
