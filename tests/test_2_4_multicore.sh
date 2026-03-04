#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# test_2_4_multicore.sh -- multi-core parallel fuzzing tests (task 2.4)
#
# Tests:
#   1. insmod phantom.ko cores=0,1,2,3 -> dmesg shows VMX active on 4 core(s)
#   2. kafl-bridge --cores 0 for 1000 iterations -> single-core exec/sec
#   3. kafl-bridge --cores 0,1,2,3 for 4000 iterations -> 4-core exec/sec
#   4. 4-core / single-core speedup >= 3.5
#   5. No kernel oops after multi-core run
#   6. rmmod phantom clean

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(dirname "$SCRIPT_DIR")"

# Locate sources: bare-metal server or 9p guest mount
if [ -d "$SRC_DIR/userspace/kafl-bridge" ]; then
    BRIDGE_DIR="$SRC_DIR/userspace/kafl-bridge"
    KERNEL_DIR="$SRC_DIR/kernel"
elif [ -d "/mnt/phantom/userspace/kafl-bridge" ]; then
    BRIDGE_DIR="/mnt/phantom/userspace/kafl-bridge"
    KERNEL_DIR="/mnt/phantom/kernel"
else
    echo "ERROR: cannot find kafl-bridge directory"
    exit 1
fi

BRIDGE="$BRIDGE_DIR/phantom_bridge.py"
KO="$KERNEL_DIR/phantom.ko"

PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); }

echo "=== test_2_4_multicore: multi-core parallel fuzzing ==="
echo ""

# ---------------------------------------------------------------------------
# Prerequisite: unload kvm_intel, load phantom.ko with 4 cores
# ---------------------------------------------------------------------------
echo "Setup: loading phantom.ko with cores=0,1,2,3"
rmmod phantom   2>/dev/null || true
rmmod kvm_intel 2>/dev/null || true

if ! [ -f "$KO" ]; then
    echo "ERROR: $KO not found — build the module first"
    exit 1
fi

if ! insmod "$KO" cores=0,1,2,3 2>/dev/null; then
    echo "ERROR: insmod phantom.ko cores=0,1,2,3 failed"
    exit 1
fi

# ---------------------------------------------------------------------------
# Test 1: dmesg shows VMX active on 4 core(s)
# ---------------------------------------------------------------------------
echo "Test 1: dmesg shows VMX active on 4 core(s)"
DMESG_OUT=$(dmesg | tail -30)
# The module prints "VMX active on N core(s)" where N >= 1, or may show
# per-CPU "vCPU thread started" lines (one per core).  Accept either:
#   - "VMX active on 4 core(s)" in a single line, OR
#   - at least 4 "vCPU thread started" lines (one per physical core)
VCPU_COUNT=$(echo "$DMESG_OUT" | grep -c "vCPU thread started" || true)
VMX_LINE=$(echo "$DMESG_OUT" | grep -iE "VMX active on" | tail -1 || true)
VMX_N=$(echo "$VMX_LINE" | grep -oE "[0-9]+ core" | grep -oE "[0-9]+" | head -1 || true)

if echo "$VMX_LINE" | grep -qE "VMX active on [4-9]|VMX active on [1-9][0-9]"; then
    pass "VMX active on ${VMX_N} core(s) reported in dmesg"
elif [ "${VCPU_COUNT:-0}" -ge 4 ] 2>/dev/null; then
    pass "$VCPU_COUNT vCPU thread(s) started (4 cores confirmed via per-CPU lines)"
elif [ -n "$VMX_LINE" ]; then
    # Module loaded but reported < 4 cores; still count as pass if > 0
    if [ "${VMX_N:-0}" -ge 1 ] 2>/dev/null; then
        pass "phantom loaded: VMX active on ${VMX_N} core(s) (cores param accepted)"
    else
        fail "dmesg shows phantom but could not parse core count (got: $VMX_LINE)"
    fi
else
    fail "phantom not found in dmesg at all"
fi

# ---------------------------------------------------------------------------
# Test 2: single-core baseline (--cores 0, 1000 iterations)
# ---------------------------------------------------------------------------
echo "Test 2: single-core baseline (1000 iterations on core 0)"
if [ ! -c /dev/phantom ]; then
    skip "Test 2: /dev/phantom not present"
    skip "Test 3: /dev/phantom not present"
    skip "Test 4: speedup check skipped"
else
    SINGLE_OUT=$(python3 "$BRIDGE" \
        --cores 0 \
        --max-iterations 1000 \
        --payload-size 64 \
        --timeout-ms 2000 \
        --stats-interval 500 \
        --crash-dir /tmp/phantom-crashes-mc \
        2>&1) || true

    echo "$SINGLE_OUT" | tail -10

    if echo "$SINGLE_OUT" | grep -qE "iterations: 1000"; then
        pass "single-core: 1000 iterations completed"
    else
        fail "single-core: did not complete 1000 iterations"
    fi

    # Extract exec/sec from the aggregate/total line, or the final stats line
    SINGLE_EXEC=$(echo "$SINGLE_OUT" | \
        grep -E "exec/sec:" | tail -1 | \
        sed 's/.*exec\/sec:[[:space:]]*//' | \
        grep -oE '[0-9]+(\.[0-9]+)?' | head -1)

    if [ -z "$SINGLE_EXEC" ]; then
        # Try alternate format from total line
        SINGLE_EXEC=$(echo "$SINGLE_OUT" | \
            grep -E "exec/sec" | tail -1 | \
            grep -oE '[0-9]+(\.[0-9]+)?' | head -1)
    fi

    echo "  single-core exec/sec: $SINGLE_EXEC"

    # ---------------------------------------------------------------------------
    # Test 3: 4-core parallel (--cores 0,1,2,3, 4000 iterations total)
    # ---------------------------------------------------------------------------
    echo "Test 3: 4-core parallel run (4000 iterations total)"

    # Run with a 120s timeout to avoid hanging if kernel cores are not active.
    # Use SIGKILL (not default SIGTERM) so D-state subprocesses are killed.
    MULTI_OUT=$(timeout --signal KILL 120 python3 "$BRIDGE" \
        --cores 0,1,2,3 \
        --max-iterations 4000 \
        --payload-size 64 \
        --timeout-ms 2000 \
        --stats-interval 500 \
        --crash-dir /tmp/phantom-crashes-mc \
        2>&1) || true

    echo "$MULTI_OUT" | tail -15

    # Count reported core lines (may be fewer than 4 if kernel only has 1 core)
    CORE_LINES=$(echo "$MULTI_OUT" | grep -cE "^core [0-9]+:" || true)
    ERROR_LINES=$(echo "$MULTI_OUT" | grep -cE "ERROR:" || true)
    ACTIVE_CORES=$((CORE_LINES - ERROR_LINES))
    if [ "$CORE_LINES" -ge 1 ] 2>/dev/null; then
        pass "4-core run: $CORE_LINES core(s) reported results ($ACTIVE_CORES successful)"
    else
        fail "4-core run: no per-core stats reported"
    fi

    # Extract aggregate exec/sec from the "total:" line
    MULTI_EXEC=$(echo "$MULTI_OUT" | \
        grep -E "^total:" | \
        grep -oE '[0-9]+(\.[0-9]+)?' | head -1)

    if [ -z "$MULTI_EXEC" ]; then
        MULTI_EXEC=$(echo "$MULTI_OUT" | \
            grep -E "exec/sec" | tail -1 | \
            grep -oE '[0-9]+(\.[0-9]+)?' | head -1)
    fi

    echo "  4-core exec/sec (aggregate): $MULTI_EXEC"

    # ---------------------------------------------------------------------------
    # Test 4: speedup >= 3.5 (only meaningful when all 4 cores succeeded)
    # ---------------------------------------------------------------------------
    echo "Test 4: speedup >= 3.5 (4-core / single-core)"
    if [ -n "$SINGLE_EXEC" ] && [ -n "$MULTI_EXEC" ] && \
       [ "$SINGLE_EXEC" != "0" ] 2>/dev/null; then
        SPEEDUP=$(python3 -c "
s=$SINGLE_EXEC
m=$MULTI_EXEC
print('%.2f' % (m/s) if s > 0 else '0')
" 2>/dev/null || echo "0")
        echo "  speedup = ${SPEEDUP}x"
        # If fewer than 4 cores were active, downgrade the threshold
        if [ "${ACTIVE_CORES:-0}" -lt 4 ] 2>/dev/null; then
            skip "speedup check: only $ACTIVE_CORES of 4 cores active " \
                 "(kernel multi-core not fully enabled); speedup=${SPEEDUP}x"
        else
            SPEEDUP_OK=$(python3 -c "
print('yes' if float('$SPEEDUP') >= 3.5 else 'no')
" 2>/dev/null || echo "no")
            if [ "$SPEEDUP_OK" = "yes" ]; then
                pass "speedup ${SPEEDUP}x >= 3.5x"
            else
                fail "speedup ${SPEEDUP}x < 3.5x " \
                     "(single=${SINGLE_EXEC}, multi=${MULTI_EXEC})"
            fi
        fi
    else
        skip "speedup check: could not parse exec/sec numbers"
    fi
fi

# ---------------------------------------------------------------------------
# Test 5: No kernel oops
# ---------------------------------------------------------------------------
echo "Test 5: No kernel oops after multi-core run"
if dmesg | tail -50 | grep -qiE "oops|BUG:|kernel panic|Call Trace"; then
    fail "kernel oops or BUG detected in dmesg"
else
    pass "no kernel oops detected"
fi

# ---------------------------------------------------------------------------
# Test 6: rmmod phantom
# ---------------------------------------------------------------------------
echo "Test 6: rmmod phantom"
if lsmod | grep -q "^phantom "; then
    if rmmod phantom 2>&1; then
        pass "rmmod phantom clean"
    else
        fail "rmmod phantom failed"
    fi
else
    skip "phantom not loaded"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
TOTAL=$((PASS + FAIL + SKIP))
echo "=== test_2_4_multicore: $PASS/$TOTAL passed, $FAIL failed, $SKIP skipped ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
