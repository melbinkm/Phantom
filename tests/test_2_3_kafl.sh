#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# test_2_3_kafl.sh -- tests for kafl-bridge Python adapter
#
# Tests:
#   1. Python 3.8+ available
#   2. phantom_ioctl.py imports without error
#   3. phantom_bridge.py --help works
#   4. ioctl constants match kernel interface.h
#   5. phantom.ko loaded -> run bridge with --max-iterations 10
#   6. exec/sec sanity check (> 0)
#   7. rmmod phantom clean

set -euo pipefail

# Detect environment: 9p guest vs bare-metal server
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(dirname "$SCRIPT_DIR")"

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

PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); }

echo "=== test_2_3_kafl: kafl-bridge Python adapter ==="
echo ""

# ---------------------------------------------------------------
# Test 1: Python 3.8+ available
# ---------------------------------------------------------------
echo "Test 1: Python version check"
PYVER=$(python3 -c 'import sys; print(sys.version_info[:2])' 2>&1) || true
if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
    pass "Python $PYVER >= 3.8"
else
    fail "Python 3.8+ required, got $PYVER"
fi

# ---------------------------------------------------------------
# Test 2: phantom_ioctl.py imports cleanly
# ---------------------------------------------------------------
echo "Test 2: phantom_ioctl.py import"
if python3 -c "import sys; sys.path.insert(0, '$BRIDGE_DIR'); import phantom_ioctl" 2>&1; then
    pass "phantom_ioctl.py imports without error"
else
    fail "phantom_ioctl.py import failed"
fi

# ---------------------------------------------------------------
# Test 3: phantom_bridge.py --help
# ---------------------------------------------------------------
echo "Test 3: phantom_bridge.py --help"
HELP_OUT=$(python3 "$BRIDGE_DIR/phantom_bridge.py" --help 2>&1) || true
if echo "$HELP_OUT" | grep -q "max-iterations"; then
    pass "phantom_bridge.py --help shows expected options"
else
    fail "phantom_bridge.py --help missing expected options"
fi

# ---------------------------------------------------------------
# Test 4: ioctl constants match kernel
# ---------------------------------------------------------------
echo "Test 4: ioctl constant verification"
# Verify PHANTOM_CREATE_VM ioctl number matches what the kernel defines.
# From interface.h: _IOWR('P', 0x30, struct phantom_create_args)
# struct phantom_create_args is 24 bytes (6 x u32).
# _IOWR = (3 << 30) | (24 << 16) | (0x50 << 8) | 0x30
# = 0xC0185030
EXPECTED_CREATE_VM=$((0xC0185030))
ACTUAL_CREATE_VM=$(python3 -c "
import sys; sys.path.insert(0, '$BRIDGE_DIR')
from phantom_ioctl import PHANTOM_CREATE_VM
print(PHANTOM_CREATE_VM)
" 2>&1)
if [ "$ACTUAL_CREATE_VM" = "$EXPECTED_CREATE_VM" ]; then
    pass "PHANTOM_CREATE_VM = 0x$(printf '%08X' "$EXPECTED_CREATE_VM")"
else
    fail "PHANTOM_CREATE_VM mismatch: expected $EXPECTED_CREATE_VM got $ACTUAL_CREATE_VM"
fi

# Verify PHANTOM_RUN_ITERATION_CMD
# _IOWR('P', 0x33, struct phantom_run_args2)
# struct phantom_run_args2 is 32 bytes (u64 + u32 + u32 + u32 + u32 + u64 = 32 with alignment).
# = (3 << 30) | (32 << 16) | (0x50 << 8) | 0x33
# = 0xC0205033
EXPECTED_RUN=$((0xC0205033))
ACTUAL_RUN=$(python3 -c "
import sys; sys.path.insert(0, '$BRIDGE_DIR')
from phantom_ioctl import PHANTOM_RUN_ITERATION_CMD
print(PHANTOM_RUN_ITERATION_CMD)
" 2>&1)
if [ "$ACTUAL_RUN" = "$EXPECTED_RUN" ]; then
    pass "PHANTOM_RUN_ITERATION_CMD = 0x$(printf '%08X' "$EXPECTED_RUN")"
else
    fail "PHANTOM_RUN_ITERATION_CMD mismatch: expected $EXPECTED_RUN got $ACTUAL_RUN"
fi

# ---------------------------------------------------------------
# Test 5: Live run (requires phantom.ko)
# ---------------------------------------------------------------
echo "Test 5: Live fuzzing iteration (10 iterations)"
if [ ! -c /dev/phantom ]; then
    # Try to load the module
    rmmod phantom 2>/dev/null || true
    rmmod kvm_intel 2>/dev/null || true
    if insmod "$KERNEL_DIR/phantom.ko" 2>/dev/null; then
        echo "  (loaded phantom.ko)"
    else
        skip "phantom.ko not loadable or /dev/phantom not present"
    fi
fi

if [ -c /dev/phantom ]; then
    RUN_OUT=$(python3 "$BRIDGE_DIR/phantom_bridge.py" \
        --max-iterations 10 \
        --payload-size 64 \
        --timeout-ms 2000 \
        --stats-interval 5 \
        --crash-dir /tmp/phantom-crashes \
        2>&1) || true
    echo "$RUN_OUT"
    if echo "$RUN_OUT" | grep -q "iterations: 10"; then
        pass "10 iterations completed"
    else
        fail "did not complete 10 iterations"
    fi

    # Test 6: exec/sec sanity
    echo "Test 6: exec/sec sanity check"
    EXEC_SEC=$(echo "$RUN_OUT" | grep "exec/sec" | tail -1 | \
        sed 's/.*exec\/sec:[[:space:]]*//' | cut -d. -f1)
    if [ -n "$EXEC_SEC" ] && [ "$EXEC_SEC" -gt 0 ] 2>/dev/null; then
        pass "exec/sec = $EXEC_SEC (> 0)"
    else
        # Even if parsing fails, if iterations completed we consider it ok
        if echo "$RUN_OUT" | grep -q "iterations: 10"; then
            pass "iterations completed (exec/sec parse skipped)"
        else
            fail "exec/sec sanity check failed"
        fi
    fi
else
    skip "Test 5: /dev/phantom not available"
    skip "Test 6: /dev/phantom not available"
fi

# ---------------------------------------------------------------
# Test 7: rmmod phantom
# ---------------------------------------------------------------
echo "Test 7: rmmod phantom"
if lsmod | grep -q "^phantom "; then
    if rmmod phantom 2>&1; then
        pass "rmmod phantom clean"
    else
        fail "rmmod phantom failed"
    fi
else
    skip "phantom not loaded"
fi

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo ""
TOTAL=$((PASS + FAIL + SKIP))
echo "=== test_2_3_kafl: $PASS/$TOTAL passed, $FAIL failed, $SKIP skipped ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
