#!/usr/bin/env bash
set -euo pipefail
PASS=0; FAIL=0
log() { echo "[$(date +%H:%M:%S)] $*"; }
pass() { log "PASS  $*"; PASS=$((PASS + 1)); }
fail() { log "FAIL  $*"; FAIL=$((FAIL + 1)); }

log "=== Crash Detection Test Suite ==="
log "Server: $(ssh phantom-bench uname -n)  Kernel: $(ssh phantom-bench uname -r)"

# Test 1: kvm_intel unloaded
ssh phantom-bench "lsmod | grep -q kvm_intel && exit 1 || exit 0" \
  && pass "kvm_intel not loaded" || fail "kvm_intel still loaded"

# Test 2: insmod
ssh phantom-bench "rmmod phantom 2>/dev/null; rmmod kvm_intel 2>/dev/null; \
  insmod /root/phantom/src/kernel/phantom.ko" \
  && pass "insmod" || { fail "insmod failed"; exit 1; }

# Test 3: compile test_crash.c
ssh phantom-bench "gcc -O2 -o /tmp/test_crash \
  /root/phantom/src/tests/test_crash.c \
  -I/root/phantom/src/kernel/ 2>&1" \
  && pass "compiled test_crash.c" || { fail "compile failed"; exit 1; }

# Test 4: run C test suite
OUTPUT=$(ssh phantom-bench "/tmp/test_crash 2>&1")
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "Results:.*0 failed" \
  && pass "C test suite: all subtests passed" \
  || fail "C test suite: some subtests failed"

# Test 5: no kernel oops
ssh phantom-bench "dmesg | grep -iE '(BUG:|Oops|kernel panic)'" \
  && fail "kernel oops detected" || pass "no kernel oops"

# Test 6: rmmod
ssh phantom-bench "rmmod phantom" \
  && pass "rmmod" || fail "rmmod failed"

echo ""
echo "================================================="
echo " RESULTS: $PASS passed, $FAIL failed"
echo "================================================="
[[ $FAIL -eq 0 ]]
