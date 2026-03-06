#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# post-campaign-test.sh — After the 1-hour campaign, reload phantom.ko with
# preemption timer and run the full 8-test suite.
#
# Run on phantom-bench as root from /root/phantom/src

set -uo pipefail
SRC=/root/phantom/src

echo "=== post-campaign-test.sh ==="
echo ""

# 1. Ensure old campaign processes are done
echo "Step 1: Check for lingering campaign processes"
pids=$(pgrep -f 'fuzz.py --duration' 2>/dev/null || true)
if [ -n "$pids" ]; then
    echo "  Waiting for campaign PIDs: $pids"
    wait $pids 2>/dev/null || true
fi
echo "  Campaign processes done"

# 2. Unload old phantom.ko
echo ""
echo "Step 2: Unload phantom"
rmmod phantom 2>/dev/null && echo "  rmmod OK" || echo "  phantom not loaded"
rmmod kvm_intel 2>/dev/null || true

# 3. Build new phantom.ko (includes preemption timer)
echo ""
echo "Step 3: Build phantom.ko"
make -C "$SRC/kernel/" 2>&1 | tail -5

# 4. Build guest harness (if not already built)
echo ""
echo "Step 4: Build guest harness"
if [ ! -f "$SRC/guest/libxml2_harness.bin.flat" ]; then
    make -C "$SRC/guest/" 2>&1 | tail -5
else
    echo "  harness already built"
fi

# 5. Load new phantom.ko
echo ""
echo "Step 5: Load phantom.ko (phantom_cores=0,1,2,3)"
insmod "$SRC/kernel/phantom.ko" "phantom_cores=0,1,2,3" && echo "  insmod OK"

echo ""
dmesg | tail -10

# 6. Run the 8-test suite
echo ""
echo "Step 6: Run test_2_4_multicore.sh"
bash "$SRC/tests/test_2_4_multicore.sh" 2>&1
TEST_RC=$?

# 7. Start seeded campaign in /tmp (not /root/phantom/src — avoids rsync deletion)
echo ""
if [ $TEST_RC -eq 0 ]; then
    echo "Step 7: Start seeded 4-core campaign (1 hour, logs to /tmp/phantom-campaign2)"
    mkdir -p /tmp/phantom-campaign2
    for cpu in 0 1 2 3; do
        mkdir -p /tmp/phantom-campaign2/crashes-cpu${cpu}
        python3 "$SRC/userspace/phantom-fuzz-libxml2/fuzz.py" \
            --duration 3600 \
            --cpu ${cpu} \
            --timeout-ms 1000 \
            --crash-dir /tmp/phantom-campaign2/crashes-cpu${cpu} \
            > /tmp/phantom-campaign2/log-cpu${cpu}.txt 2>&1 &
        echo "  Started fuzzer on CPU ${cpu} (pid $!)"
    done
    echo "  Campaign running. Check /tmp/phantom-campaign2/log-cpu*.txt"
else
    echo "Step 7: SKIPPED — tests failed (exit $TEST_RC)"
fi

echo ""
echo "=== Done ==="
