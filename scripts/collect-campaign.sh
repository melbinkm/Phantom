#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# collect-campaign.sh — Wait for running fuzz.py campaign processes to exit,
# then collect results from /proc/PID/fd before the inodes are freed.
#
# Usage: collect-campaign.sh [PID ...]
#   Defaults to finding all python3 fuzz.py processes automatically.

set -uo pipefail

PIDS=("$@")

if [ ${#PIDS[@]} -eq 0 ]; then
    mapfile -t PIDS < <(pgrep -f 'fuzz.py --duration' 2>/dev/null || true)
fi

if [ ${#PIDS[@]} -eq 0 ]; then
    echo "No fuzz.py processes found."
    exit 0
fi

echo "Watching PIDs: ${PIDS[*]}"
RESULTS_DIR="/tmp/campaign-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"

# Snapshot stdout (fd 1) from each process while still alive
for pid in "${PIDS[@]}"; do
    if [ -e "/proc/$pid/fd/1" ]; then
        echo "  Snapshotting /proc/$pid/fd/1 ..."
        cat "/proc/$pid/fd/1" > "$RESULTS_DIR/log-pid-$pid.txt" 2>/dev/null || true
    fi
done

# Wait for all campaign processes to exit
echo "Waiting for processes to exit ..."
for pid in "${PIDS[@]}"; do
    while kill -0 "$pid" 2>/dev/null; do
        sleep 5
        # Try to capture any newly flushed data
        if [ -e "/proc/$pid/fd/1" ]; then
            cat "/proc/$pid/fd/1" >> "$RESULTS_DIR/log-pid-$pid.txt" 2>/dev/null || true
        fi
    done
    echo "  PID $pid exited"
done

echo ""
echo "=== Campaign results in $RESULTS_DIR ==="
for f in "$RESULTS_DIR"/*.txt; do
    echo ""
    echo "--- $f ---"
    cat "$f"
done

echo ""
echo "Crash files:"
find /root/phantom/src -name 'campaign_crashes_*' 2>/dev/null | head -20 || echo "(none found)"
