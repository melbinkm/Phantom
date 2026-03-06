#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# run_afl_nft.sh — Launch AFL++ fuzzing of nf_tables via Phantom
#
# Usage:
#   bash scripts/run_afl_nft.sh [--seeds DIR] [--output DIR] [--timeout SEC]
#
# Prerequisites:
#   - phantom.ko loaded (phantom_cores=0 or similar)
#   - afl-phantom built (make -C userspace/afl-phantom)
#   - nft guest kernel bzImage at BZIMAGE path
#   - seed corpus generated (make -C guest/guest_kernel seeds)

set -euo pipefail

BZIMAGE="${BZIMAGE:-/root/phantom/linux-6.1.90/arch/x86/boot/bzImage}"
SEEDS="${SEEDS:-/root/phantom/src/guest/guest_kernel/seeds/corpus}"
OUTPUT="${OUTPUT:-/tmp/phantom-afl-nft}"
AFL_PHANTOM="/root/phantom/src/userspace/afl-phantom/afl-phantom"
BOOT_WAIT="${BOOT_WAIT:-12}"
TIMEOUT_MS="${TIMEOUT_MS:-1000}"
CPU="${CPU:-0}"
GUEST_MEM="${GUEST_MEM:-256}"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --seeds)   SEEDS="$2";    shift 2 ;;
        --output)  OUTPUT="$2";   shift 2 ;;
        --timeout) TIMEOUT_MS="$2"; shift 2 ;;
        --bzimage) BZIMAGE="$2";  shift 2 ;;
        --cpu)     CPU="$2";      shift 2 ;;
        *)         echo "Unknown: $1"; exit 1 ;;
    esac
done

# Validate
if [ ! -f "$BZIMAGE" ]; then
    echo "ERROR: bzImage not found: $BZIMAGE"
    echo "Build with: make -C guest/guest_kernel setup HARNESS=nft && make -C guest/guest_kernel bzImage"
    exit 1
fi

if [ ! -d "$SEEDS" ] || [ -z "$(ls -A "$SEEDS" 2>/dev/null)" ]; then
    echo "ERROR: seed corpus empty: $SEEDS"
    echo "Generate with: make -C guest/guest_kernel seeds"
    exit 1
fi

if [ ! -f "$AFL_PHANTOM" ]; then
    echo "ERROR: afl-phantom not built: $AFL_PHANTOM"
    echo "Build with: make -C userspace/afl-phantom"
    exit 1
fi

if [ ! -c /dev/phantom ]; then
    echo "ERROR: /dev/phantom not found. Load phantom.ko first."
    exit 1
fi

# Set core_pattern if needed
if grep -q '|' /proc/sys/kernel/core_pattern 2>/dev/null; then
    echo core > /proc/sys/kernel/core_pattern
fi

echo "=== AFL++ nf_tables fuzzing via Phantom ==="
echo "  bzImage:    $BZIMAGE"
echo "  seeds:      $SEEDS ($(ls "$SEEDS" | wc -l) files)"
echo "  output:     $OUTPUT"
echo "  cpu:        $CPU"
echo "  timeout:    ${TIMEOUT_MS}ms"
echo "  boot-wait:  ${BOOT_WAIT}s"
echo ""

mkdir -p "$OUTPUT"

# AFL++ environment
export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_FORKSRV_INIT_TMOUT=30000

exec afl-fuzz \
    -i "$SEEDS" \
    -o "$OUTPUT" \
    -t "$TIMEOUT_MS" \
    -- "$AFL_PHANTOM" \
        --bzimage "$BZIMAGE" \
        --boot-wait "$BOOT_WAIT" \
        --cpu "$CPU" \
        --guest-mem "$GUEST_MEM" \
        --timeout-ms "$TIMEOUT_MS"
