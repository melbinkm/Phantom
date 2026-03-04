#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# phantom-multi.sh -- multi-core Phantom fuzzer launcher
#
# Usage:
#   phantom-multi.sh [--cores N] [--corpus DIR] [--output DIR]
#                    [--duration SECONDS] [--payload-size BYTES]
#                    [--timeout-ms MS] [--module PATH]
#
# Default: --cores 4 --duration 60
#
# Steps:
#   1. Verify kvm_intel is unloaded (or unload it)
#   2. Load phantom.ko with cores=0,...,N-1
#   3. Run kafl-bridge --cores 0,...,N-1 for --duration seconds
#   4. Print aggregate exec/sec and per-core stats
#   5. rmmod phantom

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
CORES=4
DURATION=60
CORPUS_DIR=""
OUTPUT_DIR="./phantom-out"
PAYLOAD_SIZE=256
TIMEOUT_MS=1000
MODULE_PATH=""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(dirname "$SCRIPT_DIR")"
BRIDGE="$SRC_DIR/userspace/kafl-bridge/phantom_bridge.py"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cores)
            CORES="$2"; shift 2 ;;
        --corpus)
            CORPUS_DIR="$2"; shift 2 ;;
        --output)
            OUTPUT_DIR="$2"; shift 2 ;;
        --duration)
            DURATION="$2"; shift 2 ;;
        --payload-size)
            PAYLOAD_SIZE="$2"; shift 2 ;;
        --timeout-ms)
            TIMEOUT_MS="$2"; shift 2 ;;
        --module)
            MODULE_PATH="$2"; shift 2 ;;
        --help|-h)
            sed -n '3,20p' "$0"
            exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Locate phantom.ko
# ---------------------------------------------------------------------------
if [ -z "$MODULE_PATH" ]; then
    if [ -f "$SRC_DIR/kernel/phantom.ko" ]; then
        MODULE_PATH="$SRC_DIR/kernel/phantom.ko"
    else
        echo "ERROR: cannot find phantom.ko; use --module PATH" >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Build core list string for module parameter and bridge flag
# ---------------------------------------------------------------------------
if ! [[ "$CORES" =~ ^[0-9]+$ ]] || [ "$CORES" -lt 1 ] || [ "$CORES" -gt 8 ]; then
    echo "ERROR: --cores must be an integer 1..8" >&2
    exit 1
fi

CORE_LIST=""
CORE_PARAM=""
for i in $(seq 0 $((CORES - 1))); do
    if [ -z "$CORE_LIST" ]; then
        CORE_LIST="$i"
        CORE_PARAM="$i"
    else
        CORE_LIST="$CORE_LIST,$i"
        CORE_PARAM="$CORE_PARAM,$i"
    fi
done

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found" >&2
    exit 1
fi

if [ ! -f "$BRIDGE" ]; then
    echo "ERROR: phantom_bridge.py not found at $BRIDGE" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Ensure kvm_intel is unloaded
# ---------------------------------------------------------------------------
echo "[phantom-multi] Checking kvm_intel..."
if lsmod 2>/dev/null | grep -q "^kvm_intel "; then
    echo "[phantom-multi] Unloading kvm_intel..."
    rmmod kvm_intel || { echo "ERROR: cannot rmmod kvm_intel" >&2; exit 1; }
fi
echo "[phantom-multi] kvm_intel not loaded: OK"

# ---------------------------------------------------------------------------
# 2. Load phantom.ko with all requested cores activated
# ---------------------------------------------------------------------------
echo "[phantom-multi] Loading phantom.ko (cores=$CORE_PARAM)..."
if lsmod 2>/dev/null | grep -q "^phantom "; then
    rmmod phantom || true
fi
insmod "$MODULE_PATH" "cores=$CORE_PARAM" || {
    echo "ERROR: insmod phantom.ko failed" >&2
    exit 1
}

# Give the module a moment to set up the chardev
sleep 0.2

if [ ! -c /dev/phantom ]; then
    echo "ERROR: /dev/phantom not created after insmod" >&2
    rmmod phantom 2>/dev/null || true
    exit 1
fi

echo "[phantom-multi] phantom.ko loaded, /dev/phantom ready"

# ---------------------------------------------------------------------------
# 3. Run kafl-bridge for --duration seconds
# ---------------------------------------------------------------------------
mkdir -p "$OUTPUT_DIR"
CRASH_DIR="$OUTPUT_DIR/crashes"

# Estimate iterations: 10k per second per core is conservative; the bridge
# will stop after this many or when killed.
MAX_ITERS=$(( DURATION * 10000 * CORES ))

BRIDGE_ARGS=(
    "--max-iterations" "$MAX_ITERS"
    "--payload-size"   "$PAYLOAD_SIZE"
    "--timeout-ms"     "$TIMEOUT_MS"
    "--crash-dir"      "$CRASH_DIR"
    "--stats-interval" "1000"
    "--cores"          "$CORE_LIST"
)

if [ -n "$CORPUS_DIR" ] && [ -d "$CORPUS_DIR" ]; then
    BRIDGE_ARGS+=("--corpus-dir" "$CORPUS_DIR")
fi

echo "[phantom-multi] Starting fuzzing on cores: $CORE_LIST (duration: ${DURATION}s)"
echo "[phantom-multi] Command: python3 $BRIDGE ${BRIDGE_ARGS[*]}"
echo ""

# Run bridge with a duration timeout
BRIDGE_OUT=""
if command -v timeout &>/dev/null; then
    BRIDGE_OUT=$(timeout "$DURATION" python3 "$BRIDGE" "${BRIDGE_ARGS[@]}" 2>&1) || true
else
    BRIDGE_OUT=$(python3 "$BRIDGE" "${BRIDGE_ARGS[@]}" 2>&1) || true
fi

echo "$BRIDGE_OUT"

# ---------------------------------------------------------------------------
# 4. Print summary
# ---------------------------------------------------------------------------
echo ""
echo "[phantom-multi] === Summary ==="
echo "$BRIDGE_OUT" | grep -E "(core [0-9]|total:|aggregate|exec/sec|crashes|kasan|timeouts)" || true

# ---------------------------------------------------------------------------
# 5. Unload phantom.ko
# ---------------------------------------------------------------------------
echo ""
echo "[phantom-multi] Unloading phantom.ko..."
rmmod phantom 2>/dev/null && echo "[phantom-multi] rmmod OK" || \
    echo "[phantom-multi] WARNING: rmmod failed (may already be unloaded)"

echo "[phantom-multi] Done."
