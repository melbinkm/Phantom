#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# benchmarks/reproduce.sh — end-to-end benchmark reproduction for Phantom.
#
# Runs on bare metal (not nested KVM). Collects:
#   1. 30-run exec/sec (single-load mode, no rmmod between runs)
#   2. Restore latency microbenchmark (per-component cycle counts)
#   3. Statistical analysis (median, p25/p75, Mann-Whitney U vs kAFL)
#
# Usage:
#   sudo bash benchmarks/reproduce.sh [--cores N] [--seconds N] [--runs N]
#
# Expected result ranges (i7-6700, 1 core, Class B kernel target):
#   Phantom exec/sec:    85,000 – 90,000
#   Restore latency:     ~1,700 cycles (~0.5μs)
#   Published kAFL:      10,000 – 20,000 exec/sec
#   Expected speedup:    4.4x – 8.8x vs kAFL
#
# Methodology:
#   - Single-load mode: one insmod, N measurement intervals, one rmmod
#   - Module reload between runs is unstable on ≤4-core machines
#   - 30 runs, discard first 5 as warmup, report median + p25/p75
#
# Exit codes:
#   0  PASS
#   1  FAIL
#   2  SKIP (missing dependencies)
#   3  ERROR

set -euo pipefail

CORES=1
SECONDS_PER_RUN=15
RUNS=30
WARMUP=5
SETTLE=2

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KO="${SRC_ROOT}/kernel/phantom.ko"
RESULTS_DIR="${SCRIPT_DIR}/results"

while [[ $# -gt 0 ]]; do
	case "$1" in
		--cores) CORES="$2"; shift 2 ;;
		--seconds) SECONDS_PER_RUN="$2"; shift 2 ;;
		--runs) RUNS="$2"; shift 2 ;;
		--warmup) WARMUP="$2"; shift 2 ;;
		-h|--help)
			echo "Usage: $0 [--cores N] [--seconds N] [--runs N] [--warmup N]"
			exit 0 ;;
		*) echo "Unknown argument: $1"; exit 3 ;;
	esac
done

echo "=== Phantom Performance Benchmark Suite ==="
echo "Module     : ${KO}"
echo "Cores      : ${CORES}"
echo "Runs       : ${RUNS} × ${SECONDS_PER_RUN}s (warmup=${WARMUP})"
echo "Results    : ${RESULTS_DIR}"
echo ""

# ---- Preflight ---------------------------------------------------------------

if [[ ! -f "${KO}" ]]; then
	echo "ERROR: phantom.ko not found: ${KO}"
	exit 3
fi

if [[ "$(id -u)" -ne 0 ]]; then
	echo "ERROR: must run as root"
	exit 3
fi

if grep -q hypervisor /proc/cpuinfo 2>/dev/null; then
	echo "WARNING: running under hypervisor — results may not reflect bare-metal"
fi

mkdir -p "${RESULTS_DIR}"

# ---- Hardware info -----------------------------------------------------------

echo "=== Hardware ==="
grep 'model name' /proc/cpuinfo | head -1
echo "Kernel: $(uname -r)"
echo "Physical cores: $(grep 'core id' /proc/cpuinfo | sort -u | wc -l)"
echo ""

# Watchdog mitigation
WD_THRESH_ORIG=$(cat /proc/sys/kernel/watchdog_thresh)
NMI_WD_ORIG=$(cat /proc/sys/kernel/nmi_watchdog)
echo 60 > /proc/sys/kernel/watchdog_thresh
echo 0 > /proc/sys/kernel/nmi_watchdog
echo "watchdog_thresh=60, nmi_watchdog=0"

trap '{
	echo "${NMI_WD_ORIG}" > /proc/sys/kernel/nmi_watchdog 2>/dev/null
	echo "${WD_THRESH_ORIG}" > /proc/sys/kernel/watchdog_thresh 2>/dev/null
	rmmod phantom 2>/dev/null || true
	echo "Cleanup done"
}' EXIT

# ---- Benchmark 1: 30-run exec/sec (single-load mode) ------------------------

echo ""
echo "=== Benchmark 1: 30-run exec/sec (${CORES}-core, single-load) ==="

if lsmod | grep -q "^kvm_intel "; then
	rmmod kvm_intel 2>/dev/null; sleep 0.5
fi
rmmod phantom 2>/dev/null; sleep 1

CORE_LIST=$(seq -s, 0 $((CORES - 1)))
insmod "${KO}" phantom_cores="${CORE_LIST}" || { echo "ERROR: insmod failed"; exit 3; }
sleep 0.5

EXEC_OUTPUT="${RESULTS_DIR}/bench_${CORES}core_reproduce.json"

python3 "${SCRIPT_DIR}/scripts/bench_30run_multicore.py" \
	--cores "${CORES}" \
	--seconds "${SECONDS_PER_RUN}" \
	--runs "${RUNS}" \
	--warmup "${WARMUP}" \
	--settle "${SETTLE}" \
	--output "${EXEC_OUTPUT}" \
	2>&1

echo ""
python3 "${SCRIPT_DIR}/scripts/analyze.py" --input "${EXEC_OUTPUT}" 2>&1

rmmod phantom 2>/dev/null; sleep 2

# ---- Benchmark 2: Restore latency -------------------------------------------

echo ""
echo "=== Benchmark 2: Restore latency microbenchmark ==="

insmod "${KO}" phantom_cores=0 || { echo "ERROR: insmod failed"; exit 3; }
sleep 0.5

RESTORE_OUTPUT="${RESULTS_DIR}/restore_sweep_reproduce.json"

python3 "${SCRIPT_DIR}/scripts/bench_restore_sweep.py" \
	--cpu 0 \
	--iters-per-point 50 \
	--warmup 10 \
	--output "${RESTORE_OUTPUT}" \
	2>&1

echo ""
python3 "${SCRIPT_DIR}/scripts/analyze.py" --restore-sweep "${RESTORE_OUTPUT}" 2>&1

rmmod phantom 2>/dev/null

# ---- Summary -----------------------------------------------------------------

echo ""
echo "=== Benchmark Suite Complete ==="
echo "Results:"
ls -la "${RESULTS_DIR}/"*.json 2>/dev/null
echo ""
echo "Compare against published kAFL/Nyx (kernel targets): 10,000 – 20,000 exec/sec"
echo "PASS: all benchmarks completed"
exit 0
