#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# benchmarks/reproduce.sh — end-to-end benchmark reproduction for Phantom.
#
# Runs on bare metal (not nested KVM). Collects:
#   1. 30-run exec/sec at 1-core and 3-core (60s each)
#   2. Mann-Whitney U comparison between 1-core and 3-core
#   3. Restore latency sweep (dirty page count vs cycles)
#   4. Scaling benchmark (1, 2, 3 cores)
#
# Usage:
#   sudo bash benchmarks/reproduce.sh [--bzimage PATH] [--seconds 60]
#
# Expected result ranges (i7-6700, 4-core/8-thread):
#   1-core exec/sec:  70,000 – 90,000
#   3-core exec/sec: 150,000 – 180,000
#   Scaling factor 3-core: 0.60 – 0.80
#   Restore latency R²: ≥ 0.95
#
# Exit codes:
#   0  PASS
#   1  FAIL
#   2  SKIP (missing dependencies)
#   3  ERROR

set -euo pipefail

BZIMAGE="${BZIMAGE:-/root/phantom/linux-6.1.90/arch/x86/boot/bzImage}"
SECONDS_PER_RUN=60
RUNS=30

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KO="${SRC_ROOT}/kernel/phantom.ko"
RESULTS_DIR="${SCRIPT_DIR}/results"

# Parse arguments
while [[ $# -gt 0 ]]; do
	case "$1" in
		--bzimage) BZIMAGE="$2"; shift 2 ;;
		--seconds) SECONDS_PER_RUN="$2"; shift 2 ;;
		--runs) RUNS="$2"; shift 2 ;;
		*) echo "Unknown argument: $1"; exit 3 ;;
	esac
done

echo "=== Phantom Performance Benchmark Suite ==="
echo "bzImage    : ${BZIMAGE}"
echo "Module     : ${KO}"
echo "Runs       : ${RUNS} × ${SECONDS_PER_RUN}s each"
echo "Results    : ${RESULTS_DIR}"
echo ""

# ---- Preflight ---------------------------------------------------------------

if [[ ! -f "${BZIMAGE}" ]]; then
	echo "SKIP: bzImage not found: ${BZIMAGE}"
	exit 2
fi

if [[ ! -f "${KO}" ]]; then
	echo "ERROR: phantom.ko not found: ${KO}"
	exit 3
fi

if [[ "$(id -u)" -ne 0 ]]; then
	echo "ERROR: must run as root"
	exit 3
fi

# Check bare metal
if grep -q hypervisor /proc/cpuinfo 2>/dev/null; then
	echo "WARNING: running under hypervisor — results may not reflect bare-metal performance"
fi

mkdir -p "${RESULTS_DIR}"

# ---- Hardware info -----------------------------------------------------------

echo "=== Hardware ==="
grep 'model name' /proc/cpuinfo | head -1
echo "Kernel: $(uname -r)"
echo "Cores: $(nproc)"
echo ""

# Disable turbo boost if available
if [[ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
	TURBO_ORIG=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)
	echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
	echo "Turbo boost disabled (was ${TURBO_ORIG})"
else
	TURBO_ORIG=""
	echo "Turbo boost control not available"
fi

# Watchdog mitigation
WD_THRESH_ORIG=$(cat /proc/sys/kernel/watchdog_thresh)
NMI_WD_ORIG=$(cat /proc/sys/kernel/nmi_watchdog)
echo 60 > /proc/sys/kernel/watchdog_thresh
echo 0 > /proc/sys/kernel/nmi_watchdog
echo "watchdog_thresh=60, nmi_watchdog=0"

trap '{
	echo "${NMI_WD_ORIG}" > /proc/sys/kernel/nmi_watchdog 2>/dev/null
	echo "${WD_THRESH_ORIG}" > /proc/sys/kernel/watchdog_thresh 2>/dev/null
	[[ -n "${TURBO_ORIG}" ]] && echo "${TURBO_ORIG}" > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null
	echo "Settings restored"
}' EXIT

overall_pass=0

# ---- Benchmark 1: 30-run exec/sec (1 core) ----------------------------------

echo ""
echo "=== Benchmark 1: 30-run exec/sec (1 core) ==="

if lsmod | grep -q "^kvm_intel "; then
	rmmod kvm_intel 2>/dev/null; sleep 0.5
fi
rmmod phantom 2>/dev/null; sleep 1
insmod "${KO}" phantom_cores=0 || { echo "ERROR: insmod failed"; exit 3; }
sleep 0.5

python3 "${SCRIPT_DIR}/scripts/bench_30run.py" \
	--bzimage "${BZIMAGE}" \
	--seconds "${SECONDS_PER_RUN}" \
	--runs "${RUNS}" \
	--warmup 5 \
	--cpu 0 \
	--output "${RESULTS_DIR}/bench_1core.json" \
	2>&1

rmmod phantom 2>/dev/null; sleep 3

# ---- Benchmark 2: 30-run exec/sec (3 cores) ---------------------------------

echo ""
echo "=== Benchmark 2: 30-run exec/sec (3 cores) ==="
echo "Note: 3-core runs use multicore_fuzz.py (parallel fuzz, sequential boot)"

# For 3-core we do 30 runs, each loading/unloading the module
# to get independent measurements

THREECORE_RATES=()
for run in $(seq 1 "${RUNS}"); do
	echo "--- 3-core run ${run}/${RUNS} ---"
	insmod "${KO}" phantom_cores=0,1,2 || { echo "ERROR: insmod failed"; exit 3; }
	sleep 0.5

	OUTPUT=$(python3 "${SRC_ROOT}/tests/integration/multicore_fuzz.py" \
		--bzimage "${BZIMAGE}" \
		--cores 3 \
		--seconds "${SECONDS_PER_RUN}" \
		--boot-wait 10 \
		2>/dev/null)

	# Sum per-core rates
	TOTAL=0
	while IFS= read -r line; do
		RATE=$(echo "${line}" | grep -oP 'exec_per_sec=\K[0-9]+' || true)
		[[ -n "${RATE}" ]] && TOTAL=$((TOTAL + RATE))
	done <<< "${OUTPUT}"

	echo "  total_exec_per_sec=${TOTAL}"
	THREECORE_RATES+=("${TOTAL}")

	rmmod phantom 2>/dev/null; sleep 3
done

# Write 3-core results to JSON
python3 -c "
import json, sys
rates = [${THREECORE_RATES[*]/%/,}]
rates = [r for r in rates if r > 0]
rates.sort()
n = len(rates)
result = {
    'benchmark': 'phantom_30run_execsec_3core',
    'exec_per_sec_values': rates,
    'summary': {
        'n': n,
        'median': rates[n//2] if n else 0,
        'p25': rates[n//4] if n else 0,
        'p75': rates[3*n//4] if n else 0,
        'min': rates[0] if n else 0,
        'max': rates[-1] if n else 0,
        'mean': round(sum(rates)/n, 1) if n else 0,
    }
}
with open('${RESULTS_DIR}/bench_3core.json', 'w') as f:
    json.dump(result, f, indent=2)
print('3-core summary: n=%d median=%.0f' % (n, rates[n//2] if n else 0))
" 2>&1

# ---- Benchmark 3: Mann-Whitney U comparison ---------------------------------

echo ""
echo "=== Benchmark 3: Mann-Whitney U (1-core vs 3-core) ==="

python3 "${SCRIPT_DIR}/scripts/analyze.py" \
	--compare "${RESULTS_DIR}/bench_1core.json" "${RESULTS_DIR}/bench_3core.json" \
	--output "${RESULTS_DIR}/mann_whitney.json" \
	2>&1

# ---- Benchmark 4: Restore latency sweep -------------------------------------

echo ""
echo "=== Benchmark 4: Restore latency sweep ==="

insmod "${KO}" phantom_cores=0 || { echo "ERROR: insmod failed"; exit 3; }
sleep 0.5

python3 "${SCRIPT_DIR}/scripts/bench_restore_sweep.py" \
	--bzimage "${BZIMAGE}" \
	--output "${RESULTS_DIR}/restore_sweep.json" \
	--iters-per-point 30 \
	2>&1

echo ""
echo "=== Restore latency analysis ==="
python3 "${SCRIPT_DIR}/scripts/analyze.py" \
	--restore-sweep "${RESULTS_DIR}/restore_sweep.json" \
	2>&1

rmmod phantom 2>/dev/null

# ---- Benchmark 5: Scaling (reuse bench_scaling.sh) --------------------------

echo ""
echo "=== Benchmark 5: Scaling (1, 2, 3 cores) ==="

bash "${SRC_ROOT}/tests/performance/bench_scaling.sh" \
	--bzimage "${BZIMAGE}" \
	2>&1
SCALING_RC=$?

if [[ "${SCALING_RC}" -ne 0 ]]; then
	echo "FAIL: scaling benchmark failed"
	overall_pass=1
fi

# ---- Summary -----------------------------------------------------------------

echo ""
echo "=== Benchmark Suite Complete ==="
echo "Results directory: ${RESULTS_DIR}"
ls -la "${RESULTS_DIR}/"
echo ""

if [[ "${overall_pass}" -eq 0 ]]; then
	echo "PASS: all benchmarks completed"
else
	echo "FAIL: one or more benchmarks failed"
fi

exit "${overall_pass}"
