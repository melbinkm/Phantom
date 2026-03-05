#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# bench_scaling.sh — measure exec/sec scaling vs core count.
#
# Starts Phantom instances at 1, 2, 4, and 7 cores (never 8 — OS reserve),
# waits 30 seconds per configuration for steady-state exec/sec, reads
# PHANTOM_IOCTL_GET_MULTICORE_STATS (ioctl nr=24), and computes the
# scaling factor:
#
#   scaling_factor_N = exec_N / (exec_1 × N)
#
# Pass criterion: scaling_factor ≥ 0.85 for N ∈ {2, 4, 7}.
#
# Usage:
#   sudo bash bench_scaling.sh [--bzimage PATH]
#
# Exit codes:
#   0  PASS — all scaling factors ≥ 0.85
#   1  FAIL — at least one core count below threshold
#   2  SKIP — bzImage not found
#   3  ERROR — module load or ioctl failure

set -euo pipefail

BZIMAGE="${BZIMAGE:-/root/phantom/linux-6.1.90/arch/x86/boot/bzImage}"
MEASURE_SECS=30
PASS_THRESHOLD="0.85"
CORE_COUNTS=(1 2 4 7)   # never 8 — always reserve 1 core for OS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
KO="${SRC_ROOT}/kernel/phantom.ko"
STATS_PY="${SCRIPT_DIR}/multicore_stats.py"

# Parse arguments
while [[ $# -gt 0 ]]; do
	case "$1" in
		--bzimage) BZIMAGE="$2"; shift 2 ;;
		*) echo "Unknown argument: $1"; exit 3 ;;
	esac
done

echo "=== Phantom exec/sec scaling benchmark ==="
echo "bzImage       : ${BZIMAGE}"
echo "Module        : ${KO}"
echo "Measure time  : ${MEASURE_SECS}s per configuration"
echo "Core counts   : ${CORE_COUNTS[*]}"
echo "Pass threshold: scaling_factor >= ${PASS_THRESHOLD}"
echo ""

# ---- Preflight checks -------------------------------------------------------

if [[ ! -f "${BZIMAGE}" ]]; then
	echo "SKIP: bzImage not found: ${BZIMAGE}"
	echo "      Build with: make -C guest/guest_kernel/ bzImage"
	exit 2
fi

if [[ ! -f "${KO}" ]]; then
	echo "ERROR: phantom.ko not found: ${KO}"
	echo "       Build with: make -C kernel/"
	exit 3
fi

if [[ "$(id -u)" -ne 0 ]]; then
	echo "ERROR: must run as root"
	exit 3
fi

if [[ ! -f "${STATS_PY}" ]]; then
	echo "ERROR: multicore_stats.py not found: ${STATS_PY}"
	exit 3
fi

# ---- Helper: load module, start N cores, measure exec/sec ------------------

# Global to collect results
declare -A EXEC_RESULTS   # EXEC_RESULTS[N] = exec_per_sec

measure_cores() {
	local n_cores=$1
	echo "--- Measuring ${n_cores} core(s) ---"

	# Unload and reload module fresh for each measurement
	if lsmod | grep -q "^phantom "; then
		rmmod phantom 2>/dev/null
		sleep 0.3
	fi
	if lsmod | grep -q "^kvm_intel "; then
		rmmod kvm_intel 2>/dev/null
		sleep 0.2
	fi

	# Build CPU list: cores 0..(n_cores-1), always skip core 7 if n_cores=7
	# i7-6700 has 8 logical cores (0-7); we never use core 7.
	# For N=7, use cores 0-6.
	local cpu_list=""
	for ((i = 0; i < n_cores; i++)); do
		[[ -n "${cpu_list}" ]] && cpu_list+=","
		cpu_list+="${i}"
	done

	insmod "${KO}" phantom_cores="${cpu_list}" || {
		echo "ERROR: insmod phantom.ko phantom_cores=${cpu_list} failed"
		exit 3
	}
	sleep 0.3

	if [[ ! -c /dev/phantom ]]; then
		echo "ERROR: /dev/phantom not found after insmod"
		dmesg | tail -10
		exit 3
	fi

	# Boot the guest on each active core using background python processes.
	# Each process opens /dev/phantom independently — the driver supports
	# one fd per CPU (PHANTOM_CREATE_VM pinned to that CPU).
	local boot_pids=()
	for ((i = 0; i < n_cores; i++)); do
		python3 "${SRC_ROOT}/tests/integration/boot_and_fuzz.py" \
			--bzimage "${BZIMAGE}" \
			--cpu "${i}" \
			--run-secs $(( MEASURE_SECS + 5 )) \
			>/tmp/phantom_scale_core${i}.log 2>&1 &
		boot_pids+=($!)
	done

	# Wait for guests to reach steady state
	echo "  Waiting ${MEASURE_SECS}s for steady state..."
	sleep "${MEASURE_SECS}"

	# Read stats while fuzzing is running
	local stats
	stats=$(python3 "${STATS_PY}" 2>/dev/null) || {
		echo "  WARNING: multicore_stats.py failed; falling back to dmesg"
		stats=""
	}

	local total_exec=0
	if [[ -n "${stats}" ]]; then
		# Parse "total_exec_per_sec: N" from multicore_stats.py output
		total_exec=$(echo "${stats}" | awk '/total_exec_per_sec/{print $NF}')
	else
		# Fallback: sum exec/sec from per-core dmesg lines
		# phantom logs: "phantom: core N: exec/sec: M"
		total_exec=$(dmesg | grep -oP 'exec/sec:\s*\K[0-9]+' | \
			tail -"${n_cores}" | awk '{s+=$1} END{print s}')
		[[ -z "${total_exec}" ]] && total_exec=0
	fi

	# Kill background fuzz processes
	for pid in "${boot_pids[@]}"; do
		kill "${pid}" 2>/dev/null || true
	done
	wait 2>/dev/null || true

	echo "  cores=${n_cores} total_exec/s=${total_exec}"
	EXEC_RESULTS[${n_cores}]="${total_exec}"

	rmmod phantom 2>/dev/null || true
	sleep 0.5
}

# ---- Run measurements -------------------------------------------------------

for n in "${CORE_COUNTS[@]}"; do
	measure_cores "${n}"
done

# ---- Compute scaling factors ------------------------------------------------

echo ""
echo "=== Scaling Results ==="
printf "%-8s %-14s %-14s %-10s %-8s\n" \
	"Cores" "exec/s" "ideal_exec/s" "factor" "Result"
printf "%-8s %-14s %-14s %-10s %-8s\n" \
	"-----" "------" "------------" "------" "------"

exec_1="${EXEC_RESULTS[1]:-0}"
overall_pass=0   # 0 = pass, 1 = fail

if [[ "${exec_1}" -eq 0 ]]; then
	echo "ERROR: single-core exec/sec is zero — cannot compute scaling"
	exit 3
fi

printf "%-8s %-14s %-14s %-10s %-8s\n" \
	"1" "${exec_1}" "${exec_1}" "1.000" "BASELINE"

for n in "${CORE_COUNTS[@]}"; do
	[[ "${n}" -eq 1 ]] && continue

	exec_n="${EXEC_RESULTS[${n}]:-0}"
	ideal=$(( exec_1 * n ))

	# Compute scaling factor with two decimal places using awk
	factor=$(awk "BEGIN {printf \"%.3f\", ${exec_n} / ${ideal}}")
	# Compare factor >= PASS_THRESHOLD
	result=$(awk "BEGIN {
		if (${factor} >= ${PASS_THRESHOLD}) print \"PASS\"
		else print \"FAIL\"
	}")

	printf "%-8s %-14s %-14s %-10s %-8s\n" \
		"${n}" "${exec_n}" "${ideal}" "${factor}" "${result}"

	if [[ "${result}" == "FAIL" ]]; then
		overall_pass=1
	fi
done

echo ""
if [[ "${overall_pass}" -eq 0 ]]; then
	echo "PASS: all scaling factors >= ${PASS_THRESHOLD}"
else
	echo "FAIL: one or more scaling factors below ${PASS_THRESHOLD}"
	echo "      Check for lock contention or NUMA imbalance."
fi

exit "${overall_pass}"
