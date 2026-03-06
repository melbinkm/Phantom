#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# bench_scaling.sh — measure exec/sec scaling vs core count.
#
# Starts Phantom instances at 1, 2, and 3 cores, waits 30 seconds per
# configuration for steady-state exec/sec, and computes the scaling factor:
#
#   scaling_factor_N = exec_N / (exec_1 × N)
#
# Pass criterion: scaling_factor ≥ 0.50 for N ∈ {2, 3}.
#
# Hardware limit (i7-6700, 4 physical cores + HT):
#   - Max 3 VMX cores; core 3 (+HT sibling 7) reserved for OS.
#   - 4 VMX cores = all physical cores in VMX → genuine resource starvation.
#   - PIN_BASED_NMI_EXITING intercepts perf PMI NMIs; self-NMI re-delivery
#     sends generic NMI (not PMI), so the hard lockup detector is not fed.
#     watchdog_thresh must be raised above MEASURE_SECS to prevent false
#     hard lockup detection at 2 × watchdog_thresh.
#
# Usage:
#   sudo bash bench_scaling.sh [--bzimage PATH]
#
# Exit codes:
#   0  PASS — all scaling factors ≥ threshold
#   1  FAIL — at least one core count below threshold
#   2  SKIP — bzImage not found
#   3  ERROR — module load or ioctl failure

set -euo pipefail

BZIMAGE="${BZIMAGE:-/root/phantom/linux-6.1.90/arch/x86/boot/bzImage}"
MEASURE_SECS=30
PASS_THRESHOLD="0.50"
CORE_COUNTS=(1 2 3)     # i7-6700: max 3 VMX cores; core 3 reserved for OS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
KO="${SRC_ROOT}/kernel/phantom.ko"

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

# ---- Watchdog mitigation -----------------------------------------------------
#
# PIN_BASED_NMI_EXITING intercepts perf PMI NMIs during guest execution.
# phantom_handle_nmi_exit() re-delivers via __apic_send_IPI_self(NMI_VECTOR),
# but this is a generic NMI — not a PMI — so the hard lockup detector's
# perf counter never resets.  The detector fires at 2 × watchdog_thresh.
#
# Fix: disable nmi_watchdog AND raise watchdog_thresh above the measurement
# duration so any residual detection path cannot fire during the test.
# Restore originals on exit via trap.

NMI_WD_ORIG=$(cat /proc/sys/kernel/nmi_watchdog)
WD_THRESH_ORIG=$(cat /proc/sys/kernel/watchdog_thresh)

# Set threshold first (before disabling watchdog) to max safe value.
# Kernel max is typically 60.  Hard lockup fires at 2 × thresh = 120s,
# well above our 30s measurement window.
echo 60 > /proc/sys/kernel/watchdog_thresh
echo 0 > /proc/sys/kernel/nmi_watchdog

echo "watchdog_thresh raised to 60s (was ${WD_THRESH_ORIG}s)"
echo "NMI watchdog disabled (was ${NMI_WD_ORIG})"

trap 'echo "${NMI_WD_ORIG}" > /proc/sys/kernel/nmi_watchdog 2>/dev/null; \
      echo "${WD_THRESH_ORIG}" > /proc/sys/kernel/watchdog_thresh 2>/dev/null; \
      echo "Watchdog settings restored"' EXIT

# ---- Per-core-count measurement (separate insmod/rmmod per count) -----------
#
# Each measurement: insmod → sequential boot → parallel fuzz → rmmod.
# Separate module loads avoid idle vCPU busy-wait threads (vmx_core.c:1726)
# that cause starvation when pre-booted cores are not actively fuzzing.
# Sleep 5s between loads to allow clean VMX teardown.

declare -A EXEC_RESULTS   # EXEC_RESULTS[N] = exec_per_sec

for n_cores in "${CORE_COUNTS[@]}"; do
	echo ""
	echo "--- Measuring ${n_cores} core(s) ---"

	# Unload any conflicting modules
	if lsmod | grep -q "^phantom "; then
		rmmod phantom 2>/dev/null
		sleep 3
	fi
	if lsmod | grep -q "^kvm_intel "; then
		rmmod kvm_intel 2>/dev/null
		sleep 1
	fi

	# Build CPU list: cores 0..(n_cores-1)
	CPU_LIST=""
	for ((i = 0; i < n_cores; i++)); do
		[[ -n "${CPU_LIST}" ]] && CPU_LIST+=","
		CPU_LIST+="${i}"
	done

	echo "  insmod phantom.ko phantom_cores=${CPU_LIST}"
	insmod "${KO}" phantom_cores="${CPU_LIST}" || {
		echo "ERROR: insmod phantom.ko phantom_cores=${CPU_LIST} failed"
		dmesg | tail -10
		exit 3
	}
	sleep 0.5

	if [[ ! -c /dev/phantom ]]; then
		echo "ERROR: /dev/phantom not found after insmod"
		dmesg | tail -10
		exit 3
	fi

	echo "  Sequential boot + parallel fuzz for ${MEASURE_SECS}s..."
	python3 "${SRC_ROOT}/tests/integration/multicore_fuzz.py" \
		--bzimage "${BZIMAGE}" \
		--cores "${n_cores}" \
		--seconds "${MEASURE_SECS}" \
		--boot-wait 10 \
		>/tmp/phantom_scale_n${n_cores}.log 2>&1

	# Parse per-core exec_per_sec and sum
	total_exec=0
	for ((i = 0; i < n_cores; i++)); do
		core_exec=$(grep -oP "^cpu=${i} .*exec_per_sec=\K[0-9]+" \
			/tmp/phantom_scale_n${n_cores}.log 2>/dev/null | tail -1)
		if [[ -n "${core_exec}" ]]; then
			total_exec=$(( total_exec + core_exec ))
			echo "    cpu=${i} exec_per_sec=${core_exec}"
		else
			echo "    cpu=${i} ERROR: no result"
		fi
	done

	echo "  cores=${n_cores} total_exec/s=${total_exec}"
	EXEC_RESULTS[${n_cores}]="${total_exec}"

	rmmod phantom 2>/dev/null || true
	sleep 5   # generous pause for clean VMX teardown before next load
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
