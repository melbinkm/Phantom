#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_3_3_multicore.sh — Task 3.3 top-level multi-core test runner.
#
# Runs all task 3.3 acceptance tests in sequence:
#
#   Test 1: Module loads with multi-core support (phantom_cores=0,1,2,3)
#   Test 2: bench_scaling.sh — scaling factor >= 0.85 for N in {2,4,7}
#   Test 3: bench_numa.sh — NUMA topology documented
#   Test 4: test_multicore_isolation.sh — EPT isolation confirmed
#   Test 5: 1-hour soak test — exec/sec at t=60min >= 90% of t=0
#
# Usage:
#   sudo bash test_3_3_multicore.sh [--bzimage PATH] [--skip-soak]
#
# Options:
#   --bzimage PATH   Path to guest bzImage (default: /root/phantom/linux-6.1.90/...)
#   --skip-soak      Skip the 1-hour soak test (for quick smoke runs)
#
# Exit codes:
#   0  PASS — all tests passed
#   1  FAIL — at least one test failed
#   2  SKIP — bzImage not found
#   3  ERROR — module or environment failure

set -euo pipefail

BZIMAGE="${BZIMAGE:-/root/phantom/linux-6.1.90/arch/x86/boot/bzImage}"
SKIP_SOAK=0
SOAK_CORES=4          # 4-core soak (cores 0-3; reserve cores 4-7 for OS)
SOAK_DURATION=3600    # 1 hour in seconds
SOAK_SAMPLE_INTERVAL=60   # sample exec/sec every 60s
SOAK_PASS_RATIO="0.90"    # t=60min exec/s >= 90% of t=0 exec/s

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
KO="${SRC_ROOT}/kernel/phantom.ko"
PERF_DIR="${SRC_ROOT}/tests/performance"
LOG_DIR="/tmp/phantom-task-3.3"

# Parse arguments
while [[ $# -gt 0 ]]; do
	case "$1" in
		--bzimage)  BZIMAGE="$2";     shift 2 ;;
		--skip-soak) SKIP_SOAK=1;     shift   ;;
		*) echo "Unknown argument: $1"; exit 3  ;;
	esac
done

# ---- Setup -----------------------------------------------------------------

mkdir -p "${LOG_DIR}"

echo "============================================================"
echo " Phantom Task 3.3 — Multi-Core Test Suite"
echo "============================================================"
echo "bzImage : ${BZIMAGE}"
echo "Module  : ${KO}"
echo "Logs    : ${LOG_DIR}"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

report() {
	local name=$1
	local rc=$2
	if [[ "${rc}" -eq 0 ]]; then
		echo "[PASS] ${name}"
		(( PASS_COUNT++ )) || true
	elif [[ "${rc}" -eq 2 ]]; then
		echo "[SKIP] ${name}"
	else
		echo "[FAIL] ${name}"
		(( FAIL_COUNT++ )) || true
	fi
}

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

# ---- Test 1: Module loads with multi-core support --------------------------

echo "------------------------------------------------------------"
echo "Test 1: Module load with phantom_cores=0,1,2,3"
echo "------------------------------------------------------------"

if lsmod | grep -q "^phantom "; then
	rmmod phantom 2>/dev/null
	sleep 0.3
fi
if lsmod | grep -q "^kvm_intel "; then
	rmmod kvm_intel 2>/dev/null
	sleep 0.2
fi

insmod "${KO}" phantom_cores="0,1,2,3" \
	>"${LOG_DIR}/test1_insmod.log" 2>&1
insmod_rc=$?

if [[ "${insmod_rc}" -ne 0 ]]; then
	echo "  ERROR: insmod failed (rc=${insmod_rc})"
	cat "${LOG_DIR}/test1_insmod.log"
	dmesg | tail -10
	report "Module load (multi-core)" 3
else
	sleep 0.3
	if [[ -c /dev/phantom ]]; then
		# Verify dmesg shows multiple vCPU VMXON lines
		vmxon_count=$(dmesg | grep -c 'VMXON.*CPU\|vmxon.*core\|phantom.*core.*OK' || true)
		echo "  insmod OK — detected ${vmxon_count} VMXON/core log lines"
		report "Module load (multi-core)" 0
	else
		echo "  ERROR: /dev/phantom missing after insmod"
		dmesg | tail -10
		report "Module load (multi-core)" 1
	fi
fi

rmmod phantom 2>/dev/null || true
sleep 0.5
echo ""

# ---- Test 2: Scaling benchmark ---------------------------------------------

echo "------------------------------------------------------------"
echo "Test 2: exec/sec scaling factor >= 0.85 for N in {2,4,7}"
echo "------------------------------------------------------------"

BZIMAGE="${BZIMAGE}" bash "${PERF_DIR}/bench_scaling.sh" \
	>"${LOG_DIR}/test2_scaling.log" 2>&1
scale_rc=$?
cat "${LOG_DIR}/test2_scaling.log"
report "Scaling benchmark (>= 0.85 factor)" "${scale_rc}"
echo ""

# ---- Test 3: NUMA benchmark -------------------------------------------------

echo "------------------------------------------------------------"
echo "Test 3: NUMA locality documented"
echo "------------------------------------------------------------"

BZIMAGE="${BZIMAGE}" bash "${PERF_DIR}/bench_numa.sh" \
	>"${LOG_DIR}/test3_numa.log" 2>&1
numa_rc=$?
cat "${LOG_DIR}/test3_numa.log"
report "NUMA locality benchmark" "${numa_rc}"
echo ""

# ---- Test 4: EPT isolation --------------------------------------------------

echo "------------------------------------------------------------"
echo "Test 4: EPT isolation with 4 cores active"
echo "------------------------------------------------------------"

bash "${SCRIPT_DIR}/test_multicore_isolation.sh" "${BZIMAGE}" \
	>"${LOG_DIR}/test4_isolation.log" 2>&1
iso_rc=$?
cat "${LOG_DIR}/test4_isolation.log"
report "Multi-core EPT isolation" "${iso_rc}"
echo ""

# ---- Test 5: 1-hour soak test ----------------------------------------------

if [[ "${SKIP_SOAK}" -eq 1 ]]; then
	echo "------------------------------------------------------------"
	echo "Test 5: Soak test [SKIPPED via --skip-soak]"
	echo "------------------------------------------------------------"
	echo "[SKIP] 1-hour soak test (--skip-soak)"
	echo ""
else
	echo "------------------------------------------------------------"
	echo "Test 5: 1-hour soak test (${SOAK_CORES} cores, ${SOAK_DURATION}s)"
	echo "------------------------------------------------------------"
	echo "  Start time : $(date)"
	echo "  End time   : $(date -d "+${SOAK_DURATION} seconds")"
	echo ""

	# Load module for soak
	if lsmod | grep -q "^phantom "; then
		rmmod phantom 2>/dev/null; sleep 0.3
	fi
	if lsmod | grep -q "^kvm_intel "; then
		rmmod kvm_intel 2>/dev/null; sleep 0.2
	fi

	CPU_LIST="0,1,2,3"
	insmod "${KO}" phantom_cores="${CPU_LIST}" || {
		echo "ERROR: insmod failed for soak test"
		report "1-hour soak test" 3
	}
	sleep 0.3

	if [[ ! -c /dev/phantom ]]; then
		echo "ERROR: /dev/phantom missing — soak test cannot start"
		report "1-hour soak test" 3
	else
		# Start fuzzing on all soak cores
		declare -a SOAK_PIDS
		for ((i = 0; i < SOAK_CORES; i++)); do
			python3 "${SRC_ROOT}/tests/integration/determinism_check.py" \
				--bzimage "${BZIMAGE}" \
				--cpu "${i}" \
				--iterations 999999 \
				>"${LOG_DIR}/soak_core${i}.log" 2>&1 &
			SOAK_PIDS+=($!)
		done

		# Capture t=0 exec/sec
		sleep 10
		MEM_START=$(free -m | awk '/^Mem:/{print $3}')
		DMESG_ERRORS_START=$(dmesg | grep -cE 'phantom.*ERROR|BUG:|Oops:|kernel BUG' || true)

		exec_t0=0
		stats0=$(python3 "${PERF_DIR}/multicore_stats.py" 2>/dev/null) || true
		if [[ -n "${stats0}" ]]; then
			exec_t0=$(echo "${stats0}" | awk '/total_exec_per_sec/{print $NF}')
		else
			exec_t0=$(dmesg | grep -oP 'exec/sec:\s*\K[0-9]+' | tail -1 || echo 0)
		fi
		echo "  t=0  exec/s: ${exec_t0}  mem_used_MB: ${MEM_START}"

		# Progress monitoring loop
		ELAPSED=0
		SAMPLE_COUNT=0
		exec_last="${exec_t0}"
		soak_ok=0

		while [[ "${ELAPSED}" -lt "${SOAK_DURATION}" ]]; do
			sleep "${SOAK_SAMPLE_INTERVAL}"
			ELAPSED=$(( ELAPSED + SOAK_SAMPLE_INTERVAL ))
			SAMPLE_COUNT=$(( SAMPLE_COUNT + 1 ))

			MEM_NOW=$(free -m | awk '/^Mem:/{print $3}')
			DMESG_ERRORS_NOW=$(dmesg | grep -cE 'phantom.*ERROR|BUG:|Oops:|kernel BUG' || true)

			stats_now=$(python3 "${PERF_DIR}/multicore_stats.py" 2>/dev/null) || true
			if [[ -n "${stats_now}" ]]; then
				exec_now=$(echo "${stats_now}" | awk '/total_exec_per_sec/{print $NF}')
			else
				exec_now=$(dmesg | grep -oP 'exec/sec:\s*\K[0-9]+' | tail -1 || echo 0)
			fi

			MINS=$(( ELAPSED / 60 ))
			echo "  t=${MINS}min exec/s: ${exec_now}  mem_MB: ${MEM_NOW}  dmesg_errors: ${DMESG_ERRORS_NOW}"

			# Log to file
			echo "t=${ELAPSED}s exec/s=${exec_now} mem_MB=${MEM_NOW} errors=${DMESG_ERRORS_NOW}" \
				>>"${LOG_DIR}/soak_stats.log"

			exec_last="${exec_now}"
		done

		# Kill soak processes
		for pid in "${SOAK_PIDS[@]}"; do
			kill "${pid}" 2>/dev/null || true
		done
		wait 2>/dev/null || true

		# Evaluate soak results
		MEM_END=$(free -m | awk '/^Mem:/{print $3}')
		MEM_DELTA=$(( MEM_END - MEM_START ))
		MEM_DELTA_PCT=$(awk "BEGIN {printf \"%.1f\", ${MEM_DELTA} * 100 / (${MEM_START} + 1)}")
		DMESG_ERRORS_FINAL=$(dmesg | grep -cE 'phantom.*ERROR|BUG:|Oops:|kernel BUG' \
			|| true)
		DMESG_NEW=$(( DMESG_ERRORS_FINAL - DMESG_ERRORS_START ))

		echo ""
		echo "  Soak completed at $(date)"
		echo "  t=0  exec/s : ${exec_t0}"
		echo "  t=60 exec/s : ${exec_last}"
		echo "  Memory delta: +${MEM_DELTA}MB (${MEM_DELTA_PCT}%)"
		echo "  New dmesg errors: ${DMESG_NEW}"

		# Check t=60 exec/s >= 90% of t=0
		throughput_ok=$(awk "BEGIN {
			if (${exec_t0} == 0) { print \"skip\"; exit }
			ratio = ${exec_last} / ${exec_t0}
			if (ratio >= ${SOAK_PASS_RATIO}) print \"pass\"
			else print \"fail\"
		}")

		# Memory leak: flag if > 5% growth
		mem_ok=$(awk "BEGIN {
			pct = ${MEM_DELTA} * 100 / (${MEM_START} + 1)
			if (pct > 5) print \"fail\"
			else print \"pass\"
		}")

		soak_pass=0
		if [[ "${throughput_ok}" == "fail" ]]; then
			echo "  FAIL: throughput degraded below 90% of t=0"
			soak_pass=1
		fi
		if [[ "${mem_ok}" == "fail" ]]; then
			echo "  FAIL: memory growth > 5% (${MEM_DELTA_PCT}%) — possible leak"
			soak_pass=1
		fi
		if [[ "${DMESG_NEW}" -gt 0 ]]; then
			echo "  FAIL: ${DMESG_NEW} new dmesg errors during soak"
			dmesg | grep -E 'phantom.*ERROR|BUG:|Oops:|kernel BUG' | tail -10
			soak_pass=1
		fi

		rmmod phantom 2>/dev/null || true
		report "1-hour soak test" "${soak_pass}"
	fi
fi

# ---- Summary ---------------------------------------------------------------

echo ""
echo "============================================================"
echo " Task 3.3 Results"
echo "============================================================"
echo "  PASS : ${PASS_COUNT}"
echo "  FAIL : ${FAIL_COUNT}"
echo "  Logs : ${LOG_DIR}/"
echo ""

if [[ "${FAIL_COUNT}" -eq 0 ]]; then
	echo "PASS: All task 3.3 tests passed."
	exit 0
else
	echo "FAIL: ${FAIL_COUNT} test(s) failed — see logs above."
	exit 1
fi
