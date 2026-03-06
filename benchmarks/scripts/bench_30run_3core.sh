#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# bench_30run_3core.sh — 30 independent 3-core exec/sec measurements.
#
# Each run: insmod → sequential boot → parallel fuzz → rmmod.
# Module reload between runs ensures clean VMX state and prevents
# cumulative resource starvation on HT siblings.
#
# Usage:
#   sudo bash bench_30run_3core.sh [--seconds 15] [--runs 30] [--output results.json]

set -euo pipefail

BZIMAGE="${BZIMAGE:-/root/phantom/linux-6.1.90/arch/x86/boot/bzImage}"
KO="${KO:-/root/phantom/src/kernel/phantom.ko}"
MULTICORE="${MULTICORE:-/root/phantom/src/tests/integration/multicore_fuzz.py}"
SECONDS_PER_RUN=15
RUNS=30
WARMUP=5
OUTPUT="/root/phantom/src/benchmarks/results/bench_3core.json"
CORES=3
BOOT_WAIT=10
TEARDOWN_WAIT=5

while [[ $# -gt 0 ]]; do
	case "$1" in
		--seconds) SECONDS_PER_RUN="$2"; shift 2 ;;
		--runs) RUNS="$2"; shift 2 ;;
		--output) OUTPUT="$2"; shift 2 ;;
		--cores) CORES="$2"; shift 2 ;;
		--warmup) WARMUP="$2"; shift 2 ;;
		*) echo "Unknown: $1"; exit 1 ;;
	esac
done

# Build phantom_cores param: "0,1,2" for 3 cores
CORE_LIST=$(seq -s, 0 $((CORES - 1)))

echo "=== 3-core 30-run benchmark ==="
echo "Cores: ${CORES} (${CORE_LIST})"
echo "Runs: ${RUNS} × ${SECONDS_PER_RUN}s"
echo "Warmup: ${WARMUP} (excluded from stats)"
echo "Output: ${OUTPUT}"
echo ""

# Mitigations
echo 60 > /proc/sys/kernel/watchdog_thresh
echo 0 > /proc/sys/kernel/nmi_watchdog
echo "watchdog_thresh=60 nmi_watchdog=0"

ALL_RATES=()
ALL_SAMPLES=""

# Warmup: run 1-core for 10s to initialize perf/timer subsystems
# Without this, first 3-core run after fresh boot locks up the system.
echo "=== Warmup: 1-core 10s ==="
rmmod kvm_intel 2>/dev/null || true
insmod "${KO}" phantom_cores=0 || { echo "insmod warmup failed"; exit 1; }
sleep 0.5
python3 "${MULTICORE}" --cores 1 --seconds 10 --boot-wait 5 --bzimage "${BZIMAGE}" 2>/dev/null || true
rmmod phantom 2>/dev/null || true
sleep 3
echo "Warmup done. Starting 3-core measurements."
echo ""

for run in $(seq 1 "${RUNS}"); do
	echo "--- Run ${run}/${RUNS} ---"

	# Load module
	rmmod phantom 2>/dev/null || true
	rmmod kvm_intel 2>/dev/null || true
	sleep 1
	insmod "${KO}" "phantom_cores=${CORE_LIST}" || { echo "insmod failed"; exit 1; }
	sleep 0.5

	# Run parallel fuzz
	OUTPUT_TEXT=$(python3 "${MULTICORE}" \
		--cores "${CORES}" \
		--seconds "${SECONDS_PER_RUN}" \
		--boot-wait "${BOOT_WAIT}" \
		--bzimage "${BZIMAGE}" \
		2>/dev/null) || true

	# Parse per-core rates and sum
	TOTAL=0
	PER_CORE=""
	while IFS= read -r line; do
		RATE=$(echo "${line}" | grep -oP 'exec_per_sec=\K[0-9]+' || true)
		CPU=$(echo "${line}" | grep -oP 'cpu=\K[0-9]+' || true)
		if [[ -n "${RATE}" ]]; then
			TOTAL=$((TOTAL + RATE))
			[[ -n "${PER_CORE}" ]] && PER_CORE="${PER_CORE}, "
			PER_CORE="${PER_CORE}\"${CPU}\": ${RATE}"
		fi
	done <<< "${OUTPUT_TEXT}"

	echo "  total_exec_per_sec=${TOTAL}"
	ALL_RATES+=("${TOTAL}")

	# Build JSON sample
	SAMPLE="{\"run\": ${run}, \"total_exec_per_sec\": ${TOTAL}, \"per_core\": {${PER_CORE}}}"
	if [[ -n "${ALL_SAMPLES}" ]]; then
		ALL_SAMPLES="${ALL_SAMPLES}, ${SAMPLE}"
	else
		ALL_SAMPLES="${SAMPLE}"
	fi

	# Unload and settle
	rmmod phantom 2>/dev/null || true
	if [[ "${run}" -lt "${RUNS}" ]]; then
		sleep "${TEARDOWN_WAIT}"
	fi
done

# Write results JSON via Python (handles stats properly)
python3 -c "
import json, sys, time

samples = [${ALL_SAMPLES}]
rates = [s['total_exec_per_sec'] for s in samples if s['total_exec_per_sec'] > 0]

# Exclude warmup
warmup = ${WARMUP}
stats_rates = sorted(rates[warmup:])
n = len(stats_rates)

summary = {}
if n > 0:
    summary = {
        'n': n,
        'cores': ${CORES},
        'seconds_per_run': ${SECONDS_PER_RUN},
        'median': stats_rates[n // 2],
        'p25': stats_rates[n // 4],
        'p75': stats_rates[3 * n // 4],
        'min': stats_rates[0],
        'max': stats_rates[-1],
        'mean': round(sum(stats_rates) / n, 1),
    }
    print('Summary (excluding %d warmup):' % warmup)
    print('  n=%d median=%d p25=%d p75=%d min=%d max=%d mean=%.0f' % (
        n, summary['median'], summary['p25'], summary['p75'],
        summary['min'], summary['max'], summary['mean']))

result = {
    'benchmark': 'phantom_30run_execsec_${CORES}core',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    'config': {
        'cores': ${CORES},
        'seconds_per_run': ${SECONDS_PER_RUN},
        'total_runs': ${RUNS},
        'warmup_runs': warmup,
    },
    'samples': samples,
    'exec_per_sec_values': stats_rates,
    'summary': summary,
}

import os
os.makedirs(os.path.dirname('${OUTPUT}') or '.', exist_ok=True)
with open('${OUTPUT}', 'w') as f:
    json.dump(result, f, indent=2)
print('Results written to ${OUTPUT}')
"
