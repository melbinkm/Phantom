#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# bench_30run_3core_reboot.sh — 30 independent 3-core measurements with reboot.
#
# Runs LOCALLY (not on server). For each measurement:
#   1. SSH to server, set mitigations, build module
#   2. 1-core warmup (10s) + rmmod
#   3. 3-core measurement (15s)
#   4. Reboot server (avoids rmmod hang after 3-core VMX)
#   5. Wait for server to come back, repeat
#
# Usage:
#   bash benchmarks/scripts/bench_30run_3core_reboot.sh

set -euo pipefail

SERVER="phantom-bench"
RUNS=30
WARMUP=5
RESULTS_FILE="/mnt/d/fuzzer/benchmarks/results/bench_3core.json"
SAMPLES_FILE="/tmp/phantom_3core_samples.txt"

echo "=== 3-core 30-run benchmark (reboot between runs) ==="
echo "Runs: ${RUNS}, Warmup: ${WARMUP}"
echo ""

# Clear samples file
> "${SAMPLES_FILE}"

for run in $(seq 1 "${RUNS}"); do
	echo "--- Run ${run}/${RUNS} ---"

	# Wait for server to be ready
	for attempt in $(seq 1 30); do
		if ssh -o ConnectTimeout=10 -o BatchMode=yes "${SERVER}" "echo ready" 2>/dev/null; then
			break
		fi
		echo "  Waiting for server... (attempt ${attempt})"
		sleep 10
	done

	# Run measurement: warmup + 3-core fuzz (all in one SSH session)
	RESULT=$(ssh -o ServerAliveInterval=30 "${SERVER}" '
		# Mitigations
		echo 60 > /proc/sys/kernel/watchdog_thresh
		echo 0 > /proc/sys/kernel/nmi_watchdog

		KO=/root/phantom/src/kernel/phantom.ko
		FUZZ=/root/phantom/src/tests/integration/multicore_fuzz.py
		BZ=/root/phantom/linux-6.1.90/arch/x86/boot/bzImage

		# Build if needed
		if [ ! -f "${KO}" ]; then
			cd /root/phantom/src/kernel && make 2>/dev/null
		fi

		# Warmup: 1-core 10s
		rmmod kvm_intel 2>/dev/null
		insmod "${KO}" phantom_cores=0 2>/dev/null
		python3 "${FUZZ}" --cores 1 --seconds 10 --boot-wait 5 --bzimage "${BZ}" >/dev/null 2>&1
		rmmod phantom 2>/dev/null
		sleep 3

		# 3-core measurement
		insmod "${KO}" phantom_cores=0,1,2 2>/dev/null
		python3 "${FUZZ}" --cores 3 --seconds 15 --boot-wait 10 --bzimage "${BZ}" 2>/dev/null
	' 2>/dev/null) || true

	# Parse total exec/sec
	TOTAL=0
	while IFS= read -r line; do
		RATE=$(echo "${line}" | grep -oP 'exec_per_sec=\K[0-9]+' || true)
		[[ -n "${RATE}" ]] && TOTAL=$((TOTAL + RATE))
	done <<< "${RESULT}"

	echo "  total_exec_per_sec=${TOTAL}"
	echo "${run} ${TOTAL}" >> "${SAMPLES_FILE}"

	# Reboot server (avoids rmmod hang after 3-core VMX)
	if [[ "${run}" -lt "${RUNS}" ]]; then
		ssh -o ConnectTimeout=10 "${SERVER}" "reboot" 2>/dev/null || true
		echo "  Rebooting server..."
		sleep 30  # wait for reboot to initiate
	fi
done

echo ""
echo "=== All ${RUNS} runs complete ==="

# Generate JSON results
python3 -c "
import json, time

samples = []
with open('${SAMPLES_FILE}') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) == 2:
            samples.append({'run': int(parts[0]), 'total_exec_per_sec': int(parts[1])})

rates = [s['total_exec_per_sec'] for s in samples if s['total_exec_per_sec'] > 0]
warmup = ${WARMUP}
stats_rates = sorted(rates[warmup:])
n = len(stats_rates)

summary = {}
if n > 0:
    summary = {
        'n': n,
        'cores': 3,
        'seconds_per_run': 15,
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
    'benchmark': 'phantom_30run_execsec_3core',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    'config': {
        'cores': 3,
        'seconds_per_run': 15,
        'total_runs': ${RUNS},
        'warmup_runs': warmup,
        'method': 'per-run reboot (avoids rmmod hang after 3-core VMX)',
    },
    'samples': samples,
    'exec_per_sec_values': stats_rates,
    'summary': summary,
}

import os
os.makedirs(os.path.dirname('${RESULTS_FILE}') or '.', exist_ok=True)
with open('${RESULTS_FILE}', 'w') as f:
    json.dump(result, f, indent=2)
print('Results written to ${RESULTS_FILE}')
"
