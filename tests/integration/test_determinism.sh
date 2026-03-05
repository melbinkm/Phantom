#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_determinism.sh — 1000/1000 determinism gate for Phantom kernel fuzzing.
#
# Loads phantom.ko, then runs determinism_check.py which boots the guest
# bzImage and runs 1000 iterations using the same fixed input.  After each
# iteration it calls PHANTOM_IOCTL_GET_ITER_STATE (ioctl nr=23) to read
# register state + dirty list.  All 1000 states must be byte-identical.
#
# Exit codes:
#   0  PASS — 1000/1000 identical states
#   1  FAIL — divergence detected (details printed)
#   2  SKIP — bzImage not found (build guest kernel first)
#   3  ERROR — module load or boot failure
#
# Usage:
#   sudo bash test_determinism.sh [bzimage_path] [iterations]
#
# Defaults:
#   bzimage_path  /root/phantom/linux-6.1.90/arch/x86/boot/bzImage
#   iterations    1000

set -euo pipefail

BZIMAGE="${1:-/root/phantom/linux-6.1.90/arch/x86/boot/bzImage}"
ITERATIONS="${2:-1000}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
KO="${SRC_ROOT}/kernel/phantom.ko"
DET_CHECK="${SCRIPT_DIR}/determinism_check.py"

echo "=== Phantom determinism gate: ${ITERATIONS} iterations ==="
echo "bzImage: ${BZIMAGE}"
echo "Module:  ${KO}"

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

# ---- Load phantom.ko --------------------------------------------------------

echo ""
echo "--- Loading phantom.ko ---"
if lsmod | grep -q "^phantom "; then
	rmmod phantom 2>/dev/null && echo "  rmmod phantom: OK"
fi
if lsmod | grep -q "^kvm_intel "; then
	rmmod kvm_intel 2>/dev/null && echo "  rmmod kvm_intel: OK"
fi
insmod "${KO}" && echo "  insmod phantom.ko: OK"
sleep 0.5

if [[ ! -c /dev/phantom ]]; then
	echo "ERROR: /dev/phantom not found after insmod"
	dmesg | tail -20
	exit 3
fi

# ---- Run determinism check --------------------------------------------------
#
# determinism_check.py handles boot and iterations in a single fd session:
#   1. Opens /dev/phantom
#   2. Calls PHANTOM_IOCTL_BOOT_KERNEL (boots guest, waits 2s for harness init)
#   3. Runs ITERATIONS × (RUN_ITERATION + GET_ITER_STATE)
#   4. Compares all states against the reference (iteration 1)

echo ""
echo "--- Running determinism_check.py (${ITERATIONS} iterations) ---"
python3 "${DET_CHECK}" \
	--bzimage "${BZIMAGE}" \
	--iterations "${ITERATIONS}"
DET_RC=$?

echo ""
if [[ ${DET_RC} -eq 0 ]]; then
	echo "PASS: ${ITERATIONS}/${ITERATIONS} iterations produced identical state"
else
	echo "FAIL: divergence detected (see details above)"
fi

# ---- Cleanup ----------------------------------------------------------------

echo ""
echo "--- Cleanup ---"
rmmod phantom 2>/dev/null && echo "  rmmod phantom: OK"

exit ${DET_RC}
