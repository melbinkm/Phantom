#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# run_tests.sh — top-level test runner for phantom task 1.1
#
# Runs from the WSL2 dev machine.  Syncs sources to phantom-bench,
# builds the module there, then SSH-es into the QEMU guest to run
# the in-guest test suite.
#
# Usage:
#   bash /mnt/d/fuzzer/tests/run_tests.sh [--build-only]
#
# Options:
#   --build-only   Sync and build but skip in-guest testing
#
# Requirements:
#   - phantom-bench SSH alias configured in ~/.ssh/config
#   - QEMU guest running on phantom-bench (port 2222)
#   - 9p share: host /root/phantom/src → guest /mnt/phantom

set -euo pipefail

SRC_DIR="/mnt/d/fuzzer"
REMOTE_HOST="phantom-bench"
REMOTE_SRC="/root/phantom/src"
GUEST_SSH="ssh -p 2222 -o StrictHostKeyChecking=no -o BatchMode=yes root@localhost"
BUILD_ONLY=false

while [[ $# -gt 0 ]]; do
	case "$1" in
		--build-only) BUILD_ONLY=true ;;
		*) echo "Unknown option: $1" >&2; exit 1 ;;
	esac
	shift
done

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
die() { log "ERROR: $*" >&2; exit 1; }

# ---- Step 1: Sync sources to server ---------------------------------

log "Syncing sources to $REMOTE_HOST:$REMOTE_SRC ..."
rsync -az --delete \
	--exclude='.git' \
	--exclude='*.o' \
	--exclude='*.ko' \
	--exclude='*.mod*' \
	--exclude='*.cmd' \
	--exclude='modules.order' \
	--exclude='Module.symvers' \
	"$SRC_DIR/" "$REMOTE_HOST:$REMOTE_SRC/"

log "Sync complete."

# ---- Step 2: Build on server ----------------------------------------

log "Building phantom.ko on $REMOTE_HOST ..."
ssh "$REMOTE_HOST" "make -C $REMOTE_SRC/kernel/ 2>&1" || \
	die "Build failed on $REMOTE_HOST"

log "Build succeeded."

if $BUILD_ONLY; then
	log "--build-only: skipping in-guest tests."
	exit 0
fi

# ---- Step 3: Verify QEMU guest is running ---------------------------

log "Checking QEMU guest is running ..."
if ! ssh "$REMOTE_HOST" "pgrep -x qemu-system-x86 >/dev/null 2>&1"; then
	log "QEMU guest not running — attempting to start ..."
	ssh "$REMOTE_HOST" "bash $REMOTE_SRC/scripts/launch-guest.sh" &
	sleep 15
fi

# Verify SSH to guest works
if ! ssh "$REMOTE_HOST" "$GUEST_SSH 'echo guest-ok'" 2>/dev/null | \
		grep -q 'guest-ok'; then
	die "Cannot SSH into QEMU guest on $REMOTE_HOST:2222"
fi
log "QEMU guest is reachable."

# ---- Step 4: Run in-guest test suite --------------------------------

log "Running in-guest tests ..."
ssh "$REMOTE_HOST" "$GUEST_SSH \
	'bash /mnt/phantom/tests/test_1_1_basic.sh 2>&1'"

log "In-guest tests complete."
