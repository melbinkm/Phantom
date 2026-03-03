#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# scripts/launch-guest.sh — Launch QEMU guest for Phase 0-1 nested KVM testing
#
# Run on phantom-bench after create-guest-image.sh:
#   bash /root/phantom/src/scripts/launch-guest.sh
#
# The guest runs in the background. Serial output is written to:
#   /root/phantom/logs/guest.log
#
# Connect to guest:
#   ssh -p 2222 -o StrictHostKeyChecking=no root@localhost   (password: phantom)
#
# Load phantom.ko in guest (9p share makes it instantly available):
#   ssh -p 2222 root@localhost "bash /root/load-phantom.sh"
#
# Stop the guest:
#   kill $(cat /root/phantom/logs/guest.pid)
#
# From dev machine (WSL2), nested SSH:
#   ssh phantom-bench "ssh -p 2222 root@localhost 'bash /root/load-phantom.sh'"

set -euo pipefail

IMAGES_DIR=/root/phantom/images
LOGS_DIR=/root/phantom/logs
SRC_DIR=/root/phantom/src
GUEST_IMAGE="$IMAGES_DIR/phantom-guest.qcow2"
GUEST_LOG="$LOGS_DIR/guest.log"
GUEST_PID="$LOGS_DIR/guest.pid"

# Guest resources — use half of available cores, cap at 4
GUEST_SMP=$(( $(nproc) / 2 ))
GUEST_SMP=$(( GUEST_SMP > 4 ? 4 : GUEST_SMP ))
GUEST_SMP=$(( GUEST_SMP < 1 ? 1 : GUEST_SMP ))
GUEST_MEM=4G

HOST_KERNEL="/boot/vmlinuz-$(uname -r)"
HOST_INITRD="/boot/initrd.img-$(uname -r)"

echo "==> Checking prerequisites"
[[ -f "$GUEST_IMAGE" ]] || {
    echo "ERROR: $GUEST_IMAGE not found — run create-guest-image.sh first"
    exit 1
}
[[ -f "$HOST_KERNEL" ]] || { echo "ERROR: $HOST_KERNEL not found"; exit 1; }
[[ -c /dev/kvm ]] || { echo "ERROR: /dev/kvm not found"; exit 1; }

# Stop any already-running guest
if [[ -f "$GUEST_PID" ]]; then
    OLD_PID=$(cat "$GUEST_PID")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        if [[ -t 0 ]]; then
            echo "WARNING: Guest already running (PID $OLD_PID). Kill it? [y/N]"
            read -r ans
            [[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
        else
            echo "Non-interactive mode: auto-killing guest (PID $OLD_PID)"
        fi
        kill "$OLD_PID"
        sleep 2
    fi
    rm -f "$GUEST_PID"
fi

mkdir -p "$LOGS_DIR"
: > "$GUEST_LOG"

echo "==> Launching QEMU guest"
echo "    Kernel:  $HOST_KERNEL"
echo "    Image:   $GUEST_IMAGE"
echo "    CPUs:    $GUEST_SMP"
echo "    RAM:     $GUEST_MEM"
echo "    9p src:  $SRC_DIR → /mnt/phantom (in guest)"
echo "    SSH:     localhost:2222 → guest:22"
echo "    Log:     $GUEST_LOG"
echo ""

qemu-system-x86_64 \
    -enable-kvm \
    -cpu host \
    -smp "$GUEST_SMP" \
    -m "$GUEST_MEM" \
    -kernel "$HOST_KERNEL" \
    -initrd "$HOST_INITRD" \
    -append "console=ttyS0 root=LABEL=phantom-root rw quiet" \
    -drive "file=$GUEST_IMAGE,format=qcow2,if=virtio,cache=writeback" \
    -virtfs "local,path=$SRC_DIR,mount_tag=phantom_share,security_model=passthrough,id=phantom_fs" \
    -netdev "user,id=net0,hostfwd=tcp::2222-:22" \
    -device "virtio-net-pci,netdev=net0" \
    -nographic \
    -serial "file:$GUEST_LOG" \
    -monitor "none" \
    -pidfile "$GUEST_PID" \
    &

QEMU_BG_PID=$!

echo "==> Guest launched (background PID: $QEMU_BG_PID)"
echo "    Waiting for guest SSH to come up (up to 60s)..."

for i in $(seq 1 90); do
    sleep 1
    # Use nc TCP check first (no auth needed); fall back to key-based SSH
    if nc -z localhost 2222 2>/dev/null && \
       ssh -p 2222 \
           -o StrictHostKeyChecking=no \
           -o ConnectTimeout=2 \
           -o BatchMode=yes \
           -o PasswordAuthentication=no \
           root@localhost "echo ready" 2>/dev/null | grep -q ready; then
        echo ""
        echo "==> Guest is ready!"
        echo ""
        echo "Connect:  ssh -p 2222 -o StrictHostKeyChecking=no root@localhost"
        echo "          (key auth; password: phantom)"
        echo ""
        echo "From dev machine (WSL2):"
        echo "  ssh phantom-bench \"ssh -p 2222 root@localhost 'bash /root/load-phantom.sh'\""
        echo ""
        echo "Serial log (boot messages + panics):"
        echo "  ssh phantom-bench 'tail -f /root/phantom/logs/guest.log'"
        echo ""
        echo "Stop guest:  kill \$(cat $GUEST_PID)"
        exit 0
    fi
    printf "."
done

echo ""
echo "WARNING: Guest SSH did not come up in 60s."
echo "Check boot log: ssh phantom-bench 'cat $GUEST_LOG'"
