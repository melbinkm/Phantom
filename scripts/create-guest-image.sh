#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# scripts/create-guest-image.sh — Build minimal Debian guest for Phase 0-1 nested KVM
#
# Run on phantom-bench AFTER scripts/server-setup.sh and after reboot:
#   bash /root/phantom/src/scripts/create-guest-image.sh
#
# Output: /root/phantom/images/phantom-guest.qcow2
#
# The guest uses the HOST kernel (passed via -kernel in launch-guest.sh),
# so phantom.ko built against host headers loads cleanly in the guest.
# The guest root filesystem is minimal Debian bookworm (~500MB).
#
# The host /root/phantom/src is shared into the guest at /mnt/phantom
# via 9p virtfs — no scp needed, phantom.ko is immediately visible in guest.

set -euo pipefail

IMAGES_DIR=/root/phantom/images
GUEST_IMAGE="$IMAGES_DIR/phantom-guest.qcow2"
GUEST_RAW="$IMAGES_DIR/phantom-guest.raw"
ROOTFS_DIR="$IMAGES_DIR/rootfs"
GUEST_SIZE_GB=8

# Use host kernel + initrd for the guest (ensures .ko version match)
HOST_KERNEL="/boot/vmlinuz-$(uname -r)"
HOST_INITRD="/boot/initrd.img-$(uname -r)"

echo "==> [1/7] Checking prerequisites"
for cmd in debootstrap qemu-img mkfs.ext4 mount; do
    command -v "$cmd" >/dev/null || { echo "ERROR: $cmd not found — run server-setup.sh first"; exit 1; }
done
[[ -f "$HOST_KERNEL" ]] || { echo "ERROR: $HOST_KERNEL not found"; exit 1; }
[[ -f "$HOST_INITRD" ]] || { echo "ERROR: $HOST_INITRD not found"; exit 1; }

if [[ -f "$GUEST_IMAGE" ]]; then
    echo "WARNING: $GUEST_IMAGE already exists."
    read -r -p "Overwrite? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
    rm -f "$GUEST_IMAGE" "$GUEST_RAW"
fi

mkdir -p "$IMAGES_DIR"

echo "==> [2/7] Creating raw disk image (${GUEST_SIZE_GB}GB)"
dd if=/dev/zero of="$GUEST_RAW" bs=1M count=$((GUEST_SIZE_GB * 1024)) status=progress
mkfs.ext4 -F -L phantom-root "$GUEST_RAW"

echo "==> [3/7] Mounting raw image and running debootstrap"
mkdir -p "$ROOTFS_DIR"
mount -o loop "$GUEST_RAW" "$ROOTFS_DIR"

# Minimal bookworm with just what we need for kernel module testing
debootstrap \
    --include=kmod,systemd,systemd-sysv,openssh-server,login,passwd,procps,util-linux,iproute2 \
    --variant=minbase \
    bookworm "$ROOTFS_DIR" http://deb.debian.org/debian

echo "==> [4/7] Configuring guest root filesystem"

# Root password (no key auth needed for local QEMU guest)
chroot "$ROOTFS_DIR" bash -c "echo 'root:phantom' | chpasswd"

# Hostname
echo "phantom-guest" > "$ROOTFS_DIR/etc/hostname"

# Network (virtio-net via QEMU user networking)
cat > "$ROOTFS_DIR/etc/systemd/network/20-eth.network" <<'EOF'
[Match]
Name=e*

[Network]
DHCP=yes
EOF
chroot "$ROOTFS_DIR" systemctl enable systemd-networkd 2>/dev/null || true

# Serial console for boot messages and panic output (visible in launch-guest.sh stdio)
mkdir -p "$ROOTFS_DIR/etc/systemd/system"
chroot "$ROOTFS_DIR" systemctl enable serial-getty@ttyS0.service 2>/dev/null || true

# SSH: permit root login (testing convenience, isolated guest)
sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' "$ROOTFS_DIR/etc/ssh/sshd_config"
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' "$ROOTFS_DIR/etc/ssh/sshd_config"
echo "PermitRootLogin yes" >> "$ROOTFS_DIR/etc/ssh/sshd_config"

# /etc/fstab — 9p mount for host src tree
cat > "$ROOTFS_DIR/etc/fstab" <<'EOF'
# <file system>    <mount point>   <type>  <options>               <dump>  <pass>
LABEL=phantom-root /               ext4    errors=remount-ro       0       1
phantom_share      /mnt/phantom    9p      trans=virtio,version=9p2000.L,rw,_netdev   0   0
EOF

# Create 9p mount point
mkdir -p "$ROOTFS_DIR/mnt/phantom"

# Auto-load 9p modules at boot (needed before fstab mount)
cat > "$ROOTFS_DIR/etc/modules-load.d/9p.conf" <<'EOF'
9p
9pnet
9pnet_virtio
EOF

# Convenience script: load and test phantom.ko from shared mount
cat > "$ROOTFS_DIR/root/load-phantom.sh" <<'INNEREOF'
#!/bin/bash
# Load phantom.ko from 9p shared mount
set -e
echo "Loading phantom.ko from /mnt/phantom/kernel/"
rmmod phantom 2>/dev/null || true
insmod /mnt/phantom/kernel/phantom.ko "$@"
echo "--- dmesg (phantom) ---"
dmesg | grep -E "(phantom|BUG|OOPS|WARNING|Call Trace)" | tail -30
INNEREOF
chmod +x "$ROOTFS_DIR/root/load-phantom.sh"

echo "==> [5/7] Setting up SSH host keys"
chroot "$ROOTFS_DIR" dpkg-reconfigure openssh-server 2>/dev/null || \
    chroot "$ROOTFS_DIR" ssh-keygen -A 2>/dev/null || true

echo "==> [6/7] Unmounting and converting to qcow2"
sync
umount "$ROOTFS_DIR"
rmdir "$ROOTFS_DIR"

qemu-img convert -f raw -O qcow2 -c "$GUEST_RAW" "$GUEST_IMAGE"
rm -f "$GUEST_RAW"

IMGSIZE=$(du -sh "$GUEST_IMAGE" | cut -f1)
echo "==> [7/7] Done"
echo ""
echo "Guest image: $GUEST_IMAGE ($IMGSIZE)"
echo "Host kernel:  $HOST_KERNEL"
echo "Host initrd:  $HOST_INITRD"
echo ""
echo "Next steps:"
echo "  1. Launch guest: bash /root/phantom/src/scripts/launch-guest.sh"
echo "  2. SSH into guest: ssh -p 2222 -o StrictHostKeyChecking=no root@localhost"
echo "     Password: phantom"
echo "  3. In guest: bash /root/load-phantom.sh"
