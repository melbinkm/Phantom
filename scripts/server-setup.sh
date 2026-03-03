#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# scripts/server-setup.sh — One-time provisioning of phantom-bench
#
# Run once on the bare-metal server after a fresh Ubuntu 24.04 install:
#   ssh phantom-bench "bash -s" < scripts/server-setup.sh
#
# After this script completes:
#   1. Reboot the server (required for crashkernel= to take effect)
#   2. Run scripts/create-guest-image.sh to build the nested KVM guest
#   3. Run scripts/launch-guest.sh to start the QEMU guest for Phase 0-1 work
#
# Server state this script expects:
#   - Ubuntu 24.04.x LTS, kernel 6.8+ (generic)
#   - Internet access via apt
#   - /dev/kvm present (kvm_intel loaded)
#   - Running as root

set -euo pipefail

PHANTOM_SRC=/root/phantom/src
PHANTOM_IMAGES=/root/phantom/images
PHANTOM_LOGS=/root/phantom/logs

echo "==> [1/6] Installing build prerequisites"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    gcc \
    make \
    "linux-headers-$(uname -r)" \
    linux-tools-common \
    "linux-tools-$(uname -r)" \
    qemu-system-x86 \
    qemu-utils \
    debootstrap \
    kdump-tools \
    kexec-tools \
    crash \
    trace-cmd \
    sparse \
    git \
    rsync \
    wget \
    curl

echo "==> [2/6] Creating phantom directory layout"
mkdir -p "$PHANTOM_SRC" "$PHANTOM_IMAGES" "$PHANTOM_LOGS"
echo "phantom-bench ready at $(date)" > "$PHANTOM_LOGS/setup.log"

echo "==> [3/6] Configuring kdump (requires reboot to activate)"
# crashkernel= reserves RAM for the crash kernel at boot time.
# Must be in GRUB_CMDLINE_LINUX so it applies even on the production kernel.
# 256M is sufficient for a kernel crash dump on a 62GB machine.
mkdir -p /etc/default/grub.d
cat > /etc/default/grub.d/kdump.cfg <<'EOF'
# Reserve 256M for kdump crash kernel
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX crashkernel=256M"
EOF
update-grub
systemctl enable kdump-tools
# Set kdump to save dumps to local disk (not SSH) for simplicity
sed -i 's|^USE_KDUMP=.*|USE_KDUMP=1|' /etc/default/kdump-tools 2>/dev/null || true

echo "==> [4/6] Configuring kdump crash dump path"
# Save vmcore to /var/crash (default) — check post-panic via:
#   ssh phantom-bench "ls -lt /var/crash/ | head"
mkdir -p /var/crash
chmod 700 /var/crash

echo "==> [5/6] Configuring netconsole (serial console substitute)"
# Netconsole sends kernel log messages over UDP to your dev machine.
# This replaces a physical serial console for remote Hetzner servers.
#
# Usage:
#   On dev machine (WSL2): nc -u -l -p 6666
#   On server (after setup): modprobe netconsole netconsole=@/enp0s31f6,6666@<DEV_IP>/
#
# To find your server's network interface:
#   ip route get 8.8.8.8 | awk '{print $5; exit}'
#
# To make netconsole persistent across reboots:
NETCONSOLE_CONF=/etc/modprobe.d/netconsole.conf
SERVER_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -1)
if [[ -n "$SERVER_IFACE" ]]; then
    echo "# Netconsole: modprobe netconsole to activate, configure DEV_MACHINE_IP first" \
        > "$NETCONSOLE_CONF"
    echo "# options netconsole netconsole=@/$SERVER_IFACE,6666@DEV_MACHINE_IP/" \
        >> "$NETCONSOLE_CONF"
    echo "    Server interface: $SERVER_IFACE"
    echo "    Edit $NETCONSOLE_CONF to set DEV_MACHINE_IP, then:"
    echo "    modprobe netconsole"
    echo "    (On dev machine): nc -u -l -p 6666"
else
    echo "    WARNING: could not detect network interface — edit $NETCONSOLE_CONF manually"
fi

echo "==> [6/6] Verifying KVM and Intel PT availability"
if [[ ! -c /dev/kvm ]]; then
    echo "ERROR: /dev/kvm not found — check BIOS VT-x settings"
    exit 1
fi
lsmod | grep -q kvm_intel && echo "    kvm_intel: loaded" || echo "    WARNING: kvm_intel not loaded"
grep -q "^flags.*intel_pt" /proc/cpuinfo && echo "    Intel PT: present" || echo "    WARNING: Intel PT not in /proc/cpuinfo"
lscpu | grep -i "model name"

echo ""
echo "==> Setup complete. REQUIRED NEXT STEPS:"
echo ""
echo "  1. REBOOT the server for crashkernel= to take effect:"
echo "       reboot"
echo "     After reboot, verify: grep crashkernel /proc/cmdline"
echo ""
echo "  2. Build guest image (Phase 0-1 only):"
echo "       bash /root/phantom/src/scripts/create-guest-image.sh"
echo ""
echo "  3. Launch guest (Phase 0-1 only):"
echo "       bash /root/phantom/src/scripts/launch-guest.sh"
echo ""
echo "  4. For netconsole (crash observability):"
echo "       Edit $NETCONSOLE_CONF — set DEV_MACHINE_IP"
echo "       modprobe netconsole"
echo "       (On dev WSL2): nc -u -l -p 6666"
