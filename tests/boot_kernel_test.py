#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
boot_kernel_test.py -- Test Linux kernel boot inside Phantom.

Usage:
  python3 boot_kernel_test.py [bzimage_path] [--cpu N] [--timeout S]

Exit codes:
  0 = kernel reached harness init (phantom-harness: init seen in dmesg)
  1 = boot failed or timed out
"""
import sys
import os
import struct
import fcntl
import ctypes
import subprocess
import time
import argparse

# ioctl numbers -- must match interface.h
# PHANTOM_IOC_MAGIC = 'P' = 0x50
# PHANTOM_IOCTL_BOOT_KERNEL = _IOW('P', 22, struct phantom_boot_kernel_args)
# struct phantom_boot_kernel_args: u64+u64+u32+u32 = 24 bytes
# _IOW(magic, nr, type) = (1<<30) | (sizeof(type)<<16) | (magic<<8) | nr
PHANTOM_IOC_MAGIC = ord('P')
PHANTOM_IOCTL_BOOT_KERNEL = (
    (1 << 30) |
    (24 << 16) |
    (PHANTOM_IOC_MAGIC << 8) |
    22
)


def main():
    parser = argparse.ArgumentParser(
        description="Test Linux kernel boot inside Phantom")
    parser.add_argument('bzimage', nargs='?',
                        default='/root/phantom/bzImage-guest')
    parser.add_argument('--cpu', type=int, default=0,
                        help='Phantom vCPU index (default: 0)')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Seconds to wait for boot (default: 30)')
    args = parser.parse_args()

    if not os.path.exists(args.bzimage):
        print("ERROR: bzImage not found: %s" % args.bzimage,
              file=sys.stderr)
        return 1

    with open(args.bzimage, 'rb') as f:
        data = f.read()
    print("bzImage: %d bytes (%d KB)" % (len(data), len(data) // 1024))

    if not os.path.exists('/dev/phantom'):
        print("ERROR: /dev/phantom not found -- is phantom.ko loaded?",
              file=sys.stderr)
        return 1

    fd = os.open('/dev/phantom', os.O_RDWR)
    try:
        # Pin the buffer in a ctypes array so it stays alive across the ioctl.
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        buf_addr = ctypes.addressof(buf)

        # struct phantom_boot_kernel_args { __u64, __u64, __u32, __u32 }
        # Pack as two signed longs + two signed ints to match 'QQll' intent,
        # but use 'QQll' where Q=u64 and l=s32 (size matches u32 on LP64).
        boot_args = struct.pack('QQII',
                                buf_addr,   # bzimage_uaddr
                                len(data),  # bzimage_size
                                args.cpu,   # cpu
                                256)        # guest_mem_mb

        print("Calling PHANTOM_IOCTL_BOOT_KERNEL "
              "(cpu=%d, mem=256MB, ioctl=0x%08x)..."
              % (args.cpu, PHANTOM_IOCTL_BOOT_KERNEL))
        try:
            fcntl.ioctl(fd, PHANTOM_IOCTL_BOOT_KERNEL,
                        bytearray(boot_args))
            print("BOOT_KERNEL ioctl: OK")
        except OSError as e:
            print("BOOT_KERNEL ioctl FAILED: %s" % e, file=sys.stderr)
            return 1
    finally:
        os.close(fd)

    # Poll dmesg for guest boot output
    print("Waiting up to %ds for guest boot..." % args.timeout)
    deadline = time.time() + args.timeout
    found_harness = False
    found_panic = False

    while time.time() < deadline:
        try:
            dmesg = subprocess.check_output(
                ['dmesg', '--since', '-60s'], text=True)
        except subprocess.CalledProcessError:
            dmesg = subprocess.check_output(['dmesg'], text=True)

        if 'phantom-harness: init' in dmesg:
            found_harness = True
            break
        if ('phantom[guest]: panic' in dmesg or
                'triple fault' in dmesg.lower()):
            found_panic = True
            break
        time.sleep(0.5)

    if found_harness:
        print("SUCCESS: guest kernel reached phantom-harness init!")
        for line in dmesg.splitlines():
            if any(k in line for k in ['phantom', 'Linux version',
                                        'KASAN', 'Booting']):
                print("  %s" % line.strip())
        return 0
    elif found_panic:
        print("FAIL: guest kernel panicked or triple-faulted")
        lines = dmesg.splitlines()
        for line in lines[-30:]:
            print("  %s" % line)
        return 1
    else:
        print("TIMEOUT: no boot signal after %ds" % args.timeout)
        lines = subprocess.check_output(['dmesg', '-T'], text=True).splitlines()
        for line in lines[-20:]:
            print("  %s" % line)
        return 1


if __name__ == '__main__':
    sys.exit(main())
