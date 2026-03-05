#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
boot_and_fuzz.py — Boot guest bzImage on one Phantom vCPU and run fuzz
iterations continuously until a time limit or iteration limit is reached.

Used by bench_scaling.sh to drive per-CPU fuzzing workers in parallel.

Usage:
  python3 boot_and_fuzz.py [--bzimage PATH] [--cpu N] [--seconds N]
                           [--iterations N] [--guest-mem-mb N]

Exit codes:
  0  OK — ran successfully
  1  FAIL — ioctl or boot error
  2  ERROR — device/file not found
"""

import argparse
import ctypes
import fcntl
import os
import struct
import sys
import time

PHANTOM_IOC_MAGIC = ord('P')  # 0x50


def _IOC(direction, magic, nr, size):
    return (direction << 30) | (size << 16) | (magic << 8) | nr


def _IOW(magic, nr, size):
    return _IOC(1, magic, nr, size)


def _IOWR(magic, nr, size):
    return _IOC(3, magic, nr, size)


# PHANTOM_IOCTL_BOOT_KERNEL = _IOW('P', 22, 24)
PHANTOM_IOCTL_BOOT_KERNEL = _IOW(PHANTOM_IOC_MAGIC, 22, 24)

# PHANTOM_IOCTL_RUN_ITERATION = _IOWR('P', 20, 8)
PHANTOM_IOCTL_RUN_ITERATION = _IOWR(PHANTOM_IOC_MAGIC, 20, 8)


def boot_kernel(fd, bzimage_path, cpu, guest_mem_mb):
    with open(bzimage_path, 'rb') as f:
        data = f.read()
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    buf_addr = ctypes.addressof(buf)
    args = struct.pack('QQII', buf_addr, len(data), cpu, guest_mem_mb)
    try:
        fcntl.ioctl(fd, PHANTOM_IOCTL_BOOT_KERNEL, bytearray(args))
        return True
    except OSError as e:
        print('ERROR: BOOT_KERNEL failed on cpu %d: %s' % (cpu, e),
              file=sys.stderr)
        return False


def run_iterations(fd, duration_sec, max_iters, payload_len=4,
                   timeout_ms=1000):
    """Run fuzz iterations for up to duration_sec seconds or max_iters."""
    args = struct.pack('II', payload_len, timeout_ms)
    count = 0
    t_end = time.time() + duration_sec if duration_sec > 0 else float('inf')
    limit = max_iters if max_iters > 0 else float('inf')

    while time.time() < t_end and count < limit:
        buf = bytearray(args)
        try:
            fcntl.ioctl(fd, PHANTOM_IOCTL_RUN_ITERATION, buf)
        except OSError as e:
            print('ERROR: RUN_ITERATION failed at iter %d: %s' % (count, e),
                  file=sys.stderr)
            return count, False
        count += 1

    return count, True


def main():
    parser = argparse.ArgumentParser(
        description='Boot Phantom guest and run fuzz iterations')
    parser.add_argument('--bzimage',
                        default='/root/phantom/linux-6.1.90/arch/x86/boot/bzImage')
    parser.add_argument('--cpu', type=int, default=0,
                        help='Phantom vCPU index (default: 0)')
    parser.add_argument('--seconds', type=int, default=30,
                        help='Run duration in seconds (0=unlimited, default: 30)')
    parser.add_argument('--iterations', type=int, default=0,
                        help='Max iterations (0=unlimited, default: 0)')
    parser.add_argument('--guest-mem-mb', type=int, default=256)
    parser.add_argument('--skip-boot', action='store_true',
                        help='Skip BOOT_KERNEL (guest already running)')
    args = parser.parse_args()

    if not os.path.exists('/dev/phantom'):
        print('ERROR: /dev/phantom not found', file=sys.stderr)
        return 2

    if not args.skip_boot and not os.path.exists(args.bzimage):
        print('ERROR: bzImage not found: %s' % args.bzimage, file=sys.stderr)
        return 2

    fd = os.open('/dev/phantom', os.O_RDWR)
    try:
        if not args.skip_boot:
            if not boot_kernel(fd, args.bzimage, args.cpu, args.guest_mem_mb):
                return 1
            time.sleep(2.0)  # wait for guest harness init

        t0 = time.time()
        count, ok = run_iterations(fd, args.seconds, args.iterations)
        elapsed = time.time() - t0

        rate = count / elapsed if elapsed > 0 else 0
        print('cpu=%d iters=%d elapsed=%.1fs exec_per_sec=%.0f' % (
            args.cpu, count, elapsed, rate))
        return 0 if ok else 1
    finally:
        os.close(fd)


if __name__ == '__main__':
    sys.exit(main())
