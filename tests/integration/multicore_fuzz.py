#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
multicore_fuzz.py — Boot N Phantom cores sequentially, then fuzz all in parallel.

Sequential boot prevents the hard lockup that occurs when all physical cores
enter VMX boot loops simultaneously (OS starvation on HT siblings).

Usage:
  python3 multicore_fuzz.py --cores 4 --seconds 30 [--bzimage PATH] [--boot-wait 10]

Output (one line per core):
  cpu=0 iters=400000 elapsed=30.0s exec_per_sec=13333
  cpu=1 iters=410000 elapsed=30.0s exec_per_sec=13666
  ...

Exit codes:
  0  OK
  1  boot or fuzz error
  2  device/file not found
"""

import argparse
import ctypes
import fcntl
import os
import struct
import sys
import threading
import time

PHANTOM_IOC_MAGIC = ord('P')


def _IOC(direction, magic, nr, size):
    return (direction << 30) | (size << 16) | (magic << 8) | nr


def _IOW(magic, nr, size):
    return _IOC(1, magic, nr, size)


def _IOWR(magic, nr, size):
    return _IOC(3, magic, nr, size)


PHANTOM_IOCTL_BOOT_KERNEL = _IOW(PHANTOM_IOC_MAGIC, 22, 24)
PHANTOM_IOCTL_RUN_ITERATION = _IOWR(PHANTOM_IOC_MAGIC, 20, 8)


def boot_kernel(fd, bzimage_data, bzimage_buf_addr, cpu, guest_mem_mb):
    args = struct.pack('QQII', bzimage_buf_addr, len(bzimage_data),
                       cpu, guest_mem_mb)
    fcntl.ioctl(fd, PHANTOM_IOCTL_BOOT_KERNEL, bytearray(args))


def fuzz_core(cpu, fd, seconds):
    """Run fuzz iterations on one core for `seconds`. Returns (count, elapsed)."""
    args = struct.pack('II', 4, 1000)  # payload_len=4, timeout_ms=1000
    count = 0
    t0 = time.time()
    t_end = t0 + seconds
    while time.time() < t_end:
        try:
            fcntl.ioctl(fd, PHANTOM_IOCTL_RUN_ITERATION, bytearray(args))
            count += 1
        except OSError as e:
            print('cpu=%d ERROR at iter %d: %s' % (cpu, count, e),
                  file=sys.stderr)
            return count, time.time() - t0
    return count, time.time() - t0


def main():
    parser = argparse.ArgumentParser(
        description='Sequential boot + parallel fuzz on N Phantom cores')
    parser.add_argument('--bzimage',
                        default='/root/phantom/linux-6.1.90/arch/x86/boot/bzImage')
    parser.add_argument('--cores', type=int, required=True,
                        help='Number of cores to use (0..N-1)')
    parser.add_argument('--seconds', type=int, default=30,
                        help='Fuzz duration per core (default: 30)')
    parser.add_argument('--boot-wait', type=int, default=10,
                        help='Seconds to wait after each boot (default: 10)')
    parser.add_argument('--guest-mem-mb', type=int, default=256)
    args = parser.parse_args()

    if not os.path.exists('/dev/phantom'):
        print('ERROR: /dev/phantom not found', file=sys.stderr)
        return 2

    if not os.path.exists(args.bzimage):
        print('ERROR: bzImage not found: %s' % args.bzimage, file=sys.stderr)
        return 2

    # Read bzImage once
    with open(args.bzimage, 'rb') as f:
        data = f.read()
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    buf_addr = ctypes.addressof(buf)

    # Phase 1: Boot each core sequentially
    fds = {}
    for cpu in range(args.cores):
        fd = os.open('/dev/phantom', os.O_RDWR)
        try:
            boot_kernel(fd, data, buf_addr, cpu, args.guest_mem_mb)
        except OSError as e:
            print('ERROR: BOOT_KERNEL cpu=%d failed: %s' % (cpu, e),
                  file=sys.stderr)
            os.close(fd)
            for prev_fd in fds.values():
                os.close(prev_fd)
            return 1
        fds[cpu] = fd
        print('boot: cpu=%d OK, waiting %ds...' % (cpu, args.boot_wait),
              file=sys.stderr)
        time.sleep(args.boot_wait)

    print('boot: all %d cores booted, starting parallel fuzz for %ds' % (
        args.cores, args.seconds), file=sys.stderr)

    # Phase 2: Fuzz all cores in parallel
    results = {}
    errors = []

    def worker(cpu):
        count, elapsed = fuzz_core(cpu, fds[cpu], args.seconds)
        results[cpu] = (count, elapsed)

    threads = []
    for cpu in range(args.cores):
        t = threading.Thread(target=worker, args=(cpu,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=args.seconds + 30)

    # Print results (stdout — parsed by bench_scaling.sh)
    ok = True
    for cpu in range(args.cores):
        if cpu in results:
            count, elapsed = results[cpu]
            rate = count / elapsed if elapsed > 0 else 0
            print('cpu=%d iters=%d elapsed=%.1fs exec_per_sec=%.0f' % (
                cpu, count, elapsed, rate))
            if count == 0:
                ok = False
        else:
            print('cpu=%d ERROR: no result' % cpu)
            ok = False

    for fd in fds.values():
        os.close(fd)

    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
