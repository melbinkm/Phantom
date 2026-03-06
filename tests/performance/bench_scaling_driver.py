#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
bench_scaling_driver.py — Incremental boot + measure exec/sec at different
parallelism levels WITHOUT module reload.

Key design: boots cores INCREMENTALLY — for measurement at N cores, only
cores 0..N-1 are booted. No pre-booting unused cores, which avoids the
busy-wait starvation where idle vCPU threads (vmx_core.c:1726-1731)
consume physical core resources via cpu_relax() polling loops.

Also avoids the rmmod/insmod cycle that triggers hard lockups on i7-6700
when multiple physical cores have been in VMX root mode (issue #32 Cause 3).

Usage:
  python3 bench_scaling_driver.py --bzimage PATH \
      --seconds 30 --boot-wait 10 --core-counts 1,2,4

Output (human-readable + JSON):
  cores=1 exec_per_sec=78000
  cores=2 exec_per_sec=124000
  cores=4 exec_per_sec=170000
  JSON:{"core_counts": {"1": 78000, "2": 124000, "4": 170000}}

Exit codes:
  0  OK
  1  boot or fuzz error
  2  device/file not found
"""

import argparse
import ctypes
import fcntl
import json
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


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def boot_kernel(fd, bzimage_buf_addr, bzimage_len, cpu, guest_mem_mb):
    args = struct.pack('QQII', bzimage_buf_addr, bzimage_len, cpu,
                       guest_mem_mb)
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
            log('cpu=%d ERROR at iter %d: %s' % (cpu, count, e))
            return count, time.time() - t0
    return count, time.time() - t0


def measure_n_cores(fds, n_cores, seconds):
    """Fuzz n_cores in parallel for `seconds`. Returns total exec/sec."""
    results = {}

    def worker(cpu):
        count, elapsed = fuzz_core(cpu, fds[cpu], seconds)
        results[cpu] = (count, elapsed)

    threads = []
    for cpu in range(n_cores):
        t = threading.Thread(target=worker, args=(cpu,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=seconds + 30)

    total_exec = 0
    for cpu in range(n_cores):
        if cpu in results:
            count, elapsed = results[cpu]
            rate = count / elapsed if elapsed > 0 else 0
            total_exec += int(rate)
            log('  cpu=%d iters=%d elapsed=%.1fs rate=%.0f' % (
                cpu, count, elapsed, rate))
        else:
            log('  cpu=%d ERROR: no result' % cpu)

    return total_exec


def main():
    parser = argparse.ArgumentParser(
        description='Incremental boot + scaling measurement (no module reload)')
    parser.add_argument('--bzimage',
                        default='/root/phantom/linux-6.1.90/arch/x86/boot/bzImage')
    parser.add_argument('--seconds', type=int, default=30,
                        help='Fuzz duration per measurement (default: 30)')
    parser.add_argument('--boot-wait', type=int, default=10,
                        help='Seconds between sequential boots (default: 10)')
    parser.add_argument('--guest-mem-mb', type=int, default=256)
    parser.add_argument('--core-counts', default='1,2,4',
                        help='Comma-separated core counts to measure (default: 1,2,4)')
    parser.add_argument('--settle', type=int, default=3,
                        help='Seconds to settle between measurements (default: 3)')
    args = parser.parse_args()

    core_counts = sorted(int(x) for x in args.core_counts.split(','))

    if not os.path.exists('/dev/phantom'):
        log('ERROR: /dev/phantom not found')
        return 2

    if not os.path.exists(args.bzimage):
        log('ERROR: bzImage not found: %s' % args.bzimage)
        return 2

    # Read bzImage once
    with open(args.bzimage, 'rb') as f:
        data = f.read()
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    buf_addr = ctypes.addressof(buf)
    log('bzImage loaded: %d bytes' % len(data))

    # Track booted cores and their fds
    fds = {}
    booted_up_to = 0  # cores 0..booted_up_to-1 are booted

    results = {}
    for n in core_counts:
        # Incremental boot: only boot cores we haven't booted yet
        while booted_up_to < n:
            cpu = booted_up_to
            log('boot: cpu=%d starting...' % cpu)
            fd = os.open('/dev/phantom', os.O_RDWR)
            try:
                boot_kernel(fd, buf_addr, len(data), cpu, args.guest_mem_mb)
            except OSError as e:
                log('ERROR: BOOT_KERNEL cpu=%d failed: %s' % (cpu, e))
                os.close(fd)
                for prev_fd in fds.values():
                    os.close(prev_fd)
                return 1
            fds[cpu] = fd
            booted_up_to += 1
            log('boot: cpu=%d OK, waiting %ds...' % (cpu, args.boot_wait))
            time.sleep(args.boot_wait)

        # Measure with n cores
        log('measure: cores=%d seconds=%d' % (n, args.seconds))
        total_exec = measure_n_cores(fds, n, args.seconds)
        results[n] = total_exec
        print('cores=%d exec_per_sec=%d' % (n, total_exec), flush=True)

        # Settle between measurements
        if n != core_counts[-1]:
            log('settle: %ds...' % args.settle)
            time.sleep(args.settle)

    # Output JSON summary
    json_results = {str(k): v for k, v in results.items()}
    print('JSON:' + json.dumps({"core_counts": json_results}), flush=True)

    # Cleanup
    for fd in fds.values():
        os.close(fd)

    log('done')
    return 0


if __name__ == '__main__':
    sys.exit(main())
