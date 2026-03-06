#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
bench_30run_multicore.py — 30 timed measurement intervals with N cores
fuzzing in parallel. Boots all cores once, then runs repeated intervals.

Output: JSON file with 30 total exec/sec samples + metadata.

Usage:
  python3 bench_30run_multicore.py --bzimage PATH --cores 3 --seconds 30 \
      --runs 30 --output results.json
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


def _IOC(d, m, nr, sz):
    return (d << 30) | (sz << 16) | (m << 8) | nr


def _IOW(m, nr, sz):
    return _IOC(1, m, nr, sz)


def _IOWR(m, nr, sz):
    return _IOC(3, m, nr, sz)


PHANTOM_IOCTL_BOOT_KERNEL = _IOW(PHANTOM_IOC_MAGIC, 22, 24)
PHANTOM_IOCTL_RUN_ITERATION = _IOWR(PHANTOM_IOC_MAGIC, 20, 8)


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def boot_kernel(fd, buf_addr, buf_len, cpu, mem_mb):
    args = struct.pack('QQII', buf_addr, buf_len, cpu, mem_mb)
    fcntl.ioctl(fd, PHANTOM_IOCTL_BOOT_KERNEL, bytearray(args))


def fuzz_core(cpu, fd, seconds):
    args = struct.pack('II', 4, 1000)
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


def measure_all_cores(fds, n_cores, seconds):
    """Fuzz all cores in parallel for `seconds`. Returns total exec/sec and per-core rates."""
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

    total = 0
    per_core = {}
    for cpu in range(n_cores):
        if cpu in results:
            count, elapsed = results[cpu]
            rate = count / elapsed if elapsed > 0 else 0
            total += int(rate)
            per_core[cpu] = round(rate, 1)

    return total, per_core


def main():
    parser = argparse.ArgumentParser(
        description='30-run multi-core exec/sec benchmark')
    parser.add_argument('--bzimage',
                        default='/root/phantom/linux-6.1.90/arch/x86/boot/bzImage')
    parser.add_argument('--cores', type=int, default=3)
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--runs', type=int, default=30)
    parser.add_argument('--output', default='results/bench_3core.json')
    parser.add_argument('--guest-mem-mb', type=int, default=256)
    parser.add_argument('--boot-wait', type=int, default=10)
    parser.add_argument('--warmup', type=int, default=5)
    parser.add_argument('--settle', type=int, default=2,
                        help='Settle seconds between runs (default: 2)')
    args = parser.parse_args()

    if not os.path.exists('/dev/phantom'):
        log('ERROR: /dev/phantom not found')
        return 2
    if not os.path.exists(args.bzimage):
        log('ERROR: bzImage not found: %s' % args.bzimage)
        return 2

    with open(args.bzimage, 'rb') as f:
        data = f.read()
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    buf_addr = ctypes.addressof(buf)

    log('Config: %d cores, %d runs × %ds each, warmup=%d' % (
        args.cores, args.runs, args.seconds, args.warmup))

    # Boot all cores sequentially
    fds = {}
    for cpu in range(args.cores):
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
        log('boot: cpu=%d OK, waiting %ds...' % (cpu, args.boot_wait))
        time.sleep(args.boot_wait)

    log('All %d cores booted. Starting %d measurement runs.' % (
        args.cores, args.runs))

    all_samples = []
    for run in range(args.runs):
        log('--- Run %d/%d ---' % (run + 1, args.runs))
        total, per_core = measure_all_cores(fds, args.cores, args.seconds)
        log('  total_exec_per_sec=%d per_core=%s' % (total, per_core))
        all_samples.append({
            'run': run + 1,
            'total_exec_per_sec': total,
            'per_core': per_core,
        })
        if run < args.runs - 1:
            time.sleep(args.settle)

    # Cleanup
    for fd in fds.values():
        os.close(fd)

    # Stats (excluding warmup)
    rates = [s['total_exec_per_sec'] for s in all_samples][args.warmup:]
    rates.sort()
    n = len(rates)
    summary = {}
    if n > 0:
        summary = {
            'n': n,
            'cores': args.cores,
            'median': rates[n // 2],
            'p25': rates[n // 4],
            'p75': rates[3 * n // 4],
            'min': rates[0],
            'max': rates[-1],
            'mean': round(sum(rates) / n, 1),
        }
        log('\nSummary (excluding %d warmup):' % args.warmup)
        log('  n=%d median=%d p25=%d p75=%d min=%d max=%d' % (
            n, summary['median'], summary['p25'], summary['p75'],
            summary['min'], summary['max']))

    result = {
        'benchmark': 'phantom_30run_execsec_%dcore' % args.cores,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'config': {
            'cores': args.cores,
            'seconds_per_run': args.seconds,
            'total_runs': args.runs,
            'warmup_runs': args.warmup,
        },
        'samples': all_samples,
        'exec_per_sec_values': rates,
        'summary': summary,
    }

    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    log('Results written to %s' % args.output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
