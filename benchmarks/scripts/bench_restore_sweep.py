#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
bench_restore_sweep.py — Measure snapshot restore latency vs dirty page count.

Runs multiple fuzz iterations at each dirty page level and reads the
PHANTOM_IOCTL_PERF_RESTORE_LATENCY counters after each iteration.
Reports median rdtsc cycle counts per component.

Usage:
  python3 bench_restore_sweep.py --bzimage PATH --output results/restore_sweep.json
"""

import argparse
import ctypes
import fcntl
import json
import os
import struct
import sys
import time

PHANTOM_IOC_MAGIC = ord('P')


def _IOC(d, m, nr, sz):
    return (d << 30) | (sz << 16) | (m << 8) | nr


def _IOW(m, nr, sz):
    return _IOC(1, m, nr, sz)


def _IOWR(m, nr, sz):
    return _IOC(3, m, nr, sz)


def _IOR(m, nr, sz):
    return _IOC(2, m, nr, sz)


PHANTOM_IOCTL_BOOT_KERNEL = _IOW(PHANTOM_IOC_MAGIC, 22, 24)
PHANTOM_IOCTL_RUN_ITERATION = _IOWR(PHANTOM_IOC_MAGIC, 20, 8)
PHANTOM_IOCTL_PERF_RESTORE_LATENCY = _IOR(PHANTOM_IOC_MAGIC, 12, 48)


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def boot_kernel(fd, buf_addr, buf_len, cpu, mem_mb):
    args = struct.pack('QQII', buf_addr, buf_len, cpu, mem_mb)
    fcntl.ioctl(fd, PHANTOM_IOCTL_BOOT_KERNEL, bytearray(args))


def run_iteration(fd, payload_len=4, timeout_ms=1000):
    args = struct.pack('II', payload_len, timeout_ms)
    fcntl.ioctl(fd, PHANTOM_IOCTL_RUN_ITERATION, bytearray(args))


def read_restore_perf(fd):
    buf = bytearray(48)
    fcntl.ioctl(fd, PHANTOM_IOCTL_PERF_RESTORE_LATENCY, buf)
    fields = struct.unpack('QQQQQQ', buf)
    return {
        'dirty_page_count': fields[0],
        'dirty_walk_cycles': fields[1],
        'invept_cycles': fields[2],
        'vmcs_cycles': fields[3],
        'xrstor_cycles': fields[4],
        'total_cycles': fields[5],
    }


def median(values):
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0
    return s[n // 2]


def main():
    parser = argparse.ArgumentParser(
        description='Restore latency sweep vs dirty page count')
    parser.add_argument('--bzimage',
                        default='/root/phantom/linux-6.1.90/arch/x86/boot/bzImage')
    parser.add_argument('--output', default='results/restore_sweep.json')
    parser.add_argument('--cpu', type=int, default=0)
    parser.add_argument('--guest-mem-mb', type=int, default=256)
    parser.add_argument('--boot-wait', type=int, default=10)
    parser.add_argument('--iters-per-point', type=int, default=30,
                        help='Iterations per dirty page level (default: 30)')
    parser.add_argument('--warmup', type=int, default=5,
                        help='Warmup iterations to discard (default: 5)')
    args = parser.parse_args()

    if not os.path.exists('/dev/phantom'):
        log('ERROR: /dev/phantom not found')
        return 2

    with open(args.bzimage, 'rb') as f:
        data = f.read()
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    buf_addr = ctypes.addressof(buf)

    fd = os.open('/dev/phantom', os.O_RDWR)
    try:
        boot_kernel(fd, buf_addr, len(data), args.cpu, args.guest_mem_mb)
        log('boot OK, waiting %ds...' % args.boot_wait)
        time.sleep(args.boot_wait)

        # Run iterations and collect restore perf data.
        # The dirty page count is determined by what the guest actually
        # modifies per iteration — we can't control it directly.
        # Instead, we collect data from many iterations and group by
        # observed dirty page count.
        total_iters = args.warmup + args.iters_per_point * 10
        log('Running %d iterations to collect restore latency samples...' %
            total_iters)

        all_perf = []
        for i in range(total_iters):
            run_iteration(fd)
            perf = read_restore_perf(fd)
            if i >= args.warmup:
                all_perf.append(perf)
            if (i + 1) % 100 == 0:
                log('  iter %d/%d dirty=%d total_cycles=%d' % (
                    i + 1, total_iters,
                    perf['dirty_page_count'], perf['total_cycles']))

    except OSError as e:
        log('ERROR: %s' % e)
        os.close(fd)
        return 1
    finally:
        os.close(fd)

    if not all_perf:
        log('ERROR: no perf samples collected')
        return 1

    # Group by dirty page count buckets
    # Since we can't control dirty pages, bucket into ranges
    buckets = {}
    for p in all_perf:
        dp = p['dirty_page_count']
        # Bucket: round to nearest 10 for small, 100 for large
        if dp < 100:
            bucket = (dp // 10) * 10
        elif dp < 1000:
            bucket = (dp // 50) * 50
        else:
            bucket = (dp // 200) * 200
        if bucket == 0:
            bucket = max(1, dp)
        buckets.setdefault(bucket, []).append(p)

    # Compute median for each bucket
    samples = []
    for bucket in sorted(buckets.keys()):
        perfs = buckets[bucket]
        if len(perfs) < 3:
            continue
        samples.append({
            'dirty_pages': bucket,
            'n_samples': len(perfs),
            'dirty_walk_cycles_median': median([p['dirty_walk_cycles'] for p in perfs]),
            'invept_cycles_median': median([p['invept_cycles'] for p in perfs]),
            'vmcs_cycles_median': median([p['vmcs_cycles'] for p in perfs]),
            'xrstor_cycles_median': median([p['xrstor_cycles'] for p in perfs]),
            'total_cycles_median': median([p['total_cycles'] for p in perfs]),
        })

    # Also report raw distribution
    all_dirty = [p['dirty_page_count'] for p in all_perf]
    all_dirty.sort()
    log('\nDirty page distribution:')
    log('  min=%d median=%d max=%d' % (
        all_dirty[0], all_dirty[len(all_dirty)//2], all_dirty[-1]))

    result = {
        'benchmark': 'phantom_restore_sweep',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'config': {
            'iters_per_point': args.iters_per_point,
            'warmup': args.warmup,
            'total_iters': len(all_perf),
        },
        'samples': samples,
        'raw_dirty_page_counts': all_dirty,
    }

    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    log('Results written to %s' % args.output)

    return 0


if __name__ == '__main__':
    sys.exit(main())
