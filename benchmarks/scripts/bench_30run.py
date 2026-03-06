#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
bench_30run.py — Run 30 independent fuzz sessions and collect exec/sec samples.

Each run: boot guest, fuzz for --seconds, record exec/sec.
Module is loaded once; runs are sequential on a single core.

Output: JSON file with 30 exec/sec samples + metadata.

Usage:
  python3 bench_30run.py --bzimage PATH --seconds 60 --runs 30 --output results.json
"""

import argparse
import ctypes
import fcntl
import json
import os
import platform
import struct
import subprocess
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


def run_iterations(fd, seconds):
    """Fuzz for `seconds`, return (count, elapsed)."""
    args = struct.pack('II', 4, 1000)
    count = 0
    t0 = time.time()
    t_end = t0 + seconds
    while time.time() < t_end:
        try:
            fcntl.ioctl(fd, PHANTOM_IOCTL_RUN_ITERATION, bytearray(args))
            count += 1
        except OSError as e:
            log('ERROR at iter %d: %s' % (count, e))
            return count, time.time() - t0
    return count, time.time() - t0


def read_restore_perf(fd):
    """Read last restore latency counters."""
    buf = bytearray(48)
    try:
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
    except OSError:
        return None


def get_hardware_info():
    """Collect hardware metadata."""
    info = {
        'kernel': platform.release(),
        'hostname': platform.node(),
    }
    try:
        with open('/proc/cpuinfo') as f:
            for line in f:
                if line.startswith('model name'):
                    info['cpu_model'] = line.split(':')[1].strip()
                    break
    except OSError:
        pass
    try:
        info['turbo_disabled'] = open(
            '/sys/devices/system/cpu/intel_pstate/no_turbo').read().strip()
    except OSError:
        info['turbo_disabled'] = 'unknown'
    return info


def main():
    parser = argparse.ArgumentParser(description='30-run exec/sec benchmark')
    parser.add_argument('--bzimage',
                        default='/root/phantom/linux-6.1.90/arch/x86/boot/bzImage')
    parser.add_argument('--seconds', type=int, default=60,
                        help='Fuzz duration per run (default: 60)')
    parser.add_argument('--runs', type=int, default=30,
                        help='Number of independent runs (default: 30)')
    parser.add_argument('--output', default='results/bench_30run.json')
    parser.add_argument('--cpu', type=int, default=0)
    parser.add_argument('--guest-mem-mb', type=int, default=256)
    parser.add_argument('--boot-wait', type=int, default=10)
    parser.add_argument('--warmup', type=int, default=5,
                        help='Discard first N runs as warmup (default: 5)')
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

    hw_info = get_hardware_info()
    log('Hardware: %s' % json.dumps(hw_info))
    log('Config: %d runs × %ds each, cpu=%d, warmup=%d' % (
        args.runs, args.seconds, args.cpu, args.warmup))

    all_samples = []
    restore_perf_samples = []

    # Boot once, then run multiple timed measurement intervals on the same fd.
    # Re-booting the same CPU without module reload crashes the system.
    fd = os.open('/dev/phantom', os.O_RDWR)
    try:
        boot_kernel(fd, buf_addr, len(data), args.cpu, args.guest_mem_mb)
        log('boot OK, waiting %ds...' % args.boot_wait)
        time.sleep(args.boot_wait)

        for run in range(args.runs):
            log('--- Run %d/%d ---' % (run + 1, args.runs))

            count, elapsed = run_iterations(fd, args.seconds)
            rate = count / elapsed if elapsed > 0 else 0
            log('  iters=%d elapsed=%.1fs exec_per_sec=%.0f' % (
                count, elapsed, rate))

            perf = read_restore_perf(fd)
            all_samples.append({
                'run': run + 1,
                'iters': count,
                'elapsed_s': round(elapsed, 2),
                'exec_per_sec': round(rate, 1),
                'restore_perf': perf,
            })
            if perf:
                restore_perf_samples.append(perf)

    except OSError as e:
        log('ERROR: %s' % e)
        all_samples.append({
            'run': len(all_samples) + 1,
            'error': str(e),
        })
    finally:
        os.close(fd)

    # Compute summary stats (excluding warmup)
    exec_rates = [s['exec_per_sec'] for s in all_samples
                  if 'exec_per_sec' in s][args.warmup:]
    exec_rates.sort()

    summary = {}
    if exec_rates:
        n = len(exec_rates)
        summary = {
            'n': n,
            'median': exec_rates[n // 2],
            'p25': exec_rates[n // 4],
            'p75': exec_rates[3 * n // 4],
            'min': exec_rates[0],
            'max': exec_rates[-1],
            'mean': round(sum(exec_rates) / n, 1),
        }
        log('\nSummary (excluding %d warmup runs):' % args.warmup)
        log('  n=%d median=%.0f p25=%.0f p75=%.0f min=%.0f max=%.0f' % (
            n, summary['median'], summary['p25'], summary['p75'],
            summary['min'], summary['max']))

    result = {
        'benchmark': 'phantom_30run_execsec',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'hardware': hw_info,
        'config': {
            'bzimage': args.bzimage,
            'seconds_per_run': args.seconds,
            'total_runs': args.runs,
            'warmup_runs': args.warmup,
            'cpu': args.cpu,
            'guest_mem_mb': args.guest_mem_mb,
        },
        'samples': all_samples,
        'exec_per_sec_values': exec_rates,
        'summary': summary,
    }

    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    log('Results written to %s' % args.output)

    return 0


if __name__ == '__main__':
    sys.exit(main())
