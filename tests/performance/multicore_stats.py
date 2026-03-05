#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
multicore_stats.py — Query PHANTOM_IOCTL_GET_MULTICORE_STATS (ioctl nr=24).

Opens /dev/phantom, calls the ioctl, and prints per-core and total exec/sec.

struct phantom_multicore_stats layout (kernel/interface.h task 3.3):
  u32 active_cores            offset 0
  u32 _pad                    offset 4
  u64 total_exec_per_sec      offset 8
  u64 per_core_exec[8]        offset 16  (8 × 8 = 64 bytes)
  Total: 80 bytes

Usage:
  python3 multicore_stats.py [--device /dev/phantom] [--repeat N] [--interval S]

Exit codes:
  0  success
  1  ioctl failed or device not found
"""

import argparse
import fcntl
import os
import struct
import sys
import time

# ---------------------------------------------------------------------------
# ioctl encoding helpers (matches determinism_check.py convention)
# ---------------------------------------------------------------------------

PHANTOM_IOC_MAGIC = ord('P')  # 0x50


def _IOC(direction, magic, nr, size):
    return (direction << 30) | (size << 16) | (magic << 8) | nr


def _IOR(magic, nr, size):
    return _IOC(2, magic, nr, size)


# struct phantom_multicore_stats: u32 + u32_pad + u64 + 8×u64 = 80 bytes
MULTICORE_STATS_FMT = '=IIQ8Q'
MULTICORE_STATS_SIZE = struct.calcsize(MULTICORE_STATS_FMT)
assert MULTICORE_STATS_SIZE == 80, (
    'struct size mismatch: expected 80, got %d' % MULTICORE_STATS_SIZE)

# PHANTOM_IOCTL_GET_MULTICORE_STATS = _IOR('P', 24, 80)
PHANTOM_IOCTL_GET_MULTICORE_STATS = _IOR(PHANTOM_IOC_MAGIC, 24,
                                          MULTICORE_STATS_SIZE)


def get_multicore_stats(fd):
    """
    Call PHANTOM_IOCTL_GET_MULTICORE_STATS.

    Returns dict with keys:
      active_cores       (int)
      total_exec_per_sec (int)
      per_core_exec      (list of 8 ints)
    Returns None on failure.
    """
    buf = bytearray(MULTICORE_STATS_SIZE)
    try:
        fcntl.ioctl(fd, PHANTOM_IOCTL_GET_MULTICORE_STATS, buf)
    except OSError as e:
        print('ERROR: PHANTOM_IOCTL_GET_MULTICORE_STATS failed: %s' % e,
              file=sys.stderr)
        return None

    fields = struct.unpack_from(MULTICORE_STATS_FMT, buf)
    active_cores = fields[0]
    # fields[1] = _pad
    total_exec_per_sec = fields[2]
    per_core_exec = list(fields[3:11])   # 8 entries

    return {
        'active_cores':       active_cores,
        'total_exec_per_sec': total_exec_per_sec,
        'per_core_exec':      per_core_exec,
    }


def print_stats(stats, label=''):
    prefix = ('[%s] ' % label) if label else ''
    active = stats['active_cores']
    total  = stats['total_exec_per_sec']
    cores  = stats['per_core_exec']

    print('%sactive_cores     : %d' % (prefix, active))
    print('%stotal_exec_per_sec: %d' % (prefix, total))
    for i in range(8):
        marker = ' *' if i < active else ''
        print('%s  core[%d]: %8d exec/s%s' % (prefix, i, cores[i], marker))


def main():
    parser = argparse.ArgumentParser(
        description='Query Phantom multi-core exec/sec stats')
    parser.add_argument('--device', default='/dev/phantom',
                        help='Phantom device node (default: /dev/phantom)')
    parser.add_argument('--repeat', type=int, default=1,
                        help='Number of samples to collect (default: 1)')
    parser.add_argument('--interval', type=float, default=1.0,
                        help='Seconds between samples (default: 1.0)')
    args = parser.parse_args()

    if not os.path.exists(args.device):
        print('ERROR: %s not found — is phantom.ko loaded?' % args.device,
              file=sys.stderr)
        return 1

    fd = os.open(args.device, os.O_RDWR)
    try:
        for i in range(args.repeat):
            stats = get_multicore_stats(fd)
            if stats is None:
                return 1
            label = ('sample %d/%d' % (i + 1, args.repeat)
                     if args.repeat > 1 else '')
            print_stats(stats, label)
            if i < args.repeat - 1:
                time.sleep(args.interval)
    finally:
        os.close(fd)

    return 0


if __name__ == '__main__':
    sys.exit(main())
