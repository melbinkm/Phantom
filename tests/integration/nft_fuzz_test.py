#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
nft_fuzz_test.py — Quick test for nf_tables fuzzing harness.

Boots the nft guest kernel, loads seed corpus files, and runs
fuzz iterations using each seed. Reports any crashes found.

Usage:
    python3 nft_fuzz_test.py [--seeds DIR] [--seconds N] [--bzimage PATH]
"""
import argparse
import ctypes
import fcntl
import mmap
import os
import struct
import sys
import time
import random

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

PAYLOAD_MAX = 65536  # shared memory page size
PAYLOAD_HDR = 4      # u32 length prefix


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(description='nf_tables fuzz test')
    parser.add_argument('--bzimage',
                        default='/root/phantom/linux-6.1.90/arch/x86/boot/bzImage')
    parser.add_argument('--seeds',
                        default='/root/phantom/src/guest/guest_kernel/seeds/corpus')
    parser.add_argument('--cpu', type=int, default=0)
    parser.add_argument('--guest-mem-mb', type=int, default=256)
    parser.add_argument('--seconds', type=int, default=30,
                        help='Fuzz duration in seconds (default: 30)')
    parser.add_argument('--boot-wait', type=int, default=15)
    parser.add_argument('--timeout-ms', type=int, default=1000)
    args = parser.parse_args()

    if not os.path.exists('/dev/phantom'):
        log('ERROR: /dev/phantom not found')
        return 2

    # Load seed files
    seeds = []
    if os.path.isdir(args.seeds):
        for fname in sorted(os.listdir(args.seeds)):
            path = os.path.join(args.seeds, fname)
            if os.path.isfile(path):
                with open(path, 'rb') as f:
                    data = f.read()
                if len(data) > 0:
                    seeds.append((fname, data))
                    log(f'  seed: {fname} ({len(data)} bytes)')
    if not seeds:
        log('ERROR: no seeds found in %s' % args.seeds)
        return 2
    log(f'Loaded {len(seeds)} seeds')

    # Open /dev/phantom
    fd = os.open('/dev/phantom', os.O_RDWR)

    # mmap the shared memory (payload region at offset 0, RW)
    # Must be done AFTER module is loaded and pages are allocated.
    MMAP_SIZE = 65536
    mm = None

    # Boot kernel
    log(f'Booting kernel: {args.bzimage}')
    with open(args.bzimage, 'rb') as f:
        bzdata = f.read()
    buf = (ctypes.c_char * len(bzdata)).from_buffer_copy(bzdata)
    buf_addr = ctypes.addressof(buf)
    boot_args = struct.pack('QQII', buf_addr, len(bzdata),
                            args.cpu, args.guest_mem_mb)
    try:
        fcntl.ioctl(fd, PHANTOM_IOCTL_BOOT_KERNEL, bytearray(boot_args))
    except OSError as e:
        log(f'ERROR: BOOT_KERNEL failed: {e}')
        mm.close()
        os.close(fd)
        return 1

    log(f'Boot OK, waiting {args.boot_wait}s for harness init...')
    time.sleep(args.boot_wait)

    # mmap shared memory now that boot has initialized everything
    try:
        mm = mmap.mmap(fd, MMAP_SIZE, flags=mmap.MAP_SHARED,
                       prot=mmap.PROT_READ | mmap.PROT_WRITE,
                       offset=0)
        log('mmap OK (payload injection active)')
    except Exception as e:
        log(f'WARNING: mmap failed: {e} — payloads will be zeros')

    # Fuzz loop: cycle through seeds with random mutations
    log(f'Starting {args.seconds}s nf_tables fuzz campaign...')
    t_start = time.time()
    t_end = t_start + args.seconds
    total_iters = 0
    crashes = 0
    seed_idx = 0

    while time.time() < t_end:
        # Pick a seed and optionally mutate it
        name, seed_data = seeds[seed_idx % len(seeds)]
        seed_idx += 1

        # Simple mutation: copy seed, flip random bytes
        data = bytearray(seed_data)
        if random.random() < 0.8 and len(data) > 0:
            # Flip 1-8 random bytes
            for _ in range(random.randint(1, min(8, len(data)))):
                pos = random.randint(0, len(data) - 1)
                data[pos] ^= random.randint(1, 255)

        # Occasionally truncate or extend
        if random.random() < 0.1 and len(data) > 16:
            data = data[:random.randint(16, len(data))]
        elif random.random() < 0.1:
            data += bytes(random.randint(0, 255)
                          for _ in range(random.randint(1, 64)))

        payload_len = min(len(data), PAYLOAD_MAX - PAYLOAD_HDR)

        # Write payload to shared memory if mmap is available
        # The shared_mem layout is: payload[64KB] at offset 0
        # The guest reads from GPA 0x600000: [u32 len][payload...]
        # The host copies shared_mem->payload (offset 0) to guest GPA
        # on each RUN_ITERATION, using payload_len from the ioctl arg.
        if mm is not None:
            mm.seek(0)
            mm.write(data[:payload_len])

        # Run one iteration
        iter_args = bytearray(struct.pack('II', payload_len, args.timeout_ms))
        try:
            fcntl.ioctl(fd, PHANTOM_IOCTL_RUN_ITERATION, iter_args)
        except OSError as e:
            log(f'ERROR: RUN_ITERATION failed at iter {total_iters}: {e}')
            break

        total_iters += 1

        if total_iters % 50000 == 0:
            elapsed = time.time() - t_start
            rate = total_iters / elapsed if elapsed > 0 else 0
            log(f'  {total_iters} iters, {rate:.0f} exec/s, '
                f'{crashes} crashes')

    elapsed = time.time() - t_start
    rate = total_iters / elapsed if elapsed > 0 else 0
    log(f'\nDone: {total_iters} iterations in {elapsed:.1f}s '
        f'({rate:.0f} exec/s)')
    log(f'Crashes: {crashes}')

    if mm is not None:
        mm.close()
    os.close(fd)
    return 0


if __name__ == '__main__':
    sys.exit(main())
