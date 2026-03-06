#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
determinism_check.py — Phantom 1000/1000 determinism gate checker.

Opens /dev/phantom, boots the guest bzImage (if not already booted),
runs N fuzz iterations with the same fixed 4-byte input, and after each
iteration calls PHANTOM_IOCTL_GET_ITER_STATE (ioctl nr=23) to read:
  - All 16 GP registers (RIP, RSP, RFLAGS, CR3, RAX..R15)
  - dirty_count and dirty_gpas[]

Compares all N states against iteration 1 (the reference).
Prints PASS or FAIL with details of the first divergence.

Usage:
  python3 determinism_check.py [--bzimage PATH] [--iterations N] [--cpu CPU]

Exit codes:
  0  PASS — all N states identical to reference
  1  FAIL — at least one divergence found
  2  ERROR — device open, boot, or ioctl failure
"""

import argparse
import array
import ctypes
import fcntl
import os
import struct
import sys
import time

# ---------------------------------------------------------------------------
# ioctl numbers
#
# _IOC(dir, type, nr, size):
#   dir:  0=none, 1=write(from user), 2=read(from kernel), 3=both
#   type: magic byte ('P' = 0x50)
#   nr:   command number
#   size: sizeof(struct)
#
# Macros:
#   _IO(type,nr)        = _IOC(0, type, nr, 0)
#   _IOR(type,nr,size)  = _IOC(2, type, nr, size)   # kernel writes result
#   _IOW(type,nr,size)  = _IOC(1, type, nr, size)   # user writes arg
#   _IOWR(type,nr,size) = _IOC(3, type, nr, size)   # both directions
#
# Linux _IOC encoding (on x86-64):
#   bits 31-30: dir
#   bits 29-16: size
#   bits 15-8:  type (magic)
#   bits 7-0:   nr
# ---------------------------------------------------------------------------

PHANTOM_IOC_MAGIC = ord('P')  # 0x50


def _IOC(direction, magic, nr, size):
    return (direction << 30) | (size << 16) | (magic << 8) | nr


def _IOR(magic, nr, size):
    return _IOC(2, magic, nr, size)


def _IOW(magic, nr, size):
    return _IOC(1, magic, nr, size)


def _IOWR(magic, nr, size):
    return _IOC(3, magic, nr, size)


# Task 3.1: PHANTOM_IOCTL_BOOT_KERNEL = _IOW('P', 22, struct 24 bytes)
# struct phantom_boot_kernel_args: u64+u64+u32+u32 = 24 bytes
BOOT_KERNEL_STRUCT_SIZE = 24
PHANTOM_IOCTL_BOOT_KERNEL = _IOW(PHANTOM_IOC_MAGIC, 22, BOOT_KERNEL_STRUCT_SIZE)

# Task 2.1: PHANTOM_IOCTL_RUN_ITERATION = _IOWR('P', 20, phantom_iter_params)
# struct phantom_iter_params: u32+u32 = 8 bytes
RUN_ITER_STRUCT_SIZE = 8
PHANTOM_IOCTL_RUN_ITERATION = _IOWR(PHANTOM_IOC_MAGIC, 20, RUN_ITER_STRUCT_SIZE)

# Task 3.2: PHANTOM_IOCTL_GET_ITER_STATE = _IO('P', 23)
#
# Uses _IO (not _IOR) because struct phantom_iter_state is ~32KB, which
# overflows the 14-bit size field in the ioctl encoding. The kernel copies
# sizeof(struct phantom_iter_state) bytes to the userspace pointer in arg.
#
# struct phantom_iter_state layout (kernel/interface.h):
#   u64 rax,rbx,rcx,rdx,rsi,rdi,rsp,rbp  = 8 × 8 =  64 bytes  offset 0
#   u64 r8..r15                            = 8 × 8 =  64 bytes  offset 64
#   u64 rip, rflags, cr3                   = 3 × 8 =  24 bytes  offset 128
#   u32 dirty_count, u32 _pad0             = 8 bytes             offset 152
#   u64 dirty_gpas[4096]                   = 32768 bytes         offset 160
#   u8  tss_verified, u8 _pad1[7]          = 8 bytes             offset 32928
#   u64 tss_rsp0_snapshot                  = 8 bytes             offset 32936
#   u64 tss_rsp0_restored                  = 8 bytes             offset 32944
#   u32 run_result, u32 _pad2              = 8 bytes             offset 32952
#   Total: 32960 bytes
DIRTY_LIST_MAX = 4096
# _IO(type, nr) = _IOC(0, type, nr, 0)
PHANTOM_IOCTL_GET_ITER_STATE = _IOC(0, PHANTOM_IOC_MAGIC, 23, 0)

# Struct format: native byte order, no padding inserted by Python (explicit pads)
# 16 GPRs (rax..r15), 3 (rip/rflags/cr3), 2 u32 (dirty_count+pad),
# 4096 u64 (dirty_gpas), 1 u8 (tss_verified), 7 pad bytes,
# 2 u64 (tss_rsp0_*), 2 u32 (run_result+pad)
ITER_STATE_FMT = '=16Q3QII4096QB7xQQII'
ITER_STATE_SIZE = struct.calcsize(ITER_STATE_FMT)
GET_ITER_STATE_STRUCT_SIZE = ITER_STATE_SIZE
assert ITER_STATE_SIZE == 32960, (
    'struct size mismatch: expected 32960, got %d' % ITER_STATE_SIZE)

# GP register names in order (matching struct phantom_iter_state field order)
GP_REGS = ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RSP', 'RBP',
           'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']

# Fixed determinism test input: 4 bytes, same every iteration.
# Use all-zeros so the result is maximally deterministic.
FIXED_INPUT = b'\x00\x00\x00\x00'


def parse_iter_state(raw):
    """Parse raw bytes from PHANTOM_IOCTL_GET_ITER_STATE into a dict.

    Format: =16Q3QII4096QB7xQQII
      fields[0:16]  = rax,rbx,rcx,rdx,rsi,rdi,rsp,rbp,r8..r15
      fields[16:19] = rip, rflags, cr3
      fields[19]    = dirty_count
      fields[20]    = _pad0 (ignored)
      fields[21:21+4096] = dirty_gpas[4096]
      fields[4117]  = tss_verified (u8, packed as int)
      (7 pad bytes skipped by format)
      fields[4118]  = tss_rsp0_snapshot
      fields[4119]  = tss_rsp0_restored
      fields[4120]  = run_result
      fields[4121]  = _pad2 (ignored)
    """
    fields = struct.unpack_from(ITER_STATE_FMT, raw)
    gp_regs     = list(fields[0:16])
    rip         = fields[16]
    rflags      = fields[17]
    cr3         = fields[18]
    dirty_count = fields[19]
    # fields[20] = _pad0
    dirty_gpas  = list(fields[21:21 + dirty_count])
    tss_verified        = bool(fields[4117])
    tss_rsp0_snapshot   = fields[4118]
    tss_rsp0_restored   = fields[4119]
    run_result          = fields[4120]
    return {
        'rip':               rip,
        'rsp':               gp_regs[6],   # RSP is gp_regs[6]
        'rflags':            rflags,
        'cr3':               cr3,
        'gp_regs':           gp_regs,
        'dirty_count':       dirty_count,
        'dirty_gpas':        dirty_gpas,
        'tss_verified':      tss_verified,
        'tss_rsp0_snapshot': tss_rsp0_snapshot,
        'tss_rsp0_restored': tss_rsp0_restored,
        'run_result':        run_result,
    }


def states_equal(a, b):
    """Return (equal, reason) comparing two iter_state dicts."""
    for field in ('rip', 'rsp', 'rflags', 'cr3'):
        if a[field] != b[field]:
            return False, '%s: ref=0x%016x got=0x%016x' % (
                field.upper(), a[field], b[field])
    for i, (ra, rb) in enumerate(zip(a['gp_regs'], b['gp_regs'])):
        if ra != rb:
            return False, '%s: ref=0x%016x got=0x%016x' % (
                GP_REGS[i], ra, rb)
    if a['dirty_count'] != b['dirty_count']:
        return False, 'dirty_count: ref=%d got=%d' % (
            a['dirty_count'], b['dirty_count'])
    for i, (ga, gb) in enumerate(zip(a['dirty_gpas'], b['dirty_gpas'])):
        if ga != gb:
            return False, 'dirty_gpas[%d]: ref=0x%016x got=0x%016x' % (
                i, ga, gb)
    return True, ''


def boot_kernel(fd, bzimage_path, cpu, guest_mem_mb):
    """Call PHANTOM_IOCTL_BOOT_KERNEL. Returns True on success."""
    with open(bzimage_path, 'rb') as f:
        data = f.read()
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    buf_addr = ctypes.addressof(buf)
    args = struct.pack('QQII', buf_addr, len(data), cpu, guest_mem_mb)
    try:
        fcntl.ioctl(fd, PHANTOM_IOCTL_BOOT_KERNEL, bytearray(args))
        return True
    except OSError as e:
        print('ERROR: PHANTOM_IOCTL_BOOT_KERNEL failed: %s' % e,
              file=sys.stderr)
        return False


def run_iteration(fd, payload_len, timeout_ms=1000):
    """Call PHANTOM_IOCTL_RUN_ITERATION. Returns True on success."""
    args = struct.pack('II', payload_len, timeout_ms)
    buf = bytearray(args)
    try:
        fcntl.ioctl(fd, PHANTOM_IOCTL_RUN_ITERATION, buf)
        return True
    except OSError as e:
        print('ERROR: PHANTOM_IOCTL_RUN_ITERATION failed: %s' % e,
              file=sys.stderr)
        return False


def get_iter_state(fd):
    """Call PHANTOM_IOCTL_GET_ITER_STATE. Returns raw bytes or None."""
    buf = bytearray(GET_ITER_STATE_STRUCT_SIZE)
    try:
        fcntl.ioctl(fd, PHANTOM_IOCTL_GET_ITER_STATE, buf)
        return bytes(buf)
    except OSError as e:
        print('ERROR: PHANTOM_IOCTL_GET_ITER_STATE failed: %s' % e,
              file=sys.stderr)
        return None


def inject_payload(fd, payload):
    """
    Write fixed payload into the shared_mem payload area via mmap.

    The shared_mem region is at mmap offset 0x00000.
    First PHANTOM_PAYLOAD_MAX (65536) bytes are payload[].
    Next 4 bytes are payload_len.
    """
    import mmap
    # Map shared_mem region (payload buffer is first 64KB + 4 bytes len)
    PHANTOM_PAYLOAD_MAX = 1 << 16
    region_size = PHANTOM_PAYLOAD_MAX + 4 + 4 + 8  # payload + len + status + crash_addr
    # Round up to page boundary
    page_size = mmap.PAGESIZE
    map_size = ((region_size + page_size - 1) // page_size) * page_size
    try:
        mm = mmap.mmap(fd, map_size, mmap.MAP_SHARED,
                       mmap.PROT_READ | mmap.PROT_WRITE, offset=0)
        mm.seek(0)
        mm.write(payload[:PHANTOM_PAYLOAD_MAX])
        # Write payload_len at offset PHANTOM_PAYLOAD_MAX
        mm.seek(PHANTOM_PAYLOAD_MAX)
        mm.write(struct.pack('I', len(payload)))
        # Do NOT call mm.flush() — phantom maps VM_IO pages which do not
        # support msync; flush() calls msync(MS_SYNC) -> EINVAL.
        mm.close()
        return True
    except OSError as e:
        print('ERROR: mmap shared_mem failed: %s' % e, file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Phantom 1000-run determinism gate')
    parser.add_argument('--bzimage',
                        default='/root/phantom/linux-6.1.90/arch/x86/boot/bzImage',
                        help='Path to guest bzImage')
    parser.add_argument('--iterations', type=int, default=1000,
                        help='Number of iterations (default: 1000)')
    parser.add_argument('--cpu', type=int, default=0,
                        help='Phantom vCPU index (default: 0)')
    parser.add_argument('--guest-mem-mb', type=int, default=256,
                        help='Guest memory in MB (default: 256)')
    parser.add_argument('--skip-boot', action='store_true',
                        help='Skip BOOT_KERNEL ioctl (guest already running)')
    args = parser.parse_args()

    if not os.path.exists('/dev/phantom'):
        print('ERROR: /dev/phantom not found — is phantom.ko loaded?',
              file=sys.stderr)
        return 2

    if not args.skip_boot and not os.path.exists(args.bzimage):
        print('ERROR: bzImage not found: %s' % args.bzimage, file=sys.stderr)
        return 2

    fd = os.open('/dev/phantom', os.O_RDWR)
    try:
        # Boot guest kernel unless caller says it's already running
        if not args.skip_boot:
            print('Booting guest bzImage...')
            if not boot_kernel(fd, args.bzimage, args.cpu,
                               args.guest_mem_mb):
                return 2
            # Brief wait for guest to reach harness init
            time.sleep(2.0)

        # Inject fixed payload into shared_mem
        if not inject_payload(fd, FIXED_INPUT):
            return 2

        reference = None
        fail_count = 0
        first_fail_iter = None
        first_fail_reason = None

        print('Running %d iterations...' % args.iterations)
        t0 = time.time()

        for i in range(1, args.iterations + 1):
            if not run_iteration(fd, len(FIXED_INPUT)):
                return 2

            raw = get_iter_state(fd)
            if raw is None:
                return 2

            state = parse_iter_state(raw)

            if i == 1:
                reference = state
                print('  iter 1: reference state captured '
                      '(RIP=0x%016x dirty=%d)' % (
                          state['rip'], state['dirty_count']))
                continue

            equal, reason = states_equal(reference, state)
            if not equal:
                fail_count += 1
                if first_fail_iter is None:
                    first_fail_iter = i
                    first_fail_reason = reason
                    print('  DIVERGE at iter %d: %s' % (i, reason))

            if i % 100 == 0:
                elapsed = time.time() - t0
                rate = i / elapsed
                print('  iter %d/%d (%.0f iter/s, %d diverge)' % (
                    i, args.iterations, rate, fail_count))

        elapsed = time.time() - t0
        print('')
        print('Completed %d iterations in %.1fs (%.0f iter/s)' % (
            args.iterations, elapsed, args.iterations / elapsed))
        print('')

        if fail_count == 0:
            print('PASS: %d/%d identical — determinism gate PASSED' % (
                args.iterations, args.iterations))
            return 0
        else:
            print('FAIL: %d/%d diverged' % (fail_count, args.iterations - 1))
            print('  First divergence at iteration %d: %s' % (
                first_fail_iter, first_fail_reason))
            print('')
            print('Possible causes:')
            print('  - TSC not zeroed at snapshot point (check VMCS TSC_OFFSET)')
            print('  - APIC timer not suppressed (check LVTT mask in VMCS)')
            print('  - External interrupt injected into guest (check exit reason 1)')
            print('  - RNG source active (check defconfig RANDOM_TRUST_* flags)')
            print('  - RDRAND/RDSEED not masked in CPUID emulator')
            print('  - Slab freelist randomisation still enabled')
            return 1

    finally:
        os.close(fd)


if __name__ == '__main__':
    sys.exit(main())
