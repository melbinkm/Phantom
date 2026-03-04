#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
phantom_ioctl.py -- ctypes ioctl wrappers for /dev/phantom.

Mirrors the structs and ioctl command numbers from kernel/interface.h.
Uses fcntl.ioctl() for all kernel communication.
"""

import ctypes
import fcntl
import os
import struct

# ---------------------------------------------------------------------------
# ioctl direction/encoding helpers (mirrors linux/ioctl.h)
# ---------------------------------------------------------------------------

_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_DIRBITS = 2

_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS        # 8
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS     # 16
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS      # 30

_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2


def _IOC(direction, type_byte, nr, size):
    return ((direction << _IOC_DIRSHIFT) |
            (type_byte << _IOC_TYPESHIFT) |
            (nr << _IOC_NRSHIFT) |
            (size << _IOC_SIZESHIFT))


def _IO(type_byte, nr):
    return _IOC(_IOC_NONE, type_byte, nr, 0)


def _IOR(type_byte, nr, size):
    return _IOC(_IOC_READ, type_byte, nr, size)


def _IOW(type_byte, nr, size):
    return _IOC(_IOC_WRITE, type_byte, nr, size)


def _IOWR(type_byte, nr, size):
    return _IOC(_IOC_READ | _IOC_WRITE, type_byte, nr, size)


# ---------------------------------------------------------------------------
# Constants from kernel/interface.h
# ---------------------------------------------------------------------------

PHANTOM_IOC_MAGIC = ord('P')  # 0x50
PHANTOM_VERSION = 0x00020300

PHANTOM_PAYLOAD_MAX = 1 << 16  # 64KB

# Result codes from kernel/phantom.h
PHANTOM_RESULT_OK = 0
PHANTOM_RESULT_CRASH = 1
PHANTOM_RESULT_TIMEOUT = 2
PHANTOM_RESULT_KASAN = 3
PHANTOM_RESULT_PANIC = 4
PHANTOM_RESULT_HYPERCALL_ERROR = 5

RESULT_NAMES = {
    PHANTOM_RESULT_OK: "OK",
    PHANTOM_RESULT_CRASH: "CRASH",
    PHANTOM_RESULT_TIMEOUT: "TIMEOUT",
    PHANTOM_RESULT_KASAN: "KASAN",
    PHANTOM_RESULT_PANIC: "PANIC",
    PHANTOM_RESULT_HYPERCALL_ERROR: "HYPERCALL_ERROR",
}

# mmap offsets
PHANTOM_MMAP_PAYLOAD = 0x00000
PHANTOM_MMAP_BITMAP = 0x10000
PHANTOM_MMAP_TOPA_BUF_A = 0x20000
PHANTOM_MMAP_TOPA_BUF_B = 0x30000
PHANTOM_MMAP_STATUS = 0x40000

# kAFL hypercall numbers (for reference / documentation)
HYPERCALL_KAFL_GET_PAYLOAD = 0x11a
HYPERCALL_KAFL_SUBMIT_CR3 = 0x11b
HYPERCALL_KAFL_ACQUIRE = 0x11c
HYPERCALL_KAFL_RELEASE = 0x11d
HYPERCALL_KAFL_PANIC = 0x11e
HYPERCALL_KAFL_KASAN = 0x11f
HYPERCALL_KAFL_PRINTF = 0x120
HYPERCALL_KAFL_SUBMIT_PANIC = 0x121


# ---------------------------------------------------------------------------
# Structs (ctypes mirrors of kernel/interface.h)
# ---------------------------------------------------------------------------

class PhantomCreateArgs(ctypes.Structure):
    """struct phantom_create_args -- PHANTOM_CREATE_VM arguments."""
    _fields_ = [
        ("pinned_cpu",     ctypes.c_uint32),
        ("cow_pool_pages", ctypes.c_uint32),
        ("topa_size_mb",   ctypes.c_uint32),
        ("guest_mem_mb",   ctypes.c_uint32),
        ("instance_id",    ctypes.c_uint32),  # OUT
        ("_pad",           ctypes.c_uint32),
    ]


class PhantomLoadArgs(ctypes.Structure):
    """struct phantom_load_args -- PHANTOM_LOAD_TARGET arguments."""
    _fields_ = [
        ("gpa",            ctypes.c_uint64),
        ("userspace_ptr",  ctypes.c_uint64),
        ("size",           ctypes.c_uint64),
    ]


class PhantomRunArgs2(ctypes.Structure):
    """struct phantom_run_args2 -- PHANTOM_RUN_ITERATION arguments."""
    _fields_ = [
        ("payload_ptr",    ctypes.c_uint64),  # IN
        ("payload_size",   ctypes.c_uint32),  # IN
        ("timeout_ms",     ctypes.c_uint32),  # IN
        ("result",         ctypes.c_uint32),  # OUT
        ("exit_reason",    ctypes.c_uint32),  # OUT
        ("checksum",       ctypes.c_uint64),  # OUT
    ]


class PhantomStatus(ctypes.Structure):
    """struct phantom_status -- PHANTOM_GET_STATUS result."""
    _fields_ = [
        ("result",         ctypes.c_uint32),
        ("exit_reason",    ctypes.c_uint32),
        ("crash_addr",     ctypes.c_uint64),
        ("checksum",       ctypes.c_uint64),
        ("iterations",     ctypes.c_uint64),
    ]


class PhantomRunArgsLegacy(ctypes.Structure):
    """struct phantom_run_args -- legacy RUN_GUEST (task 1.2 API)."""
    _fields_ = [
        ("cpu",            ctypes.c_uint32),  # IN: CPU index
        ("reserved",       ctypes.c_uint32),  # IN: test_id
        ("result",         ctypes.c_uint64),  # OUT: checksum
        ("exit_reason",    ctypes.c_uint32),  # OUT: VM exit reason
        ("padding",        ctypes.c_uint32),
    ]


class PhantomIterParams(ctypes.Structure):
    """struct phantom_iter_params -- legacy RUN_ITERATION (task 2.1 API)."""
    _fields_ = [
        ("payload_len",    ctypes.c_uint32),
        ("timeout_ms",     ctypes.c_uint32),
    ]


class PhantomIterResult(ctypes.Structure):
    """struct phantom_iter_result -- legacy GET_RESULT (task 2.1 API)."""
    _fields_ = [
        ("status",         ctypes.c_uint32),
        ("_pad",           ctypes.c_uint32),
        ("crash_addr",     ctypes.c_uint64),
    ]


class PhantomPerfResult(ctypes.Structure):
    """struct phantom_perf_result -- PERF_RESTORE_LATENCY result."""
    _fields_ = [
        ("dirty_page_count",  ctypes.c_uint64),
        ("dirty_walk_cycles", ctypes.c_uint64),
        ("invept_cycles",     ctypes.c_uint64),
        ("vmcs_cycles",       ctypes.c_uint64),
        ("xrstor_cycles",     ctypes.c_uint64),
        ("total_cycles",      ctypes.c_uint64),
    ]


class PhantomSharedMem(ctypes.Structure):
    """struct phantom_shared_mem -- mmap'd shared memory region."""
    _fields_ = [
        ("payload",        ctypes.c_uint8 * PHANTOM_PAYLOAD_MAX),
        ("payload_len",    ctypes.c_uint32),
        ("status",         ctypes.c_uint32),
        ("crash_addr",     ctypes.c_uint64),
    ]


# ---------------------------------------------------------------------------
# ioctl command numbers -- task 2.3 production API (nr >= 0x30)
# ---------------------------------------------------------------------------

PHANTOM_CREATE_VM = _IOWR(
    PHANTOM_IOC_MAGIC, 0x30, ctypes.sizeof(PhantomCreateArgs))
PHANTOM_LOAD_TARGET = _IOW(
    PHANTOM_IOC_MAGIC, 0x31, ctypes.sizeof(PhantomLoadArgs))
PHANTOM_SET_SNAPSHOT = _IO(
    PHANTOM_IOC_MAGIC, 0x32)
PHANTOM_RUN_ITERATION_CMD = _IOWR(
    PHANTOM_IOC_MAGIC, 0x33, ctypes.sizeof(PhantomRunArgs2))
PHANTOM_GET_STATUS_CMD = _IOR(
    PHANTOM_IOC_MAGIC, 0x34, ctypes.sizeof(PhantomStatus))
PHANTOM_DESTROY_VM = _IO(
    PHANTOM_IOC_MAGIC, 0x35)

# Legacy ioctl command numbers (tasks 1.x / 2.1 / 2.2)
PHANTOM_IOCTL_GET_VERSION = _IOR(PHANTOM_IOC_MAGIC, 0, 4)
PHANTOM_IOCTL_RUN_GUEST = _IOWR(
    PHANTOM_IOC_MAGIC, 1, ctypes.sizeof(PhantomRunArgsLegacy))
PHANTOM_IOCTL_RUN_ITERATION = _IOWR(
    PHANTOM_IOC_MAGIC, 20, ctypes.sizeof(PhantomIterParams))
PHANTOM_IOCTL_GET_RESULT = _IOR(
    PHANTOM_IOC_MAGIC, 21, ctypes.sizeof(PhantomIterResult))
PHANTOM_IOCTL_SNAPSHOT_CREATE = _IO(PHANTOM_IOC_MAGIC, 9)
PHANTOM_IOCTL_SNAPSHOT_RESTORE = _IO(PHANTOM_IOC_MAGIC, 10)
PHANTOM_IOCTL_PT_GET_EVENTFD = _IO(PHANTOM_IOC_MAGIC, 13)
PHANTOM_IOCTL_PERF_RESTORE_LATENCY = _IOR(
    PHANTOM_IOC_MAGIC, 12, ctypes.sizeof(PhantomPerfResult))


# ---------------------------------------------------------------------------
# High-level ioctl wrappers
# ---------------------------------------------------------------------------

def phantom_open(path="/dev/phantom"):
    """Open /dev/phantom and return the file descriptor."""
    return os.open(path, os.O_RDWR)


def phantom_close(fd):
    """Close the /dev/phantom file descriptor."""
    os.close(fd)


def phantom_get_version(fd):
    """Return the PHANTOM_VERSION u32 from the kernel module."""
    buf = ctypes.c_uint32(0)
    fcntl.ioctl(fd, PHANTOM_IOCTL_GET_VERSION, buf)
    return buf.value


def phantom_run_guest(fd, cpu=0, test_id=0):
    """
    Legacy RUN_GUEST ioctl -- run the built-in guest with given test_id.

    test_id=8 runs the kAFL harness guest to the ACQUIRE point.
    Returns (result, exit_reason).
    """
    args = PhantomRunArgsLegacy(cpu=cpu, reserved=test_id)
    fcntl.ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, args)
    return args.result, args.exit_reason


def phantom_create_vm(fd, pinned_cpu=0, cow_pool_pages=0,
                      topa_size_mb=0, guest_mem_mb=0):
    """Create a Phantom VM instance. Returns the instance_id."""
    args = PhantomCreateArgs(
        pinned_cpu=pinned_cpu,
        cow_pool_pages=cow_pool_pages,
        topa_size_mb=topa_size_mb,
        guest_mem_mb=guest_mem_mb,
    )
    fcntl.ioctl(fd, PHANTOM_CREATE_VM, args)
    return args.instance_id


def phantom_load_target(fd, gpa, data):
    """Load target binary data at the given GPA."""
    buf = ctypes.create_string_buffer(data)
    args = PhantomLoadArgs(
        gpa=gpa,
        userspace_ptr=ctypes.addressof(buf),
        size=len(data),
    )
    fcntl.ioctl(fd, PHANTOM_LOAD_TARGET, args)


def phantom_set_snapshot(fd):
    """Take a snapshot of the current guest state."""
    fcntl.ioctl(fd, PHANTOM_SET_SNAPSHOT)


def phantom_run_iteration(fd, payload, timeout_ms=1000):
    """
    Run one fuzzing iteration with the given payload.

    The payload is passed via a ctypes buffer pointer in PhantomRunArgs2.
    Returns (result, exit_reason, checksum).
    """
    payload_bytes = bytes(payload)
    size = min(len(payload_bytes), PHANTOM_PAYLOAD_MAX)
    buf = ctypes.create_string_buffer(payload_bytes[:size])
    args = PhantomRunArgs2(
        payload_ptr=ctypes.addressof(buf),
        payload_size=size,
        timeout_ms=timeout_ms,
    )
    fcntl.ioctl(fd, PHANTOM_RUN_ITERATION_CMD, args)
    return args.result, args.exit_reason, args.checksum


def phantom_get_status(fd):
    """
    Retrieve status from the last iteration.
    Returns a PhantomStatus instance.
    """
    status = PhantomStatus()
    fcntl.ioctl(fd, PHANTOM_GET_STATUS_CMD, status)
    return status


def phantom_destroy_vm(fd):
    """Destroy the current VM instance."""
    fcntl.ioctl(fd, PHANTOM_DESTROY_VM)


def result_name(code):
    """Return a human-readable name for a PHANTOM_RESULT_* code."""
    return RESULT_NAMES.get(code, "UNKNOWN(%d)" % code)
