#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
phantom_bridge.py -- kAFL-compatible frontend for Phantom hypervisor fuzzer.

Translates kAFL's fuzzing loop into Phantom PHANTOM_RUN_ITERATION ioctls.
The bridge:
  1. Opens /dev/phantom
  2. Calls PHANTOM_CREATE_VM
  3. Calls PHANTOM_SET_SNAPSHOT
  4. Enters fuzzing loop:
     - Writes payload into shared memory or passes via ioctl
     - Calls PHANTOM_RUN_ITERATION
     - Reads result (PHANTOM_RESULT_OK / CRASH / KASAN / TIMEOUT / PANIC)
     - Saves crashes if requested
  5. Prints stats on exit

kAFL ABI mapping:
  HYPERCALL_KAFL_GET_PAYLOAD (0x11a) -> payload written to shared_mem before RUN_ITERATION
  HYPERCALL_KAFL_ACQUIRE     (0x11c) -> PHANTOM_SET_SNAPSHOT
  HYPERCALL_KAFL_RELEASE     (0x11d) -> iteration end (RUN_ITERATION returns)
  HYPERCALL_KAFL_PANIC       (0x11e) -> result == PHANTOM_RESULT_CRASH/PANIC
  HYPERCALL_KAFL_KASAN       (0x11f) -> result == PHANTOM_RESULT_KASAN
"""

import argparse
import mmap
import os
import random
import signal
import struct
import sys
import time

from phantom_ioctl import (
    PHANTOM_MMAP_BITMAP,
    PHANTOM_MMAP_PAYLOAD,
    PHANTOM_PAYLOAD_MAX,
    PHANTOM_RESULT_CRASH,
    PHANTOM_RESULT_KASAN,
    PHANTOM_RESULT_OK,
    PHANTOM_RESULT_PANIC,
    PHANTOM_RESULT_TIMEOUT,
    phantom_close,
    phantom_create_vm,
    phantom_destroy_vm,
    phantom_get_status,
    phantom_get_version,
    phantom_open,
    phantom_run_guest,
    phantom_run_iteration,
    phantom_set_snapshot,
    result_name,
)

# Global flag for graceful shutdown
_running = True


def _signal_handler(signum, frame):
    global _running
    _running = False


def load_corpus_file(corpus_dir):
    """Load a random file from the corpus directory."""
    files = [f for f in os.listdir(corpus_dir)
             if os.path.isfile(os.path.join(corpus_dir, f))]
    if not files:
        return os.urandom(64)
    path = os.path.join(corpus_dir, random.choice(files))
    with open(path, "rb") as f:
        data = f.read(PHANTOM_PAYLOAD_MAX)
    return data


def save_crash(crash_dir, payload, result_code, crash_addr, iteration):
    """Save a crashing payload to disk."""
    os.makedirs(crash_dir, exist_ok=True)
    name = "crash_%s_%06d_%016x" % (result_name(result_code).lower(),
                                     iteration, crash_addr)
    path = os.path.join(crash_dir, name)
    with open(path, "wb") as f:
        f.write(payload)
    return path


def run(args):
    """Main fuzzing loop."""
    global _running

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Open device
    fd = phantom_open(args.device)

    # Check version
    version = phantom_get_version(fd)
    print("phantom: version 0x%08x" % version)

    # Create VM
    instance_id = phantom_create_vm(
        fd,
        pinned_cpu=args.cpu,
        cow_pool_pages=args.cow_pool_pages,
        guest_mem_mb=args.guest_mem_mb,
    )
    print("phantom: created VM instance %d on CPU %d" % (instance_id, args.cpu))

    # Run kAFL harness guest to ACQUIRE point (test_id=8).
    # This boots the built-in guest and runs it until it calls
    # HYPERCALL_KAFL_ACQUIRE, which sets snap_acquired=true.
    result, exit_reason = phantom_run_guest(fd, cpu=args.cpu, test_id=8)
    print("phantom: kAFL harness guest reached ACQUIRE "
          "(result=%d, exit_reason=%d)" % (result, exit_reason))

    # Set snapshot (captures state at the ACQUIRE point)
    phantom_set_snapshot(fd)
    print("phantom: snapshot taken")

    # Optionally mmap the coverage bitmap (read-only)
    bitmap = None
    if args.mmap_bitmap:
        try:
            bitmap = mmap.mmap(fd, 64 * 1024,
                               offset=PHANTOM_MMAP_BITMAP,
                               prot=mmap.PROT_READ,
                               flags=mmap.MAP_SHARED)
            print("phantom: bitmap mmap'd at offset 0x%x" % PHANTOM_MMAP_BITMAP)
        except OSError as e:
            print("phantom: bitmap mmap failed: %s (continuing without)" % e)

    # Fuzzing loop
    iterations = 0
    crashes = 0
    kasan_hits = 0
    timeouts = 0
    t_start = time.monotonic()

    print("phantom: starting fuzzing loop (max %d iterations)" % args.max_iterations)

    while _running and iterations < args.max_iterations:
        # Get or generate payload
        if args.corpus_dir:
            payload = load_corpus_file(args.corpus_dir)
        else:
            payload = os.urandom(args.payload_size)

        # Run one iteration
        result, exit_reason, checksum = phantom_run_iteration(
            fd, payload, timeout_ms=args.timeout_ms)

        # Handle result
        if result == PHANTOM_RESULT_CRASH or result == PHANTOM_RESULT_PANIC:
            crashes += 1
            if args.crash_dir:
                status = phantom_get_status(fd)
                path = save_crash(args.crash_dir, payload, result,
                                  status.crash_addr, iterations)
                if args.verbose:
                    print("  [%d] CRASH: %s saved to %s" % (
                        iterations, result_name(result), path))
        elif result == PHANTOM_RESULT_KASAN:
            kasan_hits += 1
            if args.crash_dir:
                status = phantom_get_status(fd)
                path = save_crash(args.crash_dir, payload, result,
                                  status.crash_addr, iterations)
                if args.verbose:
                    print("  [%d] KASAN: saved to %s" % (iterations, path))
        elif result == PHANTOM_RESULT_TIMEOUT:
            timeouts += 1
            if args.verbose:
                print("  [%d] TIMEOUT" % iterations)

        iterations += 1

        # Periodic stats
        if args.stats_interval and iterations % args.stats_interval == 0:
            elapsed = time.monotonic() - t_start
            exec_per_sec = iterations / elapsed if elapsed > 0 else 0
            print("  [%d] %.0f exec/sec | %d crashes | %d kasan | %d timeouts" % (
                iterations, exec_per_sec, crashes, kasan_hits, timeouts))

    # Final stats
    elapsed = time.monotonic() - t_start
    exec_per_sec = iterations / elapsed if elapsed > 0 else 0
    print("\n--- phantom-bridge stats ---")
    print("iterations: %d" % iterations)
    print("exec/sec:   %.1f" % exec_per_sec)
    print("crashes:    %d" % crashes)
    print("kasan:      %d" % kasan_hits)
    print("timeouts:   %d" % timeouts)
    print("elapsed:    %.2fs" % elapsed)

    # Cleanup
    if bitmap:
        bitmap.close()
    phantom_destroy_vm(fd)
    phantom_close(fd)

    return 0 if iterations == args.max_iterations else 1


def main():
    parser = argparse.ArgumentParser(
        description="kAFL-compatible frontend for Phantom hypervisor fuzzer")

    parser.add_argument("--device", default="/dev/phantom",
                        help="path to phantom chardev (default: /dev/phantom)")
    parser.add_argument("--cpu", type=int, default=0,
                        help="CPU to pin VM instance to (default: 0)")
    parser.add_argument("--max-iterations", type=int, default=1000,
                        help="max fuzzing iterations (default: 1000)")
    parser.add_argument("--payload-size", type=int, default=256,
                        help="random payload size in bytes (default: 256)")
    parser.add_argument("--timeout-ms", type=int, default=1000,
                        help="per-iteration timeout in ms (default: 1000)")
    parser.add_argument("--corpus-dir",
                        help="directory with seed corpus files")
    parser.add_argument("--crash-dir", default="./crashes",
                        help="directory to save crash inputs (default: ./crashes)")
    parser.add_argument("--cow-pool-pages", type=int, default=0,
                        help="CoW pool size in pages (0 = module default)")
    parser.add_argument("--guest-mem-mb", type=int, default=0,
                        help="guest memory in MB (0 = module default)")
    parser.add_argument("--mmap-bitmap", action="store_true",
                        help="mmap the coverage bitmap (requires PT support)")
    parser.add_argument("--stats-interval", type=int, default=1000,
                        help="print stats every N iterations (default: 1000)")
    parser.add_argument("--verbose", action="store_true",
                        help="print per-crash/kasan/timeout messages")

    args = parser.parse_args()

    if args.payload_size > PHANTOM_PAYLOAD_MAX:
        print("error: payload-size exceeds maximum (%d)" % PHANTOM_PAYLOAD_MAX,
              file=sys.stderr)
        sys.exit(1)

    sys.exit(run(args))


if __name__ == "__main__":
    main()
