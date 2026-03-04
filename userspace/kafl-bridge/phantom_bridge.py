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
import multiprocessing
import os
import queue
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


def run_core(core_id, max_iterations, payload_size, timeout_ms,
             stats_interval, corpus_dir, crash_dir, mmap_bitmap,
             result_queue, device="/dev/phantom"):
    """Single-core fuzzing loop -- runs in a subprocess.

    Opens /dev/phantom independently, creates a VM pinned to core_id,
    runs the fuzzing loop, and puts a result dict into result_queue.
    """
    import signal as _signal
    running = [True]

    def _handler(signum, frame):
        running[0] = False

    _signal.signal(_signal.SIGINT, _handler)
    _signal.signal(_signal.SIGTERM, _handler)

    try:
        from phantom_ioctl import (
            PHANTOM_MMAP_BITMAP,
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

        fd = phantom_open(device)
        phantom_create_vm(fd, pinned_cpu=core_id)

        phantom_run_guest(fd, cpu=core_id, test_id=8)
        phantom_set_snapshot(fd)

        bitmap = None
        if mmap_bitmap:
            try:
                bitmap = mmap.mmap(fd, 64 * 1024,
                                   offset=PHANTOM_MMAP_BITMAP,
                                   prot=mmap.PROT_READ,
                                   flags=mmap.MAP_SHARED)
            except OSError:
                pass

        iterations = 0
        crashes = 0
        kasan_hits = 0
        timeouts = 0
        t_start = time.monotonic()

        while running[0] and iterations < max_iterations:
            if corpus_dir:
                payload = load_corpus_file(corpus_dir)
            else:
                payload = os.urandom(payload_size)

            result, exit_reason, checksum = phantom_run_iteration(
                fd, payload, timeout_ms=timeout_ms)

            if result in (PHANTOM_RESULT_CRASH, PHANTOM_RESULT_PANIC):
                crashes += 1
                if crash_dir:
                    status = phantom_get_status(fd)
                    save_crash(crash_dir, payload, result,
                               status.crash_addr, iterations)
            elif result == PHANTOM_RESULT_KASAN:
                kasan_hits += 1
                if crash_dir:
                    status = phantom_get_status(fd)
                    save_crash(crash_dir, payload, result,
                               status.crash_addr, iterations)
            elif result == PHANTOM_RESULT_TIMEOUT:
                timeouts += 1

            iterations += 1

            if stats_interval and iterations % stats_interval == 0:
                elapsed = time.monotonic() - t_start
                exec_per_sec = iterations / elapsed if elapsed > 0 else 0
                sys.stderr.write(
                    "  [core %d][%d] %.0f exec/sec | %d crashes | "
                    "%d kasan | %d timeouts\n" % (
                        core_id, iterations, exec_per_sec,
                        crashes, kasan_hits, timeouts))
                sys.stderr.flush()

        elapsed = time.monotonic() - t_start
        exec_per_sec = iterations / elapsed if elapsed > 0 else 0

        if bitmap:
            bitmap.close()
        phantom_destroy_vm(fd)
        phantom_close(fd)

        result_queue.put({
            "core": core_id,
            "iterations": iterations,
            "exec_sec": exec_per_sec,
            "elapsed": elapsed,
            "crashes": crashes,
            "kasan": kasan_hits,
            "timeouts": timeouts,
        })
    except Exception as exc:
        result_queue.put({
            "core": core_id,
            "error": str(exc),
            "iterations": 0,
            "exec_sec": 0.0,
            "elapsed": 0.0,
            "crashes": 0,
            "kasan": 0,
            "timeouts": 0,
        })


def _get_active_cores():
    """
    Read /sys/module/phantom/parameters/phantom_cores to get the
    comma-separated list of active CPU IDs.

    Returns a list of ints, or None if the sysfs file is not readable
    (e.g. older kernel module that does not export it).
    """
    sysfs = "/sys/module/phantom/parameters/phantom_cores"
    try:
        with open(sysfs) as f:
            raw = f.read().strip()
        if not raw:
            return None
        return [int(x.strip()) for x in raw.split(",") if x.strip()]
    except (IOError, OSError, ValueError):
        return None


def run_multi(args, cores):
    """Spawn one subprocess per core and aggregate results."""
    global _running

    # Check which cores the kernel actually activated.
    active = _get_active_cores()
    if active is not None:
        missing = [c for c in cores if c not in active]
        if missing:
            print("phantom-bridge: WARNING: cores %s not active in kernel "
                  "(phantom_cores=%s); skipping them" % (missing, active),
                  file=sys.stderr)
            cores = [c for c in cores if c in active]
            if not cores:
                print("phantom-bridge: ERROR: no requested cores are active",
                      file=sys.stderr)
                return 1

    result_queue = multiprocessing.Queue()
    iters_per_core = max(1, args.max_iterations // len(cores))

    # Setup timeout: each core gets 30s to complete CREATE_VM + snapshot.
    # If it hangs (kernel core not active), we SIGKILL the subprocess — this
    # force-closes the /dev/phantom fd, unblocking the kernel ioctl.
    setup_timeout_s = 30
    # Iteration timeout: rough upper bound — iters_per_core * timeout_ms + margin
    iter_timeout_s = (iters_per_core * args.timeout_ms) / 1000.0 + 30

    processes = []
    for core_id in cores:
        p = multiprocessing.Process(
            target=run_core,
            args=(core_id, iters_per_core, args.payload_size,
                  args.timeout_ms, args.stats_interval,
                  args.corpus_dir, args.crash_dir, args.mmap_bitmap,
                  result_queue, args.device),
            daemon=True,
        )
        p.start()
        processes.append(p)

    # Wait for all cores to finish, with a per-process kill timeout.
    total_timeout_s = setup_timeout_s + iter_timeout_s
    for p in processes:
        p.join(timeout=total_timeout_s)
        if p.is_alive():
            # Subprocess is stuck (likely in a blocking ioctl on an inactive
            # core).  SIGKILL it — the OS will close its FDs and unblock the
            # kernel.
            print("phantom-bridge: core subprocess pid=%d timed out, killing"
                  % p.pid, file=sys.stderr)
            p.kill()
            p.join(timeout=5)

    # Collect results
    results = []
    while True:
        try:
            results.append(result_queue.get_nowait())
        except Exception:
            break

    # Print aggregate stats
    total_iters = sum(r.get("iterations", 0) for r in results)
    total_crashes = sum(r.get("crashes", 0) for r in results)
    total_kasan = sum(r.get("kasan", 0) for r in results)
    total_timeouts = sum(r.get("timeouts", 0) for r in results)
    total_exec_sec = sum(r.get("exec_sec", 0) for r in results)

    print("\n--- phantom-bridge multi-core stats ---")
    for r in sorted(results, key=lambda x: x.get("core", 0)):
        if "error" in r:
            print("core %d: ERROR: %s" % (r["core"], r["error"]))
        else:
            print("core %d: %.1f exec/sec | %d iters | "
                  "%d crashes | %d kasan | %d timeouts" % (
                      r["core"], r["exec_sec"], r["iterations"],
                      r["crashes"], r["kasan"], r["timeouts"]))
    print("total:  %.1f exec/sec (aggregate) | %d iters" % (
        total_exec_sec, total_iters))
    print("crashes:    %d" % total_crashes)
    print("kasan:      %d" % total_kasan)
    print("timeouts:   %d" % total_timeouts)

    return 0


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
    cpu = args.cores[0] if args.cores else args.cpu
    instance_id = phantom_create_vm(
        fd,
        pinned_cpu=cpu,
        cow_pool_pages=args.cow_pool_pages,
        guest_mem_mb=args.guest_mem_mb,
    )
    print("phantom: created VM instance %d on CPU %d" % (instance_id, cpu))

    # Run kAFL harness guest to ACQUIRE point (test_id=8).
    # This boots the built-in guest and runs it until it calls
    # HYPERCALL_KAFL_ACQUIRE, which sets snap_acquired=true.
    result, exit_reason = phantom_run_guest(fd, cpu=cpu, test_id=8)
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


def _parse_cores(value):
    """Parse --cores argument: comma-separated list of CPU IDs."""
    try:
        ids = [int(x.strip()) for x in value.split(",") if x.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError(
            "--cores must be comma-separated integers, e.g. '0,1,2,3'")
    if not ids:
        raise argparse.ArgumentTypeError("--cores must not be empty")
    return ids


def main():
    parser = argparse.ArgumentParser(
        description="kAFL-compatible frontend for Phantom hypervisor fuzzer")

    parser.add_argument("--device", default="/dev/phantom",
                        help="path to phantom chardev (default: /dev/phantom)")
    parser.add_argument("--cpu", type=int, default=0,
                        help="CPU for single-core mode (default: 0); "
                             "overridden by --cores")
    parser.add_argument("--cores", type=_parse_cores, default=None,
                        metavar="ID[,ID,...]",
                        help="comma-separated list of CPU IDs to run in "
                             "parallel (e.g. 0,1,2,3); spawns one "
                             "subprocess per core")
    parser.add_argument("--max-iterations", type=int, default=1000,
                        help="max fuzzing iterations total (default: 1000)")
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

    # Multi-core mode: spawn one subprocess per core
    if args.cores and len(args.cores) > 1:
        sys.exit(run_multi(args, args.cores))

    # Single-core mode (default or --cores with one entry)
    sys.exit(run(args))


if __name__ == "__main__":
    main()
