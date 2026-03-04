#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
fuzz.py — Phantom libxml2 2.9.4 mutation fuzzer.

Opens /dev/phantom, loads guest/libxml2_harness.bin.flat at GPA 0x1000,
takes a snapshot, then runs a mutation loop for --duration seconds.

Crashes are saved to ./crashes/ with the triggering input.

Usage:
    python3 fuzz.py [--duration 3600] [--cpu 0] [--timeout-ms 1000]
                    [--harness PATH] [--crash-dir PATH]
"""

import argparse
import ctypes
import os
import random
import struct
import sys
import time

# ---------------------------------------------------------------------------
# Locate and import phantom_ioctl from sibling directory
# ---------------------------------------------------------------------------

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_KAFL_BRIDGE = os.path.join(_SCRIPT_DIR, "..", "kafl-bridge")
sys.path.insert(0, _KAFL_BRIDGE)

from phantom_ioctl import (
    phantom_open,
    phantom_close,
    phantom_create_vm,
    phantom_load_target,
    phantom_set_snapshot,
    phantom_run_iteration,
    phantom_run_guest,
    phantom_destroy_vm,
    result_name,
    PHANTOM_RESULT_OK,
    PHANTOM_RESULT_CRASH,
    PHANTOM_RESULT_PANIC,
    PHANTOM_RESULT_KASAN,
    PHANTOM_RESULT_TIMEOUT,
    PHANTOM_PAYLOAD_MAX,
)

# ---------------------------------------------------------------------------
# Payload GPA layout (must match libxml2_harness.c)
# ---------------------------------------------------------------------------

# Memory layout for libxml2 harness:
#   0x010000  trampoline (4KB stub: jmp 0x400000) — avoids page tables at 0x13000
#   0x400000  harness flat binary (~1.4MB)
#   0x600000  inject buffer (PAYLOAD_GPA, 64KB): [uint32_t len][XML data]
PAYLOAD_GPA      = 0x600000
TARGET_GPA       = 0x10000   # GUEST_CODE_GPA, where VMCS RIP starts
HARNESS_LOAD_GPA = 0x400000  # where libxml2_harness.bin.flat is mapped

# The harness reads len from PAYLOAD_GPA + PAYLOAD_MAX (uint32_t).
# phantom_run_iteration writes the payload blob; we append the length word
# in the 4 bytes immediately after the 64KB payload area so the guest sees it.

# ---------------------------------------------------------------------------
# Seed corpus — minimal XML inputs
# ---------------------------------------------------------------------------

SEEDS = [
    b"<a/>",
    b"<?xml version=\"1.0\"?><root/>",
    b"<!DOCTYPE x []><x/>",
    b"<root><child attr=\"val\">text</child></root>",
    b"<a b=\"&amp;\"/>",
    b"<!-- comment --><a/>",
    b"<![CDATA[hello]]>",
    b"<r xmlns=\"http://example.org\"/>",
    b"<a><b><c><d/></c></b></a>",
]

# Interesting byte values for mutation
_INTERESTING_BYTES = [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff,
                      ord('<'), ord('>'), ord('"'), ord('\''),
                      ord('&'), ord(';'), ord('/'), ord('?'), ord('!')]

_XML_TOKENS = [
    b"<?xml version=\"1.0\"?>",
    b"<!DOCTYPE",
    b"<!ENTITY",
    b"<![CDATA[",
    b"]]>",
    b"&amp;",
    b"&lt;",
    b"&gt;",
    b"&quot;",
    b"&#x0;",
    b"<!-- -->",
]

# ---------------------------------------------------------------------------
# Mutation engine
# ---------------------------------------------------------------------------

def _mutate(data: bytes) -> bytes:
    """Apply one random mutation to data. Returns mutated bytes."""
    if not data:
        data = b"<a/>"

    choice = random.randint(0, 7)

    if choice == 0:
        # Bit flip
        buf = bytearray(data)
        idx = random.randrange(len(buf))
        buf[idx] ^= (1 << random.randint(0, 7))
        return bytes(buf)

    elif choice == 1:
        # Byte replace with interesting value
        buf = bytearray(data)
        idx = random.randrange(len(buf))
        buf[idx] = random.choice(_INTERESTING_BYTES)
        return bytes(buf)

    elif choice == 2:
        # Byte insertion
        idx = random.randrange(len(data) + 1)
        ins = bytes([random.choice(_INTERESTING_BYTES)])
        return data[:idx] + ins + data[idx:]

    elif choice == 3:
        # Byte deletion
        if len(data) <= 1:
            return data
        idx = random.randrange(len(data))
        return data[:idx] + data[idx + 1:]

    elif choice == 4:
        # Random chunk duplication
        if len(data) < 2:
            return data
        start = random.randrange(len(data))
        end = random.randrange(start, min(start + 32, len(data)))
        chunk = data[start:end + 1]
        ins_pos = random.randrange(len(data) + 1)
        return data[:ins_pos] + chunk + data[ins_pos:]

    elif choice == 5:
        # Insert XML token
        tok = random.choice(_XML_TOKENS)
        idx = random.randrange(len(data) + 1)
        return data[:idx] + tok + data[idx:]

    elif choice == 6:
        # Replace small range with zeroes
        if len(data) < 2:
            return data
        start = random.randrange(len(data))
        length = random.randint(1, min(8, len(data) - start))
        return data[:start] + b'\x00' * length + data[start + length:]

    else:
        # Truncate to random prefix
        if len(data) <= 1:
            return data
        trunc = random.randint(1, len(data))
        return data[:trunc]


_DATA_MAX = PHANTOM_PAYLOAD_MAX - 4  # 4 bytes for length prefix


def _build_payload(data: bytes) -> bytes:
    """
    Build the 64KB inject blob written to PAYLOAD_GPA by inject_payload.

    Layout (matches libxml2_harness.c):
      [0..3]               uint32_t length (little-endian)
      [4 .. PAYLOAD_MAX-1] XML data (zero-padded)

    Total size == PHANTOM_PAYLOAD_MAX (64KB).
    """
    clipped = data[:_DATA_MAX]
    length = len(clipped)
    body = clipped.ljust(_DATA_MAX, b'\x00')
    return struct.pack("<I", length) + body


# ---------------------------------------------------------------------------
# Main fuzzing loop
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Phantom libxml2 mutation fuzzer")
    parser.add_argument("--duration", type=int, default=3600,
                        help="Run for this many seconds (default: 3600)")
    parser.add_argument("--cpu", type=int, default=0,
                        help="Pin VM to this physical CPU (default: 0)")
    parser.add_argument("--timeout-ms", type=int, default=1000,
                        help="Per-iteration timeout in ms (default: 1000)")
    parser.add_argument("--harness",
                        default=os.path.join(_SCRIPT_DIR, "..", "..",
                                             "guest",
                                             "libxml2_harness.bin.flat"),
                        help="Path to flat harness binary (loaded at 0x400000)")
    parser.add_argument("--trampoline",
                        default=os.path.join(_SCRIPT_DIR, "..", "..",
                                             "guest",
                                             "libxml2_trampoline.bin"),
                        help="Path to trampoline binary (loaded at 0x10000)")
    parser.add_argument("--crash-dir", default="crashes",
                        help="Directory to save crash inputs (default: crashes/)")
    args = parser.parse_args()

    harness_path = os.path.realpath(args.harness)
    trampoline_path = os.path.realpath(args.trampoline)
    crash_dir = os.path.realpath(args.crash_dir)
    os.makedirs(crash_dir, exist_ok=True)

    print("Phantom libxml2 fuzzer")
    print("  harness     : %s" % harness_path)
    print("  trampoline  : %s" % trampoline_path)
    print("  cpu         : %d" % args.cpu)
    print("  timeout     : %d ms" % args.timeout_ms)
    print("  duration    : %d s" % args.duration)
    print("  crashes     : %s" % crash_dir)

    with open(harness_path, "rb") as f:
        harness_data = f.read()
    with open(trampoline_path, "rb") as f:
        trampoline_data = f.read()
    print("  harness size   : %d bytes" % len(harness_data))
    print("  trampoline size: %d bytes" % len(trampoline_data))

    # Open device and create VM
    fd = phantom_open()
    try:
        instance_id = phantom_create_vm(fd, pinned_cpu=args.cpu)
        print("  instance_id: %d" % instance_id)

        # Step 1: load the trampoline at GUEST_CODE_GPA (0x10000).
        # The trampoline is < 4KB so it does NOT reach the page tables at
        # 0x13000. It just does: movabs $0x400000, %rax; jmp *%rax
        phantom_load_target(fd, TARGET_GPA, trampoline_data)
        print("  trampoline loaded at GPA 0x%x" % TARGET_GPA)

        # Step 2: load the harness at 0x400000 (safely above page tables).
        phantom_load_target(fd, HARNESS_LOAD_GPA, harness_data)
        print("  harness loaded at GPA 0x%x" % HARNESS_LOAD_GPA)

        # Step 3: launch once with test_id=10 (no code overwrite).
        # Guest runs: trampoline(0x10000) → harness(0x400000) →
        #   HC_GET_PAYLOAD + HC_ACQUIRE (snapshot) + xmlParseMemory + HC_RELEASE
        result, exit_reason = phantom_run_guest(fd, cpu=0, test_id=10)
        print("  initial run: result=0x%x exit_reason=0x%x" %
              (result, exit_reason))
        print()

        # Corpus: start with seeds, grow with interesting inputs
        corpus = list(SEEDS)

        iters = 0
        crashes = 0
        timeouts = 0
        start_time = time.monotonic()
        last_report = start_time
        deadline = start_time + args.duration

        print("%-10s %-12s %-8s %-8s %-10s" %
              ("iters", "exec/sec", "crashes", "timeouts", "corpus"))

        while time.monotonic() < deadline:
            # Pick a seed and mutate it
            seed = random.choice(corpus)
            payload = _mutate(seed)

            blob = _build_payload(payload)
            result, exit_reason, checksum = phantom_run_iteration(
                fd, blob, timeout_ms=args.timeout_ms)

            iters += 1

            if result in (PHANTOM_RESULT_CRASH,
                          PHANTOM_RESULT_PANIC,
                          PHANTOM_RESULT_KASAN):
                crashes += 1
                crash_name = "crash_%06d_%s" % (crashes, result_name(result))
                crash_path = os.path.join(crash_dir, crash_name)
                with open(crash_path, "wb") as cf:
                    cf.write(payload)
                print("[CRASH] result=%s exit_reason=0x%x checksum=0x%x"
                      " -> %s" % (result_name(result), exit_reason,
                                  checksum, crash_path))

            elif result == PHANTOM_RESULT_TIMEOUT:
                timeouts += 1

            elif result == PHANTOM_RESULT_OK:
                # Add interesting inputs to corpus (keep it bounded)
                if len(corpus) < 1024 and len(payload) > 4:
                    corpus.append(payload)

            now = time.monotonic()
            if now - last_report >= 30.0:
                elapsed = now - start_time
                exec_per_sec = iters / elapsed if elapsed > 0 else 0
                print("%-10d %-12.1f %-8d %-8d %-10d" %
                      (iters, exec_per_sec, crashes, timeouts, len(corpus)))
                last_report = now

        elapsed = time.monotonic() - start_time
        exec_per_sec = iters / elapsed if elapsed > 0 else 0
        print()
        print("Done.")
        print("  iterations : %d" % iters)
        print("  exec/sec   : %.1f" % exec_per_sec)
        print("  crashes    : %d" % crashes)
        print("  timeouts   : %d" % timeouts)
        print("  elapsed    : %.1f s" % elapsed)

        phantom_destroy_vm(fd)
    finally:
        phantom_close(fd)


if __name__ == "__main__":
    main()
