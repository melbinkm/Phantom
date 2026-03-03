---
name: deploy-test
description: Build, deploy phantom.ko to target machine, and run tests
user-invocable: true
argument-hint: "[test-name]"
---

# Deploy and Test Phantom

Parse `$ARGUMENTS` as an optional test name or pattern (e.g., `vmxon`, `cow`, `all`).

**Build always happens on the server** — the dev machine is WSL2 (kernel 6.6.87) and cannot
cross-compile for the server (kernel 6.8.0-generic). All steps go through SSH.

## Steps

1. **Rsync source to server:**
   ```bash
   rsync -az --delete \
     --exclude='.git' --exclude='*.o' --exclude='*.ko' --exclude='*.mod*' \
     /mnt/d/fuzzer/ phantom-bench:/root/phantom/src/
   ```
   - If rsync fails: check SSH key (`ssh phantom-bench "echo ok"`) and retry.

2. **Build on server:**
   ```bash
   ssh phantom-bench "make -C /root/phantom/src/kernel/ 2>&1"
   ```
   - If build fails: show the full error. Do not proceed. Common fixes:
     - Missing headers: `ssh phantom-bench "apt install linux-headers-\$(uname -r)"`
     - Missing tools: `ssh phantom-bench "apt install build-essential"`
   - If build succeeds: confirm `phantom.ko` was produced and note its size.

3. **Determine deployment target** (check CLAUDE.md `CURRENT_PHASE`):
   - **Phase 0–1:** Deploy into QEMU nested KVM guest via 9p share
   - **Phase 2+:** Deploy directly on the server

4. **Deploy — Phase 0–1 (QEMU guest):**

   First ensure the guest is running:
   ```bash
   ssh phantom-bench "pgrep qemu-system-x86 || bash /root/phantom/src/scripts/launch-guest.sh"
   ```

   Load the module in the guest (9p share makes the compiled .ko immediately available):
   ```bash
   ssh phantom-bench "ssh -p 2222 -o StrictHostKeyChecking=no root@localhost \
     'rmmod phantom 2>/dev/null || true; insmod /mnt/phantom/kernel/phantom.ko'"
   ssh phantom-bench "ssh -p 2222 -o StrictHostKeyChecking=no root@localhost \
     'dmesg | tail -30'"
   ```

5. **Deploy — Phase 2+ (directly on server):**
   ```bash
   ssh phantom-bench "rmmod phantom 2>/dev/null || true; \
     insmod /root/phantom/src/kernel/phantom.ko"
   ssh phantom-bench "dmesg | tail -30"
   ```
   - Ensure `kvm_intel` is unloaded first: `ssh phantom-bench "rmmod kvm_intel 2>/dev/null || true"`

6. **Run tests:**
   - If `$ARGUMENTS` is empty or `all`: run all tests for the current task (check open GitHub
     issue with `in-progress` label: `gh issue list --repo melbinkm/Phantom --label in-progress
     --state open --json number,title`, then run the full test list from the task file)
   - If `$ARGUMENTS` is a specific test name: run only that test

   **Phase 0–1 tests (run in guest):**
   ```bash
   rsync -az /mnt/d/fuzzer/tests/ phantom-bench:/root/phantom/src/tests/
   ssh phantom-bench "ssh -p 2222 -o StrictHostKeyChecking=no root@localhost \
     'bash /mnt/phantom/tests/{test-name}.sh 2>&1'"
   ```

   **Phase 2+ tests (run on server):**
   ```bash
   ssh phantom-bench "bash /root/phantom/src/tests/{test-name}.sh 2>&1"
   ```

7. **Capture and display results:**
   - Show dmesg filtered for phantom (from the right host — guest or server):
     - Phase 0–1: `ssh phantom-bench "ssh -p 2222 root@localhost 'dmesg | grep -E (phantom|BUG|OOPS|WARNING)'"`
     - Phase 2+: `ssh phantom-bench "dmesg | grep -E '(phantom|BUG|OOPS|WARNING)'"`
   - Show test pass/fail with evidence (exact output, not just exit code)
   - For benchmarks: capture timing data and summarise (median, p25/p75)
   - Check debugfs counters if relevant:
     - Phase 0–1: `ssh phantom-bench "ssh -p 2222 root@localhost 'cat /sys/kernel/debug/phantom/*/'" `
     - Phase 2+: `ssh phantom-bench "cat /sys/kernel/debug/phantom/*/"`

8. **Report:**
   ```
   BUILD: PASS (phantom.ko: 42KB, built on phantom-bench kernel 6.8.0-90-generic)
   DEPLOY: PASS (loaded in QEMU guest, no dmesg errors)

   TEST RESULTS:
   [PASS] vmxon_basic — VMX entered on 4 cores
   [FAIL] ept_cow_basic — pool exhausted after 18 pages (expected 20)

   DMESG (relevant):
   phantom: CPU0: VMX root entered successfully
   phantom: CPU1: VMX root entered successfully
   ...

   NEXT: investigate pool exhaustion in kernel/ept_cow.c phantom_pool_alloc()
   ```

## Notes

- Always check `dmesg | grep -E "(phantom|BUG|OOPS|WARNING)"` after insmod
- If insmod hangs: the VMX code may have triggered a panic; check guest serial log:
  `ssh phantom-bench "tail -50 /root/phantom/logs/guest.log"`
- For benchmark runs: disable turbo boost first:
  - Phase 2+: `ssh phantom-bench "echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo"`
  - Phase 0–1: apply inside guest
- Benchmark methodology: 30 runs, discard first 5 (warmup), report median + p25/p75
- If guest is not running: `ssh phantom-bench "bash /root/phantom/src/scripts/launch-guest.sh"`
