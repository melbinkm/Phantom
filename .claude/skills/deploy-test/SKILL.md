---
name: deploy-test
description: Build, deploy phantom.ko to target machine, and run tests
user-invocable: true
argument-hint: "[test-name]"
---

# Deploy and Test Phantom

Parse `$ARGUMENTS` as an optional test name or pattern (e.g., `vmxon`, `cow`, `all`).

## Steps

1. **Build:**
   ```bash
   make -C kernel/ 2>&1
   ```
   - If build fails: show the error and stop. Do not attempt to deploy a broken module.
   - If build succeeds: show the last few lines of make output confirming `phantom.ko` was produced.

2. **Determine deployment target:**
   - Check CLAUDE.md for current phase (`CURRENT_PHASE`)
   - Phase 0–1: deploy locally (nested KVM)
   - Phase 2+: deploy via SSH to `phantom-bench`

3. **Local deployment (Phase 0–1):**
   ```bash
   sudo rmmod phantom 2>/dev/null || true
   sudo insmod kernel/phantom.ko
   dmesg | tail -20
   ```

4. **SSH deployment (Phase 2+):**
   ```bash
   scp kernel/phantom.ko phantom-bench:/tmp/phantom.ko
   ssh phantom-bench "sudo rmmod phantom 2>/dev/null; sudo insmod /tmp/phantom.ko"
   ssh phantom-bench "sudo dmesg | tail -30"
   ```

5. **Run tests:**
   - If `$ARGUMENTS` is empty or `all`: run all tests for the current task (check open GitHub issue with `in-progress` label: `gh issue list --repo melbinkm/Phantom --label in-progress --state open --json number,title`, then run the full test list from the corresponding task file)
   - If `$ARGUMENTS` is a specific test name: run only that test

   **Local tests:**
   ```bash
   bash tests/{test-name}.sh 2>&1
   ```

   **SSH tests:**
   ```bash
   scp tests/{test-name}.sh phantom-bench:/tmp/
   ssh phantom-bench "sudo bash /tmp/{test-name}.sh 2>&1"
   ```

6. **Capture and display results:**
   - Show full dmesg output relevant to phantom.ko (filter for `phantom:` prefix)
   - Show test pass/fail with evidence (exact output, not just exit code)
   - For benchmarks: capture timing data and summarise (median, p25/p75)
   - Check debugfs counters if relevant: `cat /sys/kernel/debug/phantom/*/`

7. **Report:**
   ```
   BUILD: PASS (phantom.ko: 42KB)
   DEPLOY: PASS (loaded on phantom-bench, no dmesg errors)

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
- If `insmod` hangs: the VMX code may have triggered a host panic; check serial console
- For benchmark runs: disable turbo boost first (`echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo`)
- Benchmark methodology: 30 runs, discard first 5 (warmup), report median + p25/p75
