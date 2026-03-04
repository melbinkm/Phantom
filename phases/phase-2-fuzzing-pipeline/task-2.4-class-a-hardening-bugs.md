# Task 2.4: Multi-Core Scaling + Class A Hardening + First Bug Campaign

> **Phase:** Fuzzing Pipeline | **Week(s):** 19–20 | **Depends on:** [Task 2.3](task-2.3-userspace-interface-frontend.md)

## Objective

Enable multi-core parallel fuzzing (4× throughput on i7-6700), harden the complete fuzzing loop (timeout handling, edge case recovery, EPT isolation verification), profile and optimize the hot path, and find the first real bug in a Class A target.

## Implementation Order

**IMPORTANT: implement in this order — multi-core first, then hardening, then bug campaigns.**
Multi-core is implemented first so that all subsequent testing (hardening, bug campaigns) runs at full 4-core throughput.

## What to Build

- **[FIRST] Multi-core parallel fuzzing**: load `phantom.ko` with `cores=0,1,2,3`; add `-j N` flag to `afl-phantom` to spawn N independent AFL++ instances each bound to a separate core via `PHANTOM_CREATE_VM(pinned_cpu=N)`, using AFL++ `-M master -S slaveN` with a shared output directory for corpus sharing; add `--cores 0,1,2,3` flag to `kafl-bridge` to run N parallel processes; create `scripts/phantom-multi.sh` launcher; verify ~4× exec/sec vs single-core baseline; the kernel already supports this (`phantom_parse_cores_param`, per-core `phantom_vmx_cpu_state`) — this is purely userspace coordination work
- Performance profiling and optimisation: profile hot path with `rdtsc` instrumentation, identify top 3 bottlenecks and optimise them, produce per-component microbenchmark breakdown (restore latency, VM exit latency, input injection latency)
- Timeout handling: VMX preemption timer per Section 2.5, configurable timeout budget per target class
- Edge case hardening: guest stack overflow → EPT violation on guard page → report as `PHANTOM_RESULT_CRASH`; guest infinite loop → preemption timer timeout → `PHANTOM_RESULT_TIMEOUT`; PT buffer overflow → PMI handler → mark iteration as `PHANTOM_COVERAGE_DISCARDED`; pool exhaustion → abort iteration, log warning, instance remains usable
- EPT isolation test: create two VM instances simultaneously using `PHANTOM_CREATE_VM`; write a distinctive value into instance A's guest memory; verify instance B cannot read that value — this must be verified here in Phase 2 before any multi-core work begins in Phase 3 (per §6.5 security requirements)
- Bug campaigns on Class A targets (run at full multi-core throughput): libxml2 XML parser, OpenSSL certificate parsing, libpng/libjpeg-turbo image decoding, DNS packet parser; document all crashes, assess severity

## Implementation Guidance

### Multi-Core Scaling (DO THIS FIRST)

The kernel side is already complete. `phantom_parse_cores_param()` parses `cores=0,1,2,3`,
spins up one vCPU thread per core, and `PHANTOM_CREATE_VM(pinned_cpu=N)` binds an instance
to that core. Each core has fully independent VMCS + EPT + snapshot — zero locking on the
hot path, so throughput scales linearly.

**Step 1: Load with all 4 physical cores**

```bash
insmod phantom.ko cores=0,1,2,3
# Expect: "phantom: loaded, VMX active on 4 core(s)"
```

**Step 2: Add `-j N` to afl-phantom (`userspace/afl-phantom/afl_phantom.c`)**

```c
/* For each core i in [0, N): */
int phantom_fd = open("/dev/phantom", O_RDWR);
struct phantom_create_args ca = { .pinned_cpu = i };
ioctl(phantom_fd, PHANTOM_CREATE_VM, &ca);
/* Then run AFL++ fork-server on this fd */
```

AFL++ multi-instance corpus sharing:
```bash
# Terminal 0 (master):
afl-fuzz -i corpus/ -o out/ -M master -- ./afl-phantom --phantom-fd 0
# Terminal 1-3 (secondaries):
afl-fuzz -i corpus/ -o out/ -S slave1 -- ./afl-phantom --phantom-fd 1
afl-fuzz -i corpus/ -o out/ -S slave2 -- ./afl-phantom --phantom-fd 2
afl-fuzz -i corpus/ -o out/ -S slave3 -- ./afl-phantom --phantom-fd 3
```

**Step 3: Add `--cores` to kafl-bridge (`userspace/kafl-bridge/phantom_bridge.py`)**

```python
# --cores 0,1,2,3 spawns multiprocessing.Process per core
# Each process opens /dev/phantom independently and calls CREATE_VM(pinned_cpu=N)
```

**Step 4: `scripts/phantom-multi.sh` launcher**

```bash
#!/usr/bin/env bash
# Usage: phantom-multi.sh --cores 4 --corpus corpus/ --output out/
# Loads phantom.ko with cores=0,...,N-1, starts N afl-fuzz instances
```

**Step 5: Verify ~4× throughput**

```bash
# Single core baseline
python3 kafl-bridge/phantom_bridge.py --max-iterations 10000 --cores 0
# Multi-core
python3 kafl-bridge/phantom_bridge.py --max-iterations 10000 --cores 0,1,2,3
# Expect: ~4× exec/sec improvement
```

**Test: `tests/test_2_4_multicore.sh`**
1. `insmod phantom.ko cores=0,1,2,3` — expect "VMX active on 4 core(s)"
2. Run kafl-bridge `--cores 0,1,2,3` for 1000 iterations — no errors
3. Measure exec/sec vs single-core — verify ≥3.5× ratio (allow for OS overhead)
4. EPT isolation: CREATE_VM on CPU 0 and CPU 1 simultaneously, verify cross-instance memory isolation

### VMX Preemption Timer Setup (§2.5)

```c
/* At instance creation: convert timeout budget from TSC ticks */
static u32 phantom_preemption_timer_value(u64 tsc_ticks)
{
    /*
     * Preemption timer rate = TSC / 2^N where N = IA32_VMX_MISC[4:0]
     * Typical N = 0 (timer rate = TSC rate) or 5 (timer rate = TSC/32)
     */
    u64 misc = rdmsr(MSR_IA32_VMX_MISC);
    u32 rate_shift = misc & 0x1f;
    return (u32)(tsc_ticks >> rate_shift);
}

/* Set in VMCS field 0x482E (32-bit) on every VMRESUME */
static void phantom_set_preemption_timer(struct phantom_instance *inst)
{
    u32 budget = phantom_preemption_timer_value(inst->timeout_tsc_ticks);
    vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, budget);
    /* Ensure pin-based controls have "activate VMX preemption timer" bit set */
    vmcs_set_bits(PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_VMX_PREEMPTION_TIMER);
}

/* On timeout VM exit (reason 52) */
static int phantom_handle_preemption_timer(struct phantom_instance *inst)
{
    /* 1. Preemption timer fired — iteration is aborted */
    /* 2. Set iteration result */
    inst->run_result = PHANTOM_RESULT_TIMEOUT;
    /* 3. Snapshot restore — mandatory before next iteration */
    return phantom_snapshot_restore(inst);
    /* 4. Return to userspace — instance fully usable */
}
```

**Timeout budgets:**
- Class A: 10M–100M TSC ticks (≈3–30ms at 3GHz), configurable
- Class B: larger budget to accommodate kernel boot time (configured per target)

### EPT Isolation Test (§6.5 — Must Pass Before Phase 3)

```c
static int test_ept_isolation(void)
{
    struct phantom_instance *inst_a = phantom_create(CPU_A, ...);
    struct phantom_instance *inst_b = phantom_create(CPU_B, ...);

    u64 test_value = 0xDEADBEEFCAFEBABEULL;
    u64 read_value;

    /* Write distinctive value into instance A's guest memory */
    phantom_write_guest_mem(inst_a, TEST_GPA, &test_value, sizeof(test_value));

    /* Read the same GPA from instance B's guest memory */
    phantom_read_guest_mem(inst_b, TEST_GPA, &read_value, sizeof(read_value));

    /* Instance B must NOT see instance A's value */
    WARN_ON(read_value == test_value);

    /*
     * If this fails, the two instances are sharing EPT structures
     * (EPTP collision or EPT mapping aliasing) — critical security bug.
     */
    phantom_destroy(inst_a);
    phantom_destroy(inst_b);
    return (read_value != test_value) ? 0 : -EFAULT;
}
```

**EPT isolation mechanism:** Each instance has an independent EPT pointer (EPTP in VMCS). One guest cannot access another guest's memory because they have different EPT hierarchies. The test explicitly verifies this at the hardware level.

### Error Handling — Full Classification (§5.5 Appendix A)

**1. Hardware Errors:**
- Log full VMCS dump → mark `PHANTOM_STATE_FAILED` → return `PHANTOM_ERROR_HARDWARE`
- Do NOT re-run. Destroy and recreate instance.

**2. Guest Errors (triple fault, timeout, KASAN):**
- Abort iteration → snapshot restore → set result code
- Return to userspace — instance fully usable

**3. Resource Errors (pool exhaustion, ToPA overflow, dirty list overflow):**
- **Pool exhaustion:** Abort, restore, return `PHANTOM_ERROR_POOL_EXHAUSTED`. Instance remains usable.
- **Dirty list overflow:** Same cleanup as pool exhaustion. Return `PHANTOM_ERROR_DIRTY_OVERFLOW`.
- **ToPA overflow:** Do NOT abort. Mark `PHANTOM_COVERAGE_DISCARDED`. Continue until RELEASE or timeout. **Do not use bitmap for corpus guidance** — incomplete bitmaps show false new edges.

**4. Host Errors (NMI, corrupted VMX state):**
- NMI: handled via NMI-exiting + APIC self-NMI re-delivery (Task 1.2)
- Corrupted VMX state: mark all instances on that core `PHANTOM_STATE_FAILED`

**PT Daemon Crash Recovery:**
```c
/* chardev release handler — detect PT daemon disconnect */
static int phantom_release(struct inode *inode, struct file *filp)
{
    struct phantom_instance *inst = filp->private_data;

    /* Stop copying PT trace data to userspace */
    inst->pt_daemon_connected = false;

    /* Continue fuzzing without coverage feedback */
    pr_warn("phantom: PT daemon disconnected for instance %d\n", inst->id);

    /* New daemon can re-attach by reopening /dev/phantom */
    return 0;
}
```

### Class A Target List (§3)

| Target | Function | Expected Throughput |
|--------|----------|---------------------|
| libxml2 | `xmlParseMemory()` | >50k exec/sec |
| OpenSSL | Certificate parsing | >50k exec/sec |
| libpng | `png_read_image()` | >50k exec/sec |
| libjpeg-turbo | JPEG decode | >50k exec/sec |
| DNS parser | Packet parse | >100k exec/sec |

**Per bug:** minimise reproducer using AFL++ `tmin`; complete root cause analysis; write patch where appropriate; report to project maintainer.

## Key Data Structures

```c
/* VMX exit reasons */
#define VMX_EXIT_PREEMPTION_TIMER  52   /* Timeout — restore and continue */

/* Timeout configuration */
struct phantom_timeout_config {
    u64 tsc_ticks;              /* Budget in TSC ticks                    */
    u32 preemption_timer_value; /* Converted value for VMCS field 0x482E  */
};

#define PHANTOM_TIMEOUT_CLASS_A_MS  10   /* 10ms default for parsers       */
#define PHANTOM_TIMEOUT_CLASS_B_MS  100  /* 100ms default for kernel fuzz  */
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/watchdog.c` | VMX preemption timer management |
| `kernel/vmx_core.c` | Preemption timer exit handler (reason 52) |
| `tests/unit/test_security.c` | EPT isolation test |

## Reference Sections

- §2.5: Watchdog timer full — preemption timer setup pseudocode, timeout exit handling, restore requirement
- §6.5: EPT isolation test — per-instance EPTP, cross-instance read verification, required before Phase 3
- §3: Class A targets — libxml2, OpenSSL, libpng, libjpeg-turbo, DNS parser
- §5.5 Appendix A: Full error handling — all 4 error categories, PT daemon crash recovery

## Tests to Run

- **Multi-core**: `insmod phantom.ko cores=0,1,2,3` loads with 4 vCPU threads; kafl-bridge `--cores 0,1,2,3` achieves ≥3.5× exec/sec vs single-core baseline
- EPT isolation: instance A write is not visible to instance B (pass = instance B reads original unmodified value, confirming independent EPT hierarchies; test runs here in Phase 2 per §6.5)
- At least 1 real crash found in an unmodified real-world target (pass = crash input confirmed to trigger in unmodified binary outside Phantom)
- VMX preemption timer fires for a guest infinite loop (pass = `PHANTOM_RESULT_TIMEOUT` returned within the configured window)
- Guest stack overflow reported as crash with crash address logged (pass = `PHANTOM_RESULT_CRASH` returned, address in log)
- PT overflow marked as `PHANTOM_COVERAGE_DISCARDED` and iteration continues to completion (pass = status flag set, execution reaches RELEASE or timeout)
- Class A throughput > 50k exec/sec per core on at least one real parser target (pass = measured exec/sec exceeds 50,000 per core, ~200k total across 4 cores)

## Deliverables

First real bugs found; performance characterised for Class A targets.

## Exit Criteria

**Phase 2 exit criteria:** end-to-end fuzzing with AFL++ and kAFL frontends; coverage bitmap correctly tracks guest execution (8 input combinations × 3 branch points produce 8 distinct bitmap entries); PT decode running in userspace, double-buffered with eventfd notification; Class A throughput > 50k exec/sec on real parser targets; at least 1 real crash found in an unmodified real-world target; 24-hour stability test passed; **EPT isolation verified** (instance A write not visible to instance B); paper Background and Design sections drafted.
