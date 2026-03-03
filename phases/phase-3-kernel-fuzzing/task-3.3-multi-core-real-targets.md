# Task 3.3: Multi-Core + Real Kernel Targets

> **Phase:** Kernel Fuzzing — Class B | **Week(s):** 28–29 | **Depends on:** [Task 3.2](task-3.2-determinism-engineering.md) (GATE: 1000/1000 determinism must pass before starting)

## Objective

Scale Phantom to multiple cores with independent per-CPU instances, verify near-linear scaling, re-confirm EPT isolation in multi-core configuration, and run a 72-hour stability soak.

## What to Build

- Per-CPU VM instances: independent EPT + CoW page pool per instance; all allocations via `alloc_pages_node()` (NUMA-local to pinned core per Section 7); per-CPU instance lifecycle (VMXON/VMXOFF per core, independent VMCS per instance) — implemented in `multicore.c` here in Phase 3 (the code size estimate table at §4.2 labels this file as "Phase 4", which is a stale annotation; multi-core is required for Class B kernel fuzzing)
- Lock-free global bitmap merging: each instance maintains local bitmap, periodic merge to global using atomic OR operations; no shared state except global bitmap merge
- Scaling tests: measure exec/sec vs core count for 1, 2, 4, 8, and 16 cores; target near-linear scaling: `exec_N_cores / (exec_1_core × N) ≥ 0.85` for N ∈ {2, 4, 8}
- NUMA placement measurement: measure NUMA-local vs NUMA-remote allocation impact (Phase 3 benchmark deliverable)
- EPT isolation in multi-core configuration: re-confirm that per-CPU instances maintain independent EPT hierarchies (initial single-core isolation verified in Phase 2 Task 2.4; this re-runs the same check with all cores active simultaneously)
- 72-hour stability soak test: continuous multi-core fuzzing; monitor host memory, kernel log, exec/sec
- If multi-core issues arise (lock contention, NUMA imbalance, per-CPU lifecycle bugs): 3rd week allocated to debugging

## Implementation Guidance

### NUMA Allocation Strategy (§7)

All per-instance memory allocations must use `alloc_pages_node(cpu_to_node(pinned_cpu), ...)`:

```c
static int phantom_multicore_instance_create(int cpu)
{
    int node = cpu_to_node(cpu);  /* NUMA node for this physical CPU */
    struct phantom_instance *inst;

    inst = kzalloc_node(sizeof(*inst), GFP_KERNEL, node);
    if (!inst) return -ENOMEM;

    /* All instance memory NUMA-local to pinned_cpu */
    inst->guest_mem  = alloc_pages_node(node, GFP_KERNEL, order_for_mb(256));
    inst->cow_pool   = phantom_pool_init_node(node, COW_POOL_CLASS_B_PAGES);
    inst->topa_buf_a = phantom_topa_alloc_node(node, TOPA_SIZE_CLASS_B);
    inst->topa_buf_b = phantom_topa_alloc_node(node, TOPA_SIZE_CLASS_B);
    inst->ept_root   = alloc_page_node(node, GFP_KERNEL | __GFP_ZERO);
    inst->vmcs_page  = alloc_page_node(node, GFP_KERNEL | __GFP_ZERO);
    inst->xsave_area = alloc_pages_node(node, GFP_KERNEL, 0);  /* 4KB */

    inst->pinned_cpu = cpu;
    return 0;
}
```

**NUMA performance rationale (§7):**
- NUMA-remote memory access: ~40–80 ns per cache miss
- NUMA-local memory access: ~10 ns per cache miss
- With thousands of EPT walks and CoW page accesses per iteration, NUMA-remote allocation can degrade exec/sec by 20–40% on 2-socket systems.

### 16-Core Memory Planning (§4.3)

```
16 × (256MB + 64MB + 16MB + 2MB + misc) ≈ 16 × 340MB ≈ 5.4GB

Plan for 8GB reserved exclusively for Phantom on a 64GB machine
with 16 Class B instances.
```

### Lock-Free Global Bitmap Merging

```c
/* Each instance has an independent local bitmap (no sharing) */
/* Periodic merge to global using atomic OR — no lock on hot path */

static void phantom_merge_bitmap_to_global(struct phantom_instance *inst)
{
    u64 *local  = (u64 *)inst->coverage_bitmap;
    u64 *global = (u64 *)phantom_global_bitmap;

    /* AFL bitmap is 64KB = 8192 × 64-bit words */
    for (int i = 0; i < 8192; i++) {
        if (local[i])
            atomic64_or(local[i], (atomic64_t *)&global[i]);
    }

    /* Clear local bitmap for next batch of iterations */
    memset(inst->coverage_bitmap, 0, 64 * 1024);
}
```

### EPT Isolation Re-Verification (Multi-Core)

Re-run the EPT isolation test from Task 2.4 with all cores active simultaneously:

```c
static int test_ept_isolation_multicore(void)
{
    /* Start all instances on all cores */
    for_each_cpu(cpu, phantom_cpumask)
        phantom_start_fuzzing(per_cpu(phantom_inst, cpu));

    /* Write distinctive value to instance on CPU 0 */
    u64 sentinel = 0xDEADBEEFCAFEBABEULL;
    phantom_write_guest_mem(per_cpu(phantom_inst, 0), TEST_GPA, &sentinel, 8);

    /* Verify all other instances cannot read it */
    for_each_cpu_not(cpu, phantom_cpumask_single(0)) {
        u64 read_val;
        phantom_read_guest_mem(per_cpu(phantom_inst, cpu), TEST_GPA, &read_val, 8);
        WARN_ON(read_val == sentinel);  /* Must be different */
    }
    return 0;
}
```

### Scaling Criterion Formula

From §9 quantified criteria:

```
Near-linear scaling:
exec_N_cores / (exec_1_core × N) ≥ 0.85 for N ∈ {2, 4, 8}
```

Measurement procedure:
1. Measure exec_1 on single core (use Task 3.2 baseline)
2. Measure exec_2, exec_4, exec_8 on 2/4/8 cores simultaneously
3. Compute scaling factor for each
4. All three must be ≥ 0.85

### NUMA Benchmark Deliverable

From §7:
> Phase 3 benchmark deliverable: Measure exec/sec with NUMA-local vs NUMA-remote allocation for a Class B target on the 2-socket benchmark machine. Report as "NUMA locality impact" figure in the paper.

Test procedure:
```bash
# NUMA-local: instance pinned to CPU on same socket as memory
numactl --cpubind=0 --membind=0 phantom-ctl create --cpu 0 --class B

# NUMA-remote: instance pinned to CPU on different socket from memory
numactl --cpubind=0 --membind=1 phantom-ctl create --cpu 0 --class B
```

## Key Data Structures

```c
/* multicore.c: Per-CPU instance management */
DEFINE_PER_CPU(struct phantom_instance *, phantom_inst);

/* Global bitmap for multi-core coverage merging */
static u8 phantom_global_bitmap[64 * 1024] __cacheline_aligned;

/* Scaling measurement results */
struct phantom_scaling_result {
    u32  core_count;
    u64  exec_per_sec;
    f64  scaling_factor;   /* exec_N / (exec_1 × N) */
    bool meets_threshold;  /* ≥ 0.85 */
};
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/multicore.c` | Per-CPU instance management, NUMA allocation |
| `kernel/ept.c` | EPT isolation re-verification |
| `tests/integration/test_multicore_isolation.sh` | Multi-core EPT isolation test |
| `tests/performance/bench_scaling.sh` | Scaling measurement script |
| `tests/performance/bench_numa.sh` | NUMA locality comparison |

## Reference Sections

- §7: NUMA allocation strategy — `alloc_pages_node(cpu_to_node())`, 40–80ns vs 10ns, 20–40% degradation
- §4.3: 16-core Class B memory calculation — ~5.4GB for 16 instances, plan for 8GB
- §6.5: EPT isolation re-verification — repeat single-core test with all cores active simultaneously
- §9: Scaling criterion formula — `exec_N / (exec_1 × N) ≥ 0.85` for N ∈ {2, 4, 8}

## Tests to Run

- Near-linear scaling: exec_N / (exec_1 × N) ≥ 0.85 for N ∈ {2, 4, 8} (pass = scaling factor meets threshold for all three core counts)
- EPT isolation in multi-core configuration re-confirmed: with all cores active, instance A write does not appear in instance B's guest memory (pass = cross-instance read returns original unmodified value)
- 72-hour stability soak: no host panics, no memory leaks, exec/sec at hour 72 ≥ 90% of exec/sec at hour 1 (pass = all three conditions met)
- NUMA-local vs NUMA-remote memory comparison documented (pass = latency/throughput measurement recorded)
- At least 1 real bug found in a kernel subsystem during Phase 3 campaigns (pass = crash input confirmed to reproduce in unmodified kernel build outside Phantom; this is a Phase 3 exit gate per §12 milestone Week 30)

## Deliverables

Multi-core kernel fuzzing with near-linear scaling demonstrated across 1/2/4/8/16 cores; at least 1 real kernel bug confirmed.
