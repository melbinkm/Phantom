# Task 1.8: Performance Measurement

> **Phase:** CoW Engine + Snapshot/Restore | **Week(s):** 12 | **Depends on:** [Task 1.7](task-1.7-correctness-testing.md)

## Objective

Profile the snapshot restore path, measure latency across dirty-page sweep points, isolate XRSTOR overhead, and establish the performance baseline needed to evaluate Phase 1b exit criteria and potential §6.7 rollback.

## What to Build

- Instrument restore path with `rdtsc`
- Restore latency sweep: measure latency vs dirty page count for 10, 50, 100, 200, and 500 dirty pages; expect linear relationship; budget XRSTOR at ~200–400 cycles
- XRSTOR overhead measurement: isolate contribution of XRSTOR to total restore latency
- Pool exhaustion recovery test: reduce pool size to force exhaustion, verify graceful abort and that the instance remains usable for subsequent iterations
- 10,000+ restore cycle endurance at each sweep point: no state corruption or memory leaks
- Module load/unload stress test: 100 consecutive `insmod`/`rmmod` cycles without error

## Implementation Guidance

### Restore Path Instrumentation

```c
int phantom_snapshot_restore(struct phantom_instance *inst)
{
    u64 t_start, t_dirty_walk, t_invept, t_vmcs, t_xrstor, t_total;

    t_start = rdtsc_ordered();

    /* 1. Walk dirty list + reset EPT entries */
    phantom_dirty_list_reset(inst);
    t_dirty_walk = rdtsc_ordered() - t_start;

    /* 2. Single batched INVEPT */
    phantom_invept_single_context(inst->eptp);
    t_invept = rdtsc_ordered() - t_start - t_dirty_walk;

    /* 3. Restore VMCS guest-state */
    phantom_vmcs_restore(inst);
    t_vmcs = rdtsc_ordered() - t_start - t_dirty_walk - t_invept;

    /* 4. XRSTOR (isolate this overhead) */
    u64 t_xrstor_start = rdtsc_ordered();
    kernel_fpu_begin();
    xrstor(inst->xsave_area, inst->xcr0_supported);
    kernel_fpu_end();
    t_xrstor = rdtsc_ordered() - t_xrstor_start;

    t_total = rdtsc_ordered() - t_start;

    /* Log to debugfs latency ring buffer */
    phantom_perf_log(inst, t_dirty_walk, t_invept, t_vmcs, t_xrstor, t_total);

    return phantom_vmresume(inst);
}
```

### Restore Latency Sweep (5 Data Points)

Measure p95 restore latency vs dirty page count:

| Dirty Pages | Expected p95 Latency | Pass Criterion |
|-------------|---------------------|----------------|
| 10 | < 1μs | Target: < 5μs |
| 50 | < 5μs | **Pass gate: ≤ 5μs** |
| 100 | < 10μs | — |
| 200 | < 20μs | — |
| 500 | < 50μs | **Pass gate: ≤ 50μs** |

Expect a linear relationship between dirty page count and restore latency (dominated by dirty-list walk + INVEPT + VMCS restore). Verify with linear regression (R² ≥ 0.95).

### Rollback Evaluation Trigger

From §6.7:

**Decision point:** End of Phase 1b (Week 12). If CoW restore latency >100μs for 500 dirty pages, evaluate Fallback A:

**Fallback A: PML dirty tracking + memcpy restore (kAFL/kvm-pt approach)**
- Use Page Modification Logging (PML) to identify dirty pages per iteration
- At restore: `memcpy` original page content back to each dirty page (in-place)
- Performance: slower for large dirty sets (memcpy ~100–300μs for 1000 dirty pages × 4KB = 4MB), simpler to implement

**Fallback B: Hybrid CoW + PML**
- CoW for hot pages (dirtied every iteration) — no EPT fault on subsequent writes
- PML for cold pages (dirtied occasionally) — fewer memcpy operations

**Decision criteria:** Compare restore latency and execution overhead for a representative Class B target. Choose whichever meets the <50μs restore target for the expected dirty set. Fallback A requires PML hardware (Intel Broadwell and later — available on all target hardware).

### Performance Targets Reference

From §1 performance targets table:

| Metric | kAFL/Nyx (SOTA) | Phantom Target (Class A) | Phantom Target (Class B) |
|--------|----------------|--------------------------|--------------------------|
| Exec/sec | 10k–20k | 50k–500k | 30k–100k |
| Snapshot restore latency | 100–500μs | <5μs (tiny dirty) to ~50μs (large) | 10–100μs (kernel-sized) |
| Input injection latency | ~5μs | <1μs (EPT write) | <1μs |

**Performance claim guidance:** Benchmarks will report "Nx faster than kAFL/Nyx for target class Y on hardware Z with dirty page footprint W." Expected range: 3–10x for kernel targets (Class B), 10–50x for standalone parsers (Class A).

### XRSTOR Overhead Budget

From §2.3: "Account for ~200–400 cycles additional latency in restore path for XRSTOR." At 3GHz, 400 cycles ≈ 133ns. This is a fixed cost independent of dirty page count and should appear as a constant offset in the linear regression.

### Pool Exhaustion Impact on Pool Sizing

From §4.3 pool sizing formula:
- `pool_size >= max_dirty_pages_per_iteration * 4KB`
- Class A default: 4096 pages (16MB) — headroom for 82× typical dirty set
- Class B default: 16384 pages (64MB) — headroom for 8× typical dirty set

If pool exhaustion occurs during sweep tests, note the pool size vs dirty set ratio for §4.3 calibration.

## Key Data Structures

```c
/* Per-iteration performance measurement */
struct phantom_perf_sample {
    u64 dirty_page_count;
    u64 dirty_walk_cycles;
    u64 invept_cycles;
    u64 vmcs_restore_cycles;
    u64 xrstor_cycles;
    u64 total_restore_cycles;
    u64 timestamp_ns;
};

/* Latency histogram (for p95 calculation) */
#define PERF_HISTOGRAM_BUCKETS 64
struct phantom_latency_hist {
    u64 buckets[PERF_HISTOGRAM_BUCKETS];  /* Cycle counts, log2-spaced */
    u64 count;
    u64 sum;
};
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/snapshot.c` | rdtsc instrumentation in restore path |
| `kernel/debug.c` | Latency ring buffer, debugfs perf exposure |
| `tests/performance/bench_restore_latency.sh` | Sweep test script |

## Reference Sections

- §6.7: Rollback plan — Fallback A/B descriptions, decision criteria, >100μs trigger
- §1: Performance targets table — exec/sec, restore latency targets, comparison baseline
- §4.3: Pool sizing impact — formula, Class A/B defaults, exhaustion headroom

## Tests to Run

- Restore latency (p95) < 5μs for 50 dirty pages (pass = p95 measurement ≤ 5μs across all sweep runs)
- Restore latency (p95) < 50μs for 500 dirty pages (pass = p95 measurement ≤ 50μs across all sweep runs)
- XRSTOR overhead ≈ 200–400 cycles isolated (pass = measured overhead within stated range)
- Pool exhaustion → instance still usable for the next iteration (pass = no `PHANTOM_STATE_FAILED`, next `PHANTOM_RUN_ITERATION` succeeds)
- 100× `insmod`/`rmmod` complete cleanly (pass = zero failures, no residual VMX state after any cycle)

## Deliverables

Latency-vs-dirty-page curve documented for 5 sweep points (10/50/100/200/500 dirty pages).

## Exit Criteria

**Phase 1b exit criteria:** snapshot restore via pointer-swap (no memcpy on restore path); all VMCS fields from explicit enumeration correctly saved and restored; XSAVE/XRSTOR in snapshot path verified with SIMD-heavy test (XMM register values survive restore); TSS page appears in dirty list after privilege-level switch; restore latency < 5μs for small dirty sets, < 50μs for 500 pages; 10,000+ restore cycles without state corruption or memory leaks; module loads/unloads cleanly 100 consecutive times. **If restore latency > 100μs for 500 pages, trigger §6.7 rollback evaluation.**
