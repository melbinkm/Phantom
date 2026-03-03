# Task 3.4: Performance Benchmarking

> **Phase:** Kernel Fuzzing — Class B | **Week(s):** 30 | **Depends on:** [Task 3.3](task-3.3-multi-core-real-targets.md)

## Objective

Produce a statistically rigorous performance comparison against kAFL/Nyx using 30 runs, Mann-Whitney U test, and Kaplan-Meier survival analysis, all reproducible via `benchmarks/reproduce.sh`.

## What to Build

- Head-to-head comparison vs kAFL/Nyx: same target, same hardware, same mutation engine; 30 runs per configuration; report median + p25/p75 + min/max; Mann-Whitney U test for exec/sec comparisons (report U statistic and p-value); survival analysis (Kaplan-Meier estimator) for time-to-first-crash; disable turbo boost; report CPU model, microcode revision, kernel version
- Per-component microbenchmark breakdown: restore latency sweep (dirty page count 10–5000), VM exit latency per exit reason distribution, input injection latency, XRSTOR overhead contribution to restore latency, NUMA-local vs NUMA-remote memory comparison
- `benchmarks/reproduce.sh` script: pre-built VM image, expected result ranges, reproducible from scratch on a clean machine
- All benchmarks run on bare metal (not nested KVM)

## Implementation Guidance

### Bare-Metal Hardware Requirements (§7)

| Item | Spec | Purpose |
|------|------|---------|
| CPU | Intel Ice Lake or newer (Xeon Scalable) | PML support, latest PT features, high core count |
| RAM | 256GB+ DDR5 | Parallel instance memory; NUMA topology |
| Cores | 16+ physical cores (2 NUMA nodes preferred) | Multi-core scaling + NUMA benchmarks |
| Storage | 2TB NVMe | Corpus, traces, results |
| Access | Dedicated, no other workloads | Clean benchmark environment |

**Disable turbo boost before all benchmarks:**
```bash
# Intel turbo boost disable
echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
# Or via cpufreq
cpupower frequency-set -g performance
```

### Statistical Methodology

From §3.4 and §4.2 paper evaluation:

**30-run methodology:**
```bash
# Run 30 independent experiments per configuration
for i in $(seq 1 30); do
    phantom-ctl fuzz --target libxml2 --duration 3600 --seed $i \
        --output results/phantom_run_$i.json
    kafl fuzz --target libxml2 --duration 3600 --seed $i \
        --output results/kafl_run_$i.json
done

# Compute statistics
python3 scripts/analyze.py --phantom results/phantom_*.json \
                           --kafl results/kafl_*.json
```

**Report format:**
- Median, p25/p75, min/max for all metrics
- Mann-Whitney U test for exec/sec differences (report U statistic and p-value, p < 0.05 required)
- Kaplan-Meier survival analysis for time-to-first-crash

```python
from scipy.stats import mannwhitneyu
from lifelines import KaplanMeierFitter

# Mann-Whitney U test
u_stat, p_value = mannwhitneyu(phantom_execs, kafl_execs, alternative='two-sided')
print(f"U={u_stat:.0f}, p={p_value:.4f}")
# Must report both — not just p-value

# Kaplan-Meier for time-to-first-crash
kmf = KaplanMeierFitter()
kmf.fit(durations=time_to_crash, event_observed=found_crash)
```

### Performance Claim Guidance (§1)

From §1:
> Benchmarks will report "Nx faster than kAFL/Nyx for target class Y on hardware Z with dirty page footprint W." Expected range: **3–10x for kernel targets (Class B), 10–50x for standalone parsers (Class A)**, with speedup heavily dependent on dirty page footprint per iteration.

Do not claim a blanket multiplier. Report the specific hardware, target, and dirty page count for each measurement.

### Per-Component Microbenchmark Breakdown

Extend the restore latency sweep from Task 1.8 to the full 10–5000 dirty page range:

| Component | Measurement Method | Expected Contribution |
|-----------|-------------------|----------------------|
| Dirty-list walk | `rdtsc` bracket | Linear in dirty count |
| INVEPT (single-context) | `rdtsc` bracket | ~100–500 cycles (constant) |
| VMCS restore | `rdtsc` bracket | ~50–200 cycles (constant) |
| XRSTOR | `rdtsc` bracket | ~200–400 cycles (constant) |
| Total restore | `rdtsc` bracket | Linear + constant offset |
| VM exit latency | `rdtsc` from VMCALL to handler | ~100–500 cycles |
| Input injection latency | `rdtsc` from mmap write to VMRESUME | <1μs target |

### `benchmarks/reproduce.sh` Requirements

From §3.4 and §4.3:

```bash
#!/bin/bash
# benchmarks/reproduce.sh — end-to-end benchmark reproduction
# Usage: ./reproduce.sh [--target libxml2|nftables] [--cores N]
#
# Requirements:
#   - Bare-metal machine with Intel Ice Lake+ CPU
#   - 256GB+ RAM
#   - Phantom and kAFL installed
#   - Turbo boost disabled
#
# Expected result ranges (hardware class: 16-core Xeon Scalable):
#   Phantom Class A exec/sec: 50,000 – 500,000
#   Phantom Class B exec/sec: 30,000 – 100,000
#   kAFL Class B exec/sec:    10,000 – 20,000
#   Expected speedup Class B: 3x – 10x
```

### Benchmarks Path Layout (§10)

```
benchmarks/
├── scripts/                  # Automated benchmark runners
├── reproduce.sh              # End-to-end reproduction with expected ranges
├── results/                  # Published results
└── comparison/               # kAFL/Nyx comparison scripts
```

## Key Data Structures

```c
/* Benchmark result record */
struct phantom_bench_result {
    char    target[64];
    char    hardware[128];   /* CPU model + microcode + kernel version */
    u32     core_count;
    u64     exec_per_sec_samples[30];  /* 30-run methodology */
    u64     time_to_crash_ms[30];      /* For Kaplan-Meier */
    double  u_statistic;
    double  p_value;
    double  restore_latency_p95_us;
    u32     dirty_pages_per_iter;
};
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `benchmarks/reproduce.sh` | End-to-end reproduction script |
| `benchmarks/scripts/` | Per-component microbenchmark runners |
| `tests/performance/bench_restore_latency.sh` | Extended 10–5000 page sweep |

## Reference Sections

- §7: Bare-metal hardware requirements — Ice Lake+ Xeon, 256GB DDR5, 16+ cores, dedicated machine
- §1: Performance claim guidance — "Nx faster for target Y on hardware Z"; 3–10x Class B expected
- §10: Benchmarks path layout — `benchmarks/reproduce.sh`, results/, comparison/
- §7: NUMA benchmark requirement — NUMA locality impact figure for paper

## Tests to Run

- 30 runs per configuration completed with Mann-Whitney U test computed for exec/sec differences (pass = 30 runs complete, U statistic and p-value reported; the p-value is reported faithfully regardless of value — achieving p < 0.05 is expected but is NOT a hard pass criterion for this task)
- Restore latency sweep produces a linear curve from 10 to 5000 dirty pages (pass = R² ≥ 0.95 on linear fit)
- `benchmarks/reproduce.sh` works on a clean machine (pass = script completes, results fall within expected ranges)
- All benchmarks confirmed to run on bare metal (pass = hardware confirmation documented in results)

## Deliverables

Statistically sound benchmark report with 30-run methodology; reproducible via `benchmarks/reproduce.sh`.

## Exit Criteria

**Phase 3 exit criteria:** kernel module fuzzing (Class B) deterministic 1000/1000; multi-core scaling ≥ 0.85× per core up to 8 cores; **at least 1 real bug found in a kernel subsystem during Phase 3 campaigns**; head-to-head benchmark vs kAFL with statistically sound methodology (30 runs, Mann-Whitney U); 72-hour stability test passed; all results reproducible via `benchmarks/reproduce.sh`.
