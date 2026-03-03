# Task 4.2: Paper Writing

> **Phase:** Extended Campaigns + Publication + Release | **Week(s):** 36–38 | **Depends on:** [Task 4.1](task-4.1-extended-bug-campaigns.md)

## Objective

Complete and submit the paper to USENIX Security 2027 (primary) or IEEE S&P 2027 (backup), building on Background and Design sections drafted during Phase 2.

## What to Build

- Complete paper (Background/Design drafted in Phase 2 → finalise): Introduction (the overhead gap in current hypervisor-based fuzzers), Background (VMX, EPT, Intel PT, snapshot fuzzing), Design (EPT CoW snapshot engine, PT pipeline, micro-hypervisor architecture), Implementation (kernel module approach, kAFL ABI compatibility, userspace decode)
- Evaluation section structured by comparison group (see below)
- Case studies: notable bugs found with root cause analysis
- Discussion: limitations (Class C deferred, XSAVE overhead, determinism challenges), future work
- Related work in 4 categories
- Two novelty angles: overhead decomposition + determinism-first methodology

## Implementation Guidance

### Evaluation Structure

```
§6 Evaluation
  §6.1 Experimental Setup
       - Hardware: CPU model, microcode, kernel, RAM, # cores
       - Turbo boost: disabled for all benchmarks
       - Methodology: 30 runs per configuration, median + p25/p75 + min/max
       - Statistics: Mann-Whitney U for exec/sec; Kaplan-Meier for time-to-crash

  §6.2 Class A: Standalone Parser — Direct Comparisons
       - Phantom vs kAFL/Nyx (same target, both hypervisor-based snapshot)
       - Phantom vs AFL++ fork-server (same target, different execution model)
         "This comparison demonstrates Phantom's advantage over fork-based
          execution, not a component-level performance comparison."

  §6.3 Class B: Kernel Module — Hypervisor Comparisons
       - Phantom vs kAFL/Nyx (same harness, same target — apples-to-apples;
         both use hypervisor snapshot, differ in implementation)

  §6.4 Class B: Paradigm-Crossing Comparisons (clearly marked as indirect)
       - Phantom vs syzkaller (same kernel subsystem; fundamentally different
         approach — snapshot-based vs syscall-grammar-guided, different coverage)
         "This comparison measures overall bug-finding effectiveness, not
          component-level performance. The execution models are not directly
          comparable."

  §6.5 Restore Latency Per-Component Breakdown
       - Dirty-list walk, INVEPT, VMCS restore, XRSTOR contribution
       - Linear sweep: 10–5000 dirty pages; R² ≥ 0.95

  §6.6 Coverage Convergence Over Time
  §6.7 Bug Finding Comparison
  §6.8 Multi-Core Scaling Results
```

### Two Novelty Angles

From §4.2:

**1. Systematic overhead decomposition:**
> Per-layer microbenchmarks showing where time goes in kAFL/Nyx and how our design eliminates each identified overhead layer.

Present as a table:
| Overhead Layer | kAFL/Nyx Cost | Phantom Design | Phantom Cost |
|----------------|--------------|----------------|--------------|
| Snapshot restore | 100–500μs (memcpy) | EPT pointer-swap | <5μs (tiny dirty) |
| Input injection | ~5μs (QEMU path) | EPT write | <1μs |
| Coverage decode | On hot path | Userspace daemon | Off hot path |
| VM exit dispatch | KVM + QEMU | Minimal handler | Direct |

**2. Determinism-first methodology:**
> 1000/1000 identical traces as a hard gating criterion with explicit enumeration and mitigation of each non-determinism source.

Present as: "13 non-determinism sources identified, each with documented mitigation. Gating criterion: byte-identical PT trace for identical input 1000/1000 times."

### Related Work Structure (4 Categories)

From §4.2:

| Category | Papers to Cover |
|----------|----------------|
| Hypervisor-based fuzzers | kAFL (2017), Nyx (2021) — note these are **distinct systems** with different architectural choices; Hyper-Cube, KF-x, V-Shuttle, Morphuzz |
| Kernel fuzzers | syzkaller, HEALER, SyzVegas, HFL |
| Snapshot techniques | Agamotto, SnapFuzz, FirmAFL |
| Coverage mechanisms | WYCINWYC, Barbervisor |

**Important:** Separately discuss kAFL (2017) and Nyx (2021) — they are distinct systems.

### Known Limitations (§13)

From §13 in the master plan (lines 1036–1044):
- Class C (full VM/userland) not implemented — requires virtio device emulation
- XSAVE overhead (~200–400 cycles) contributes fixed cost to restore path
- Determinism challenges: some subsystems with hardware entropy may remain non-deterministic
- KVM coexistence not supported — dedicated machine required
- Nested KVM performance differs from bare metal — all performance claims require bare metal

### Future Work (§14)

From §14 in the master plan:
- Class C support via hybrid architecture (Phantom snapshots + minimal QEMU device model)
- AMD SVM support (analogous architecture using AMD-V nested page tables)
- FPGA-accelerated PT decoding for decode-throughput-bound workloads
- SmartNIC integration for line-rate network packet fuzzing (especially valuable for netfilter targets)
- Distributed mode — multiple Phantom machines coordinated by a central corpus manager
- Incremental snapshots — nested checkpoints for stateful protocol fuzzing
- Windows guest support — kernel driver fuzzing on Windows
- CXL memory integration — hardware-assisted snapshot/restore via CXL memory controllers
- PML-based hybrid dirty tracking — Fallback B from §6.7 as a first-class mode

*Note: Redqueen and eBPF-based coverage are not §14 future work items. Redqueen is listed in §4.1 as a reusable component; eBPF coverage is discussed in §6.6 design alternatives.*

### Performance Claim Guidance (§1)

From §1:
> "Nx faster than kAFL/Nyx for target class Y on hardware Z with dirty page footprint W."
> Expected range: **3–10x for kernel targets (Class B), 10–50x for standalone parsers (Class A)**.
> Speedup heavily dependent on dirty page footprint per iteration.

Do not claim a blanket multiplier. Each benchmark result is specific to hardware and target.

## Key Data Structures

```
Paper submission target:
  Primary:  USENIX Security 2027
  Backup:   IEEE S&P 2027

Responsible disclosure:
  All bugs must be reported and patched/acknowledged before paper submission.
  Patch merged or acknowledged by maintainer for every reported bug.
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `benchmarks/reproduce.sh` | All paper figures generated from this script |
| `docs/architecture.md` | Detailed design document expanded from paper |

## Reference Sections

- §1: Performance claim guidance — 3–10x Class B, 10–50x Class A, specific-not-blanket claims
- §13: Known limitations — Class C deferred, XSAVE overhead, determinism challenges
- §14: Future work — Class C hybrid, FPGA PT decode, PML, Windows

## Tests to Run

- Paper compiles within venue page limit (pass = PDF generated cleanly, no overflow)
- All figures generated from `benchmarks/reproduce.sh` (pass = no manually-produced figures in submission)
- 30-run methodology applied to all exec/sec comparisons (pass = all comparison tables show 30-run data with Mann-Whitney U statistics)
- All bugs confirmed disclosed and patched before submission (pass = patch merged or acknowledged by maintainer for every reported bug)
- Co-author review completed (pass = all co-authors have reviewed and approved final draft)

## Deliverables

Paper submitted to USENIX Security 2027 (primary) or IEEE S&P 2027 (backup).
