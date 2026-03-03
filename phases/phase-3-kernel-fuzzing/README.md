# Phase 3: Kernel Fuzzing — Class B (Weeks 21–30)

> Part of [Project Phantom Development Plan](../../project-phantom-dev-plan-v2.md)

## Goal

Boot minimal Linux kernel as guest, fuzz kernel subsystems, achieve deterministic execution, multi-core scaling. Includes 1-week buffer after Phase 2.

## Notes

- Determinism engineering is expanded to 4–5 weeks and multi-core to 2–3 weeks compared to v2.0 estimate, reflecting the true complexity of these components.
- **Buffer — Week 21:** Reserved for completing Phase 2 items that slip. If Phase 2 completes on time, use for Class B guest kernel preparation (defconfig, boot_params structure research).
- **GATE:** Do not proceed to Task 3.3 until 1000/1000 determinism passes in Task 3.2.

## Tasks

| Task | Title | Week(s) | Depends On |
|------|-------|---------|------------|
| [3.1](task-3.1-minimal-linux-guest-boot.md) | Minimal Linux Guest Boot | 22–23 | Task 2.4 |
| [3.2](task-3.2-determinism-engineering.md) | Determinism Engineering | 24–27 | Task 3.1 |
| [3.3](task-3.3-multi-core-real-targets.md) | Multi-Core + Real Kernel Targets | 28–29 | Task 3.2 (GATE) |
| [3.4](task-3.4-performance-benchmarking.md) | Performance Benchmarking | 30 | Task 3.3 |

## Phase Exit Criteria

Kernel module fuzzing (Class B) deterministic 1000/1000; multi-core scaling ≥ 0.85× per core up to 8 cores; **at least 1 real bug found in a kernel subsystem during Phase 3 campaigns**; head-to-head benchmark vs kAFL with statistically sound methodology (30 runs, Mann-Whitney U); 72-hour stability test passed; all results reproducible via `benchmarks/reproduce.sh`.
