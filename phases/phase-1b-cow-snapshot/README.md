# Phase 1b: CoW Engine + Snapshot/Restore (Weeks 7–12)

> Part of [Project Phantom Development Plan](../../project-phantom-dev-plan-v2.md)

## Goal

Full snapshot/restore engine using EPT CoW. Correctness-verified and performance-benchmarked.

## Notes

- Assume 30% overhead throughout Phase 1 for host kernel panic debugging (nested KVM, kdump analysis, VMCS debugging). This overhead is already budgeted in the 12-week Phase 1 timeline.
- If restore latency >100μs for 500 pages at end of Phase 1b, trigger §6.7 rollback evaluation (Fallback A: PML dirty tracking + memcpy restore).

## Tasks

| Task | Title | Week(s) | Depends On |
|------|-------|---------|------------|
| [1.5](task-1.5-full-cow-engine-2mb-splitting.md) | Full CoW Engine with 2MB Splitting | 7–8 | Task 1.4 |
| [1.6](task-1.6-snapshot-restore-integration.md) | Snapshot/Restore Integration | 9–10 | Task 1.5 |
| [1.7](task-1.7-correctness-testing.md) | Correctness Testing | 11 | Task 1.6 |
| [1.8](task-1.8-performance-measurement.md) | Performance Measurement | 12 | Task 1.7 |

## Phase Exit Criteria

Snapshot restore via pointer-swap (no memcpy on restore path); all VMCS fields from explicit enumeration correctly saved and restored; XSAVE/XRSTOR in snapshot path verified with SIMD-heavy test (XMM register values survive restore); TSS page appears in dirty list after privilege-level switch; restore latency < 5μs for small dirty sets, < 50μs for 500 pages; 10,000+ restore cycles without state corruption or memory leaks; module loads/unloads cleanly 100 consecutive times. **If restore latency > 100μs for 500 pages, trigger §6.7 rollback evaluation.**
