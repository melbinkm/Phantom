# Phase 2: Fuzzing Pipeline (Weeks 13–20)

> Part of [Project Phantom Development Plan](../../project-phantom-dev-plan-v2.md)

## Goal

Complete fuzzing loop with coverage feedback, frontend integration, and a real bug found on a Class A target. Includes 1-week buffer after Phase 1.

## Notes

- **Buffer — Week 13:** Reserved for completing Phase 1b items that slip. If Phase 1b completes on time, use Week 13 for hardening and early Phase 2 setup (environment prep, kAFL ABI study).
- **Paper writing starts here:** Start drafting paper Background and Design sections during Weeks 15–20 while implementation is fresh. Do not defer all writing to Phase 4.

## Tasks

| Task | Title | Week(s) | Depends On |
|------|-------|---------|------------|
| [2.1](task-2.1-hypercall-interface.md) | Hypercall Interface (kAFL/Nyx ABI) | 14–15 | Task 1.8 |
| [2.2](task-2.2-intel-pt-coverage.md) | Intel PT Coverage | 15–16 | Task 2.1 |
| [2.3](task-2.3-userspace-interface-frontend.md) | Userspace Interface + Frontend Integration | 17–18 | Task 2.2 |
| [2.4](task-2.4-class-a-hardening-bugs.md) | Class A Hardening + First Bug Campaign | 19–20 | Task 2.3 |

## Phase Exit Criteria

End-to-end fuzzing with AFL++ and kAFL frontends; coverage bitmap correctly tracks guest execution (8 input combinations × 3 branch points produce 8 distinct bitmap entries); PT decode running in userspace, double-buffered with eventfd notification; Class A throughput > 50k exec/sec on real parser targets; at least 1 real crash found in an unmodified real-world target; 24-hour stability test passed; **EPT isolation verified** (instance A write not visible to instance B); paper Background and Design sections drafted.
