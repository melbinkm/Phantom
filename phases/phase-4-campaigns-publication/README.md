# Phase 4: Extended Campaigns + Publication + Release (Weeks 31–40)

> Part of [Project Phantom Development Plan](../../project-phantom-dev-plan-v2.md)

## Goal

Extended bug campaigns (moved from Phase 3 for depth), paper writing, CVEs, open-source release. Includes 2-week buffer after Phase 3.

## Notes

- **Paper writing starts during Phase 2** (not Phase 4): Background and Design sections should be drafted during Phase 2 (Weeks 15–20) while implementation is fresh. Do not defer all writing to Phase 4.
- **Buffer — Weeks 31–32:** Reserved for completing Phase 3 items that slip, or for beginning Phase 4 campaign setup while Phase 3 benchmarks are still running.

## Tasks

| Task | Title | Week(s) | Depends On |
|------|-------|---------|------------|
| [4.1](task-4.1-extended-bug-campaigns.md) | Extended Bug Campaigns | 33–35 | Task 3.4 |
| [4.2](task-4.2-paper-writing.md) | Paper Writing | 36–38 | Task 4.1 |
| [4.3](task-4.3-open-source-release.md) | Open-Source Release + Artifact Evaluation | 39–40 | Task 4.2 |

## Cross-Cutting References

- [Appendix A: Error Handling and Recovery Strategy](../appendices/appendix-a-error-handling.md)
- [Appendix B: Debugging and Observability Tooling](../appendices/appendix-b-debugging-tooling.md)

## Phase Exit Criteria

At least 5 bugs in real-world kernel targets (ideally with CVEs assigned); paper submitted to top-tier venue (USENIX Security 2027 or IEEE S&P 2027); public GitHub repository with documentation; CI pipeline passing (includes sparse + smatch static analysis); artifact evaluation badges targeted (AEF + AERR); at least one external user has reproduced results (beta tester).
