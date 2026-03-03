---
name: phase-status
description: Show progress across all Phantom tasks and phase gates
user-invocable: true
---

# Phantom Phase Status

## Steps

1. **Query GitHub issues for task status:**
   - Run: `gh issue list --repo melbinkm/Phantom --state all --json number,title,state,labels,body --limit 50`
   - For each task, determine status from issue state and labels:
     - No issue → `PENDING`
     - Open issue with `started` label → `STARTED`
     - Open issue with `in-progress` label → `IN_PROGRESS`
     - Open issue with `blocked` label → `BLOCKED`
     - Closed issue → `COMPLETED`
   - For each phase, query by label: `gh issue list --repo melbinkm/Phantom --label phase-{X} --state all`
   - For each open issue, parse the `## Implementation Steps` checklist from the body:
     - Count total items and checked items (`- [x]` vs `- [ ]`)
     - Compute percentage: `{checked}/{total} ({percent}%)`

2. **Read phase READMEs:**
   - Read each `phases/*/README.md` for phase exit criteria

3. **Check gate conditions:**
   - **kdump/serial gate (Phase 1a entry):** Check if Task 1.1 issue is closed (COMPLETED)
   - **Determinism gate (Phase 3 entry):** Check Task 3.2 issue comments for "1000/1000 pass" evidence
   - **Performance gate (Phase 3 entry):** Check Task 1.8 issue comments for "<100μs for 500 pages" evidence
   - Gate labels: issues tagged `gate` represent blocking conditions

4. **Output status table:**

```
=== PROJECT PHANTOM STATUS ===
Current Phase: X
Date: {today}

PHASE 0: Feasibility Spike
  [STATUS] Task 0.1 — VMX Feasibility Spike

PHASE 1a: VMX Bootstrap + Basic EPT
  [STATUS] Task 1.1 — Dev Environment + VMX Bootstrap
  [STATUS] Task 1.2 — VMCS Configuration + Guest Execution
  [STATUS] Task 1.3 — Basic R/W EPT
  [STATUS] Task 1.4 — First CoW Fault + Page Pool

PHASE 1b: CoW Snapshot Engine
  [STATUS] Task 1.5 — Full CoW Engine + 2MB Splitting
  [STATUS] Task 1.6 — Snapshot/Restore Integration
  [STATUS] Task 1.7 — Correctness Testing
  [STATUS] Task 1.8 — Performance Measurement

PHASE 2: Fuzzing Pipeline
  [STATUS] Task 2.1 — Hypercall Interface
  [STATUS] Task 2.2 — Intel PT Coverage
  [STATUS] Task 2.3 — Userspace Interface + Frontend
  [STATUS] Task 2.4 — Class A Hardening + Bugs

PHASE 3: Kernel Fuzzing (Class B)
  [STATUS] Task 3.1 — Minimal Linux Guest Boot
  [STATUS] Task 3.2 — Determinism Engineering
  [STATUS] Task 3.3 — Multi-Core + Real Targets
  [STATUS] Task 3.4 — Performance Benchmarking

PHASE 4: Campaigns + Publication
  [STATUS] Task 4.1 — Extended Bug Campaigns
  [STATUS] Task 4.2 — Paper Writing
  [STATUS] Task 4.3 — Open-Source Release

=== GATE CONDITIONS ===
  [PASS/FAIL/PENDING] kdump + serial console verified (Phase 1a entry)
  [PASS/FAIL/PENDING] Determinism 1000/1000 (Phase 3 entry)
  [PASS/FAIL/PENDING] Performance <100μs / 500 pages (Phase 3 entry)
```

Status codes: `PENDING` (no issue) | `STARTED` | `IN_PROGRESS N/T P%` | `BLOCKED` | `COMPLETED`

- For `IN_PROGRESS` tasks, append checklist progress inline: `[IN_PROGRESS 3/7 43%] Task 1.3 — Basic R/W EPT`
- If a task shows `BLOCKED`, fetch the issue and display the blocking reason from the latest comment
- After the main table, add a detail section for any in-progress tasks:

```
=== IN-PROGRESS TASK DETAIL ===
Task {X.Y} — {title}  ({checked}/{total} steps, {percent}%)
  Remaining steps:
    [ ] {unchecked step 1}
    [ ] {unchecked step 2}
    ...
  Labels: {label list}
  Issue: melbinkm/Phantom#{number}
```
