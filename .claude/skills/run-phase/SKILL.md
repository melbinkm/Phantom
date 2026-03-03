---
name: run-phase
description: Autonomously execute all tasks in a Phantom phase — start → plan → implement → test → submit → next
user-invocable: true
argument-hint: "<phase-number>"
---

# Run Phase Autonomously

Parse `$ARGUMENTS` as a phase number (e.g., `0`, `1a`, `1b`, `2`, `3`, `4`).

This skill orchestrates an entire phase autonomously: for each task in the phase, it starts
or resumes the task, plans the implementation, delegates coding and testing, iterates on
failures, and submits — then moves to the next task. Phase gates are checked at phase
boundaries before advancing.

---

## Step 1: Validate Phase and Check Prerequisites

1. **Confirm the phase exists** in CLAUDE.md and matches `$ARGUMENTS`.
2. **Check prior phases are complete:**
   - Phase 1a requires phase 0 complete
   - Phase 1b requires phase 1a complete
   - Phase 2+ requires all prior phases complete
   ```bash
   gh issue list --repo melbinkm/Phantom --label phase-{prior} --state open
   ```
   If any prior-phase tasks are still open: STOP. Report which tasks are blocking.
3. **Check phase entry gates** from CLAUDE.md "Active Gates":
   - Phase 1a entry: kdump/crash observability gate must be PASSED
   - Phase 3 entry: Determinism gate and Performance (Class A) gate must both be PASSED
   If a gate has not passed: STOP. Report which gate is blocking.
4. **Identify tasks in this phase** (from CLAUDE.md phase table + task files):
   ```
   Phase 0:  0.1
   Phase 1a: 1.1, 1.2, 1.3, 1.4
   Phase 1b: 1.5, 1.6, 1.7, 1.8
   Phase 2:  2.1, 2.2, 2.3, 2.4
   Phase 3:  3.1, 3.2, 3.3, 3.4
   Phase 4:  4.1, 4.2, 4.3
   ```

---

## Step 2: Find the First Incomplete Task

For each task in the phase (in order):
```bash
gh issue list --repo melbinkm/Phantom --search "Task {X.Y}:" --state closed --json number,title
```
- If issue is **closed**: task is complete — skip to next.
- If issue is **open** with `in-progress` label: task is in progress — resume it (go to Step 3).
- If issue is **open** with `started` label or no issue exists: start fresh (go to Step 3).
- If issue is **open** with `blocked` label: STOP. Report the blocking issue.

If ALL tasks in the phase are closed: go to Step 4 (Phase Completion).

---

## Step 3: Task Loop

For each incomplete task `{X.Y}`, repeat this loop:

### 3a. Start or Resume

- **No issue / not started:** run `/start-task {X.Y}`
  - Creates GitHub issue, branch, implementation checklist
- **In-progress issue exists:** run `/continue-task {X.Y}`
  - Reads last checkpoint from issue comments
  - Runs cross-task knowledge search for prior design decisions and crash patterns
  - Checks git state and reconciles with issue checklist

### 3b. Plan

Delegate to `task-planner` agent:
- Read task file + master plan sections
- Read current GitHub issue for `## Adjustment` and `## Design Decision` context
- Search closed phase issues for prior lessons
- Output: function list, struct definitions, dependency order, risk factors, test strategy

Review the plan. If there is a `## Adjustment` on the issue indicating the plan changed,
incorporate those changes before delegating to `kernel-dev`.

### 3c. Implement

Delegate to `kernel-dev` agent:
- Reads the task-planner's plan and the GitHub issue
- Writes code following phantom conventions (GPL header, phantom_ prefix, goto-cleanup, etc.)
- Posts `## Checkpoint` comments after each logical unit of work
- Posts `## Design Decision` comments for non-trivial choices
- Posts `## Checkpoint` comment BEFORE any dangerous VMX operation, then proceeds

**Checkpoint before dangerous operations:** If the implementation involves:
- First VMXON on a physical core
- New VMCS fields being written for the first time
- EPT structure changes that could cause TLB corruption
Then kernel-dev must commit + post checkpoint first.

### 3d. Test

Run `/deploy-test` (which posts `## Test Results` to the issue automatically):
- Rsync → build → deploy (guest or server per phase) → run tests → post results

**Crash handling:**
- QEMU guest crash: `tester` agent captures serial log, posts `## Crash Report`, restarts guest
- Host server crash: server reboots (~2 min), `tester` checks kdump, posts `## Crash Report`

### 3e. Iterate on Failures

Initialize failure counter: `FAILURES=0`, `CRASHES_WITHOUT_PROGRESS=0`

If any test fails:
1. Increment `FAILURES`
2. If `FAILURES >= 5`: mark issue `blocked` and STOP. Post:
   ```
   ## Blocked
   **Reason:** 5 test-fix iterations exhausted without all tests passing.
   **Last failure:** {test name} — {brief diagnosis}
   **Manual intervention required.**
   ```
3. Read the `## Test Results` and `## Crash Report` from the issue comments
4. Search past issues for similar crash patterns (using the search in `tester` agent)
5. Delegate fix to `kernel-dev` agent with crash report context
6. Re-run `/deploy-test`
7. If the same crash repeats without any new code committed: increment `CRASHES_WITHOUT_PROGRESS`
8. If `CRASHES_WITHOUT_PROGRESS >= 3`: STOP. Mark blocked. Require manual intervention.
9. Loop back to step 1 of this section

### 3f. Sync and Submit

When all tests pass:
1. Run `/sync-progress {X.Y}` — reconcile git state with issue checklist
2. Run `/submit-task {X.Y}` — which will:
   - Verify tests, commit, push, create PR
   - Check phase gate if this is the last task in the phase
   - Auto-chain to the next task (which is the next iteration of this loop)

---

## Step 4: Phase Completion

When all tasks in the phase are closed:

1. **Verify phase gate** (for phases with exit gates):
   - **Phase 1b exit:** Search task 1.8 issue for `## Test Results` with `<100μs` restore time
   - **Phase 3 exit:** Search task 3.2 issue for `## Test Results` with `1000/1000` determinism
   ```bash
   gh issue list --repo melbinkm/Phantom --label phase-{X} --state closed --json number,title | \
     jq -r '.[].number' | while read n; do
       gh issue view "$n" --repo melbinkm/Phantom --comments | grep "## Test Results"
     done
   ```

2. **Post `## Phase Gate Check`** on the last task's issue:
   ```
   ## Phase Gate Check
   **Phase:** {X}  **Gate:** {gate name}
   **Result:** PASS | FAIL
   **Evidence:** {data from test results or "N/A — no gate for this phase"}
   ```

3. **If gate PASSES (or no gate):**
   - Update `CURRENT_PHASE` in CLAUDE.md to the next phase
   - Output phase completion summary:
     ```
     Phase {X} complete. {N} tasks submitted.
     Tasks: {list of task numbers}
     PRs: {list of PR URLs}
     Next: /run-phase {next-phase}
     ```

4. **If gate FAILS:** STOP. Output:
   ```
   Phase {X} BLOCKED at gate: {gate name}
   Condition: {condition from CLAUDE.md}
   Current data: {what was found in issues}
   Required: manual investigation and gate re-verification
   ```

---

## Guardrails

| Condition | Action |
|-----------|--------|
| Prior phase incomplete | STOP at Step 1 |
| Phase entry gate not passed | STOP at Step 1 |
| Task marked `blocked` | STOP, report to user |
| 5 test-fix iterations exhausted | Mark `blocked`, STOP |
| 3 crashes without new code | Mark `blocked`, STOP |
| Phase exit gate fails | STOP, require manual gate check |
| Task 4.3 submitted | "Project Phantom complete." STOP |

---

## Resumability

Re-running `/run-phase {X}` is safe:
- Step 2 skips closed issues (completed tasks are not re-run)
- If a task has an `in-progress` issue: `/continue-task` resumes from last checkpoint
- If a task has a `blocked` label: STOP and report (do not silently skip)
- Phase gate check is re-evaluated on each run

---

## Notes

- This skill delegates all code writing to `kernel-dev` and all testing to `tester`/`deploy-test`
- GitHub issues are the source of truth for task state — always read them before acting
- The failure counter resets for each new task (5 iterations per task, not per phase)
- For Phase 0–1 tests: deploy target is QEMU guest; for Phase 2+: bare-metal server
- Benchmark turbo boost disabling is handled inside `/deploy-test`
