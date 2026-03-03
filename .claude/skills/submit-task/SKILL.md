---
name: submit-task
description: Complete a task — verify tests pass, commit, push, create PR
user-invocable: true
argument-hint: "[task-number]"
---

# Submit Phantom Task

Parse `$ARGUMENTS` as a task number (e.g., `1.3`). If empty, check open GitHub issues with the `in-progress` label: `gh issue list --repo melbinkm/Phantom --label in-progress`.

## Steps

1. **Find the task file and read test criteria:**
   - Locate `phases/phase-{X}*/task-{X}.{Y}-*.md`
   - Extract the full "Tests to Run" section
   - Extract the "Exit Criteria" section; if absent, use the "Deliverables" section

2. **Verify all tests pass:**
   - Run each test from the "Tests to Run" section
   - For each test: show pass/fail with evidence
   - If any test fails: stop and report which test failed and why. Do NOT proceed to commit.
   - If all pass: continue

3. **Check git state:**
   - Run `git status` — ensure no unexpected files are staged
   - Run `git diff --stat HEAD` — show what changed
   - Verify we are on the task branch (`git branch --show-current`)

4. **Commit:**
   ```bash
   # Stage source files non-interactively (never use git add -p or -i)
   git add kernel/ tests/ benchmarks/ userspace/ Makefile phases/ scripts/ docs/ .claude/
   git diff --cached --stat   # Show what is staged
   git commit -m "task-{X.Y}: {task title}

   - {brief description of what was built}
   - Tests: {count} passing

   Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
   ```

5. **Push:**
   ```bash
   git push -u origin task-{X.Y}-{slug}
   ```

6. **Close GitHub issue:**
   - Find the open issue for this task:
     `gh issue list --repo melbinkm/Phantom --search "Task {X.Y}:" --state open --json number`
   - Post a closing comment:
   ```bash
   gh issue comment {number} --repo melbinkm/Phantom --body "## Completed

   **Status:** COMPLETED
   **All tests passing:** {count} tests
   **Submitted:** {now}
   **Commit:** $(git rev-parse --short HEAD)
   **Branch:** task-{X.Y}-{slug}"
   ```
   - Close the issue:
   ```bash
   gh issue close {number} --repo melbinkm/Phantom
   ```

7. **Create Pull Request:**
   ```bash
   gh pr create \
     --title "task-{X.Y}: {task title}" \
     --body "## Summary

   {task objective, 2–3 sentences}

   ## What was built
   {bullet list of main deliverables}

   ## Tests
   {list of tests with pass/fail results}

   ## Exit criteria
   {paste exit criteria from task file, mark each ✓}

   Closes #{issue-number}

   🤖 Generated with Claude Code"
   ```

8. **Output confirmation:**
   - PR URL and summary of what was submitted

9. **Phase gate check** (only if this is the LAST task in a phase):
   - Phase-to-last-task: 0→0.1, 1a→1.4, 1b→1.8, 2→2.4, 3→3.4, 4→4.3
   - Verify all phase tasks are closed:
     `gh issue list --repo melbinkm/Phantom --label phase-{X} --state open`
   - Check gate conditions from CLAUDE.md "Active Gates":
     - Phase 1b exit: search task 1.8 issue for performance data
     - Phase 3 exit: search task 3.2 issue for "1000/1000" determinism
   - Post `## Phase Gate Check` comment on this issue
   - If gate FAILS: STOP. Require manual intervention.
   - If gate PASSES: phase state is recorded via closed GitHub issues — no file update needed.

10. **Auto-chain to next task:**
    - Task order: 0.1→1.1→1.2→1.3→1.4→1.5→1.6→1.7→1.8→2.1→2.2→2.3→2.4→3.1→3.2→3.3→3.4→4.1→4.2→4.3
    - If phase gate just FAILED: STOP
    - If task 4.3 (final): "Project Phantom complete." STOP
    - Otherwise: execute `/start-task {next}`

## Notes

- Never commit if any test is failing
- Never force-push to main
- If the PR fails to create (no GitHub auth): commit and push, then provide the gh command for the user to run manually
- Phase state is derived from GitHub issue state (closed issues = complete) — no CLAUDE.md update needed
- Auto-chaining respects phase gates — cannot skip to next phase if gate fails
- Task ordering is strictly linear (matches "Depends On" in phase READMEs)
