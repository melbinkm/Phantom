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
   - Extract the "Exit Criteria" section

2. **Verify all tests pass:**
   - Run each test from the "Tests to Run" section
   - For each test: show pass/fail with evidence
   - If any test fails: stop and report which test failed and why. Do NOT proceed to commit.
   - If all pass: continue

3. **Check git state:**
   - Run `git status` — ensure no unexpected files are staged
   - Run `git diff --stat HEAD` — show what changed
   - Verify we are on the task branch (`git branch --show-current`)

4. **Close GitHub issue:**
   - Find the open issue for this task:
     `gh issue list --repo melbinkm/Phantom --search "Task {X.Y}:" --state open --json number`
   - Post a closing comment:
   ```bash
   gh issue comment {number} --repo melbinkm/Phantom --body "## Completed

   **Status:** COMPLETED
   **All tests passing:** {count} tests
   **Submitted:** {now}

   PR: (will be linked after push)"
   ```
   - Close the issue:
   ```bash
   gh issue close {number} --repo melbinkm/Phantom
   ```

5. **Commit:**
   ```bash
   git add -p   # Stage changes interactively, or stage specific files
   git commit -m "task-{X.Y}: {task title}

   - {brief description of what was built}
   - Tests: {count} passing

   Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
   ```

6. **Push:**
   ```bash
   git push -u origin task-{X.Y}-{slug}
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
   - PR URL
   - Summary of what was submitted
   - Suggest next task (check CLAUDE.md CURRENT_PHASE and next unstarted task)

## Notes

- Never commit if any test is failing
- Never force-push to main
- If the PR fails to create (no GitHub auth): commit and push, then provide the gh command for the user to run manually
- After submission, update `CURRENT_PHASE` in CLAUDE.md if this task completes a phase
