---
name: sync-progress
description: Reconcile planned vs actual implementation progress ("reality wins")
user-invocable: true
argument-hint: "[task-number]"
---

# Sync Phantom Task Progress

Parse `$ARGUMENTS` as an optional task number (e.g., `1.3`). If empty, target the open issue with the `in-progress` label.

## Steps

1. **Find target issue:**
   - If `$ARGUMENTS` is provided:
     - Run: `gh issue list --repo melbinkm/Phantom --search "Task {X.Y}:" --state open --json number,title,body,labels`
   - If `$ARGUMENTS` is empty:
     - Run: `gh issue list --repo melbinkm/Phantom --label in-progress --json number,title,body,labels`
   - Fetch full comments: `gh issue view {number} --repo melbinkm/Phantom --comments`
   - Parse `## Implementation Steps` checklist from issue body
   - If no checklist exists: output a warning and suggest running `/start-task` to initialise one; stop here

2. **Read planned state:**
   - Parse each line of the `## Implementation Steps` checklist from the issue body
   - Record each item: text label, currently-checked state (`- [x]` vs `- [ ]`)
   - Read the latest `## Checkpoint` or `## Resuming` comment for additional context on what was last confirmed done

3. **Read actual state:**
   - Run: `git log main..HEAD --oneline` to see commits on this task's branch
   - Run: `git diff --name-only main..HEAD` to see all changed files
   - For each checklist item, look for code evidence: file existence, key function/struct definitions, passing test output in recent comments
   - Run: `git stash list` to detect stashed work that may not be committed yet

4. **Compare planned vs actual:**
   For each checklist item, classify as one of:
   - `DONE` — code evidence exists (file created, function implemented, relevant test passing)
   - `PARTIAL` — some code exists but the item is incomplete (e.g., file present but missing key symbols)
   - `NOT_STARTED` — no code evidence found for this step
   - `DIVERGED` — implementation exists but differs significantly from the checklist description

5. **Post sync comment:**
   - Run:
   ```bash
   gh issue comment {number} --repo melbinkm/Phantom --body "## Progress Sync

   **Synced:** {now}
   **Branch:** \`{branch}\`
   **Commits on branch:** {N} commit(s)

   | Step | Status | Evidence |
   |------|--------|----------|
   | {step 1 text} | DONE/PARTIAL/NOT_STARTED/DIVERGED | {file or function found, or 'none'} |
   | {step 2 text} | ... | ... |

   **Summary:** {checked}/{total} steps complete ({percent}%)

   {If any DIVERGED items: explain discrepancy and whether the divergence is intentional or needs /adjust}"
   ```

6. **Update issue body checklist ("reality wins"):**
   - Items classified `DONE` → ensure checked (`- [x]`)
   - Items classified `NOT_STARTED` → ensure unchecked (`- [ ]`)
   - Items classified `PARTIAL` → leave unchecked (`- [ ]`); the comment provides detail
   - Items classified `DIVERGED` → leave unchecked (`- [ ]`); use `/adjust` to document the change formally
   - Apply the update:
   ```bash
   gh issue edit {number} --repo melbinkm/Phantom --body "{updated body with reconciled checklist}"
   ```

7. **Output sync summary:**
   - **Task:** `{X.Y} — {title}`
   - **Issue:** `melbinkm/Phantom#{number}`
   - **Progress:** `{checked}/{total} ({percent}%)`
   - **DONE:** bullet list of completed steps
   - **PARTIAL:** bullet list of partially-done steps
   - **NOT_STARTED:** bullet list of not-started steps
   - **DIVERGED:** bullet list of diverged steps with one-line explanation each
   - **Next step:** the first uncompleted item in the checklist

## Notes

- "Reality wins" — git state always takes precedence over checkbox state; never check off an item just because it was planned
- Run after any significant burst of implementation work to keep the checklist honest
- `/continue-task` runs a lightweight version of this reconciliation at session resume time
- If many items are DIVERGED, run `/adjust` to formally record the plan change and update the checklist in one structured operation
