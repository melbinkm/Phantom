---
name: continue-task
description: Resume work on a Phantom task after session break or crash
user-invocable: true
argument-hint: "[task-number]"
---

# Continue Phantom Task

Parse `$ARGUMENTS` as a task number (e.g., `1.3`). If empty, query `gh issue list --repo melbinkm/Phantom --label in-progress` and prompt to choose.

## Steps

1. **Find the task file:**
   - Locate `phases/phase-{X}*/task-{X}.{Y}-*.md`
   - Read the full task file

2. **Read GitHub issue:**
   - Run: `gh issue list --repo melbinkm/Phantom --search "Task {X.Y}:" --state open --json number,title,labels,body`
   - Fetch issue comments: `gh issue view {number} --repo melbinkm/Phantom --comments`
   - Extract from body: branch name, objective
   - Extract from body: `## Implementation Steps` checklist — count checked vs total (e.g., `3/7`)
   - Extract from latest comment: last checkpoint, blocking issues
   - If no open issue exists: suggest `/start-task $ARGUMENTS` instead

3. **Check git state:**
   - Run `git checkout {branch}` (the branch from the issue body)
   - Run `git status` — show any uncommitted changes
   - Run `git log --oneline -10` — show recent commits on the branch
   - Note any files that have been created or modified since the last checkpoint

4. **Reconcile plan vs reality:**
   - Compare the checkpoint description against files that actually exist
   - Compare test results in the checkpoint against tests that currently pass
   - If reality is ahead of the checkpoint (e.g., more files exist than noted), update accordingly
   - If reality is behind (e.g., panic erased work), note what was lost
   - If a `## Implementation Steps` checklist is present in the issue body, cross-reference each item against actual file state:
     - Check off items where code evidence exists (file created, function present, test passing)
     - Uncheck items that were marked done but have no code evidence (phantom completions)
     - Apply the updated checklist: `gh issue edit {number} --repo melbinkm/Phantom --body "{updated body}"`

5. **Crash recovery path** (if last comment was recent and a kdump exists):
   - Check for `/var/crash/` dumps newer than the last issue comment timestamp
   - If found, suggest: `crash /usr/lib/debug/vmlinux /var/crash/<latest>/vmcore`
   - Remind: `crash> mod -s phantom` then `crash> bt <phantom_vmx_exit_handler>`

6. **Post checkpoint comment:**
   - Run:
   ```bash
   gh issue comment {number} --repo melbinkm/Phantom --body "## Resuming

   **Status:** IN_PROGRESS
   **Branch:** \`{branch}\`
   **Resumed:** {now}

   {summary of current state and what remains}"
   ```
   - Also add the `in-progress` label if not already present:
   ```bash
   gh issue edit {number} --repo melbinkm/Phantom --add-label "in-progress" --remove-label "started"
   ```

7. **Output resume brief:**
   - **Task:** `{X.Y} — {title}`
   - **Issue:** `melbinkm/Phantom#{number}`
   - **Branch:** `{branch}`
   - **Checklist progress:** `{checked}/{total}` (from `## Implementation Steps` in issue body)
   - **Last checkpoint:** what was done before the break (from latest issue comment)
   - **What remains:** bullet list of incomplete steps from "What to Build"
   - **Next step:** specific first action to take
   - **Tests not yet passing:** from the task file's test list
   - **kdump status:** whether a recent crash dump was found

## Notes

- This command is safe to run multiple times — it reads and comments on the issue
- After a host panic, always run this before resuming to ensure git state is clean
- The checkpoint is only as accurate as the last manual update — encourage frequent comments
