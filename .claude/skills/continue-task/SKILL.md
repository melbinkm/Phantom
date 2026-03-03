---
name: continue-task
description: Resume work on a Phantom task after session break or crash
user-invocable: true
argument-hint: "[task-number]"
---

# Continue Phantom Task

Parse `$ARGUMENTS` as a task number (e.g., `1.3`). If empty, scan all task files for `status: IN_PROGRESS` and prompt to choose.

## Steps

1. **Find the task file:**
   - Locate `phases/phase-{X}*/task-{X}.{Y}-*.md`
   - Read the full task file

2. **Read PHANTOM_PROGRESS marker:**
   - Find `<!-- PHANTOM_PROGRESS` block
   - Extract: `status`, `branch`, `started`, `last_activity`, `checkpoint`, `blocking`
   - If no marker: suggest `/start-task $ARGUMENTS` instead

3. **Check git state:**
   - Run `git checkout {branch}` (the branch from the marker)
   - Run `git status` — show any uncommitted changes
   - Run `git log --oneline -10` — show recent commits on the branch
   - Note any files that have been created or modified since the checkpoint

4. **Reconcile plan vs reality:**
   - Compare the checkpoint description against files that actually exist
   - Compare test results in the checkpoint against tests that currently pass
   - If reality is ahead of the checkpoint (e.g., more files exist than noted), update the checkpoint to reflect current state
   - If reality is behind (e.g., panic erased work), note what was lost

5. **Crash recovery path** (if last_activity was recent and a kdump exists):
   - Check for `/var/crash/` dumps newer than `last_activity`
   - If found, suggest: `crash /usr/lib/debug/vmlinux /var/crash/<latest>/vmcore`
   - Remind: `crash> mod -s phantom` then `crash> bt <phantom_vmx_exit_handler>`

6. **Update marker:**
   - Set `status: IN_PROGRESS`
   - Set `last_activity` to now
   - Update `checkpoint` to reflect current state

7. **Output resume brief:**
   - **Task:** `{X.Y} — {title}`
   - **Branch:** `{branch}`
   - **Last checkpoint:** what was done before the break
   - **What remains:** bullet list of incomplete steps from "What to Build"
   - **Next step:** specific first action to take
   - **Tests not yet passing:** from the task file's test list
   - **kdump status:** whether a recent crash dump was found

## Notes

- This command is safe to run multiple times — it only reads and updates the marker
- After a host panic, always run this before resuming to ensure git state is clean
- The checkpoint is only as accurate as the last manual update — encourage frequent updates
