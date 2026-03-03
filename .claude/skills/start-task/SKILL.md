---
name: start-task
description: Begin working on a Phantom task by number (e.g., /start-task 1.3)
user-invocable: true
argument-hint: "[task-number]"
---

# Start Phantom Task

Parse `$ARGUMENTS` as a task number (e.g., `1.3`, `0.1`, `2.2`).

## Steps

1. **Identify the task file:**
   - Extract phase number X and task number Y from `$ARGUMENTS`
   - Find the file: `phases/phase-{X}*/task-{X}.{Y}-*.md`
   - If `$ARGUMENTS` is empty or invalid, list all available tasks and ask which to start

2. **Read context:**
   - Read the full task file
   - Read the phase README for exit criteria and dependencies
   - Check `CURRENT_PHASE` in CLAUDE.md

3. **Check for existing progress:**
   - Scan the task file for `<!-- PHANTOM_PROGRESS` marker
   - If found with `status: COMPLETED`: warn the task is already done; ask to confirm restart
   - If found with any other status: warn it's already in progress; suggest `/continue-task $ARGUMENTS` instead
   - If not found: proceed

4. **Create git branch:**
   - Extract the task slug from the filename (e.g., `task-1.3-basic-rw-ept` → slug `basic-rw-ept`)
   - Run: `git checkout -b task-{X.Y}-{slug}`
   - If branch already exists: `git checkout task-{X.Y}-{slug}`

5. **Insert PHANTOM_PROGRESS marker:**
   - Add the following block immediately after the first `## Objective` heading in the task file:

   ```html
   <!-- PHANTOM_PROGRESS
   status: STARTED
   branch: task-{X.Y}-{slug}
   started: {today's date}
   last_activity: {now}
   checkpoint: Not started
   blocking: none
   -->
   ```

6. **Output implementation brief:**
   Print a structured summary:
   - **Task:** `{X.Y} — {title}`
   - **Objective:** one-sentence summary from the task file
   - **What to build:** bullet list from the "What to Build" section
   - **Key data structures:** extracted from the task file
   - **Source files to create/modify:** table from the task file
   - **Tests to run:** list from the task file
   - **Suggested first step:** the most logical first implementation action
   - **Reminder:** Update the PHANTOM_PROGRESS checkpoint before any dangerous VMX/EPT operations

## Notes

- Task numbering: 0.1, 1.1–1.8, 2.1–2.4, 3.1–3.4, 4.1–4.3
- Phase directory names include descriptive suffixes (e.g., `phase-1a-vmx-bootstrap`)
- Do not start tasks out of order if their dependencies are not COMPLETED
