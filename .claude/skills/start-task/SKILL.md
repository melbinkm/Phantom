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

2b. **Extract implementation steps:**
   - Identify the "What to Build" section in the task file
   - Extract each top-level bullet point as one implementation step
   - Summarise each bullet to ~80 characters if longer — the full detail lives in the task file
   - These become the checkboxes in the GitHub issue (1:1 mapping, never split or merge bullets)

3. **Check for existing progress:**
   - Run: `gh issue list --repo melbinkm/Phantom --search "Task {X.Y}:" --state all --json number,title,state,labels`
   - If a closed issue exists for this task: warn the task is already done; ask to confirm restart
   - If an open issue exists for this task: warn it's already in progress; suggest `/continue-task $ARGUMENTS` instead
   - If no issue exists: proceed

4. **Create git branch:**
   - Extract the task slug from the filename (e.g., `task-1.3-basic-rw-ept` → slug `basic-rw-ept`)
   - Run: `git checkout -b task-{X.Y}-{slug}`
   - If branch already exists: `git checkout task-{X.Y}-{slug}`

5. **Create GitHub issue:**
   - Run:
   ```bash
   gh issue create \
     --repo melbinkm/Phantom \
     --title "Task {X.Y}: {task title}" \
     --label "phase-{phase-label},started" \
     --body "## Objective
   {one-sentence objective from the task file}

   ## Branch
   \`task-{X.Y}-{slug}\`

   ## Task file
   \`phases/phase-{X}*/task-{X}.{Y}-*.md\`

   ## Implementation Steps
   - [ ] {step 1 extracted from "What to Build" bullet 1, ≤80 chars}
   - [ ] {step 2 extracted from "What to Build" bullet 2, ≤80 chars}
   - [ ] {… one checkbox per top-level bullet …}

   ## Checkpoint
   Not started"
   ```
   - Note the issue number returned (e.g., `#12`)

6. **Output implementation brief:**
   Print a structured summary:
   - **Task:** `{X.Y} — {title}`
   - **Issue:** `melbinkm/Phantom#{issue-number}`
   - **Objective:** one-sentence summary from the task file
   - **Implementation checklist:** `{count} steps extracted from "What to Build"`
   - **What to build:** bullet list from the "What to Build" section
   - **Key data structures:** extracted from the task file
   - **Source files to create/modify:** table from the task file
   - **Tests to run:** list from the task file
   - **Suggested first step:** the most logical first implementation action
   - **Reminder:** Update the GitHub issue with a comment before any dangerous VMX/EPT operations

## Notes

- Task numbering: 0.1, 1.1–1.8, 2.1–2.4, 3.1–3.4, 4.1–4.3
- Phase label mapping: 0→`phase-0`, 1a→`phase-1a`, 1b→`phase-1b`, 2→`phase-2`, 3→`phase-3`, 4→`phase-4`
- Phase directory names include descriptive suffixes (e.g., `phase-1a-vmx-bootstrap`)
- Do not start tasks out of order if their dependencies are not COMPLETED
