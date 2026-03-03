---
name: adjust
description: Record a mid-work plan change with audit trail and update issue checklist
user-invocable: true
argument-hint: "[reason for adjustment]"
---

# Adjust Phantom Task

Parse `$ARGUMENTS` as a free-text reason for the plan change.

## Steps

1. **Find in-progress issue:**
   - Run: `gh issue list --repo melbinkm/Phantom --label in-progress --json number,title,body,labels`
   - If no in-progress issue found: ask user which task they are adjusting, then fetch by task number
   - Note: issue number, title, current body, labels

2. **Read context:**
   - Find and read the task file: `phases/phase-{X}*/task-{X}.{Y}-*.md`
   - Run: `git log --oneline -10` to see recent commits on current branch
   - Run: `git status` to see uncommitted changes

3. **Analyze impact:**
   - Identify which items in the `## Implementation Steps` checklist are affected by the change
   - Identify which files would now be created/deleted/modified differently from the original plan
   - Identify which tests would change (new tests, removed tests, changed pass criteria)
   - Estimate scope: **minor** (1–2 checkboxes), **moderate** (≤50% of steps), **major** (>50% of steps)

4. **Post adjustment comment:**
   - Run:
   ```bash
   gh issue comment {number} --repo melbinkm/Phantom --body "## Adjustment

   **Reason:** {$ARGUMENTS}
   **Scope:** {minor|moderate|major} — {N} of {total} implementation steps affected
   **Timestamp:** {now}

   ### What changes
   {bullet list of what will be done differently}

   ### Impact analysis
   - **Affected steps:** {list of checklist items that change}
   - **Affected files:** {list of files that now differ from original plan}
   - **Test changes:** {tests added, removed, or modified criteria}

   ### Previous direction
   {brief summary of what the original plan was doing before this change}

   ### Revised direction
   {clear statement of the new approach and why it is better}"
   ```

5. **Update labels:**
   - Add `adjusted` label (always):
   ```bash
   gh issue edit {number} --repo melbinkm/Phantom --add-label "adjusted"
   ```
   - If the adjustment is caused by a blocking dependency or unexpected constraint, also add `blocked`:
   ```bash
   gh issue edit {number} --repo melbinkm/Phantom --add-label "blocked"
   ```

6. **Update implementation checklist** (only if `## Implementation Steps` exists in issue body):
   - Preserve checked state of already-completed items — do not uncheck completed work
   - Identify checklist items that are no longer applicable and remove them from the list
   - Identify new steps required by the revised direction and append as new unchecked items
   - Apply the update:
   ```bash
   gh issue edit {number} --repo melbinkm/Phantom --body "{updated body with revised checklist}"
   ```

7. **Output adjustment summary:**
   - **Task:** `{X.Y} — {title}`
   - **Issue:** `melbinkm/Phantom#{number}`
   - **Reason:** `{$ARGUMENTS}`
   - **Scope:** `{minor|moderate|major}`
   - **Steps changed:** `{N} modified, {M} added, {K} removed`
   - **Label added:** `adjusted`
   - **Next action:** first uncompleted checklist item under the revised plan

## Notes

- The `adjusted` label is additive — it does not replace `in-progress`
- Always use `/adjust` (not manual comments) so the audit trail is structured and parseable by `/sync-progress`
- If the plan change is large enough that the original task file needs updating, note this in the comment but do not modify the task file (it is a planning artifact, not a working document)
- Run `/sync-progress` after a burst of implementation work to reconcile the checklist against actual code state
