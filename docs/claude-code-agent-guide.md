# Claude Code Autonomous Agent Guide — Project Phantom

This document explains how Project Phantom uses Claude Code's slash commands, sub-agents, and skills to automate kernel development workflows. It maps the patterns from [Building Autonomous SWE Agents with Claude Code](https://deoxy.dev/blog/building-autonomous-swe-agents-claude-code/) to the specifics of a bare-metal hypervisor fuzzer.

---

## 1. Overview: Three-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3: SESSION MEMORY                                        │
│  CLAUDE.md — loaded at start of every session                   │
│  Contains: architecture, conventions, phase state, file layout  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: AGENTS (sub-processes)                                │
│  kernel-dev   — writes C kernel module code                     │
│  tester       — runs tests locally or via SSH                   │
│  task-planner — read-only implementation planner                │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: SKILLS (slash commands + auto-loaded context)         │
│  /start-task /continue-task /phase-status /deploy-test          │
│  /submit-task  [user-invocable]                                 │
│  vmx-reference ept-reference intel-pt-reference                 │
│  phantom-conventions  [auto-loaded by Claude when relevant]     │
└─────────────────────────────────────────────────────────────────┘
```

**Why this fits kernel dev:** Kernel module development has unique crash-recovery requirements. Sessions terminate unexpectedly (host panic during VMX experiments). The three-layer architecture ensures Claude can resume work without losing context, even after a machine reboot.

---

## 2. Article Pattern Mapping

| Article Pattern | Phantom Equivalent | Notes |
|-----------------|-------------------|-------|
| `/start-issue <N>` | `/start-task <X.Y>` | Task numbers instead of GitHub issues |
| `/continue-issue <N>` | `/continue-task <X.Y>` | Includes crash recovery workflow |
| `/ship-issue <N>` | `/submit-task <X.Y>` | Commit + push + PR creation |
| `/standup` | `/phase-status` | Shows all 20 tasks + gate conditions |
| Custom deploy command | `/deploy-test` | Build + SSH deploy + dmesg capture |
| GitHub issues as memory | `<!-- PHANTOM_PROGRESS -->` markers | In task `.md` files (no GitHub yet) |
| Code agent | `kernel-dev` agent | VMX/EPT/PT specialist, phantom_ prefix |
| Test agent | `tester` agent | Local KVM + SSH bare-metal support |
| Plan agent | `task-planner` agent | Read-only, plan mode permission |
| Domain knowledge skills | `vmx-reference`, `ept-reference`, `intel-pt-reference` | Auto-loaded based on code context |
| Coding conventions skill | `phantom-conventions` | Auto-loaded for any phantom source file |

---

## 3. Progress Tracking with `<!-- PHANTOM_PROGRESS -->` Markers

Until the project has a GitHub repository with Issues, task state is tracked directly in the task `.md` files using HTML comment markers. These are invisible in rendered markdown but readable by Claude.

### Marker Format

```html
<!-- PHANTOM_PROGRESS
status: STARTED | IN_PROGRESS | BLOCKED | COMPLETED
branch: task-1.3-basic-rw-ept
started: 2026-03-03
last_activity: 2026-03-03T14:32:00
checkpoint: EPT 4-level structure built; MMIO classification done; CoW not started
blocking: none
-->
```

### Lifecycle

1. **Before `/start-task`:** No marker in the file
2. **After `/start-task`:** Marker inserted with `status: STARTED`
3. **During work:** Marker updated to `status: IN_PROGRESS`, `checkpoint` updated
4. **After crash/panic:** Marker retains last checkpoint; `/continue-task` reads it
5. **After `/submit-task`:** Marker updated to `status: COMPLETED`

### `/phase-status` aggregates all markers

The `/phase-status` command scans all 20 task files, reads their markers, and produces a status table showing which tasks are pending/started/in-progress/blocked/completed.

---

## 4. Crash Recovery Workflow (Unique to Kernel Dev)

Host kernel panics are **expected** during Phase 0–1 development. The workflow is:

```
1. Guest VMX code triggers host panic
        │
        ▼
2. kdump captures crash dump to /var/crash/
        │
        ▼
3. Machine reboots automatically
        │
        ▼
4. Developer connects serial console:
   screen /dev/ttyUSB0 115200
        │
        ▼
5. Boot into recovery, examine dump:
   crash /usr/lib/debug/vmlinux /var/crash/<dump>/vmcore
   crash> mod -s phantom
   crash> bt <phantom_vmx_exit_handler>
        │
        ▼
6. Start new Claude Code session, run:
   /continue-task 1.2
        │
        ▼
7. Claude reads PHANTOM_PROGRESS marker,
   checks git status on task branch,
   reconciles planned vs actual state,
   resumes from last checkpoint
```

**PHANTOM_PROGRESS checkpoint** serves as the "commit" before a crash. Always update the checkpoint before triggering potentially dangerous VMX operations.

---

## 5. SSH Remote Execution

### Phase 0–1: Local Nested KVM

```bash
# Development machine runs phantom.ko in nested KVM:
# outer_host → KVM guest (dev machine) → phantom.ko → guest VM
make -C kernel/
sudo insmod kernel/phantom.ko
dmesg | tail -20
```

### Phase 2+: SSH to Bare Metal (`phantom-bench`)

```bash
# SSH target defined in ~/.ssh/config as "phantom-bench"
# The /deploy-test skill automates this sequence:

make -C kernel/
scp kernel/phantom.ko phantom-bench:/tmp/
ssh phantom-bench "sudo rmmod phantom 2>/dev/null; sudo insmod /tmp/phantom.ko"
ssh phantom-bench "sudo dmesg | tail -30"
ssh phantom-bench "sudo bash /tmp/run_test.sh"
```

The `tester` agent is the primary executor for SSH-based test runs. It handles:
- `insmod` / `rmmod` sequencing
- `dmesg` capture and parsing
- debugfs counter verification
- Benchmark methodology (disable turbo boost, 30 runs, report median + p25/p75)

---

## 6. Phased Rollout

Not all config files are relevant at every phase. This table shows when each becomes active:

| Config File | Active From | Purpose |
|-------------|------------|---------|
| `CLAUDE.md` | Day 1 | Session memory — always loaded |
| `phantom-conventions` skill | Day 1 | Coding standards |
| `vmx-reference` skill | Task 0.1 | VMX instruction context |
| `kernel-dev` agent | Task 1.1 | Writing kernel C code |
| `tester` agent | Task 1.1 | Running tests |
| `task-planner` agent | Task 1.1 | Planning before writing |
| `/start-task`, `/continue-task` | Task 1.1 | Task lifecycle |
| `/phase-status` | Task 1.1 | Progress visibility |
| `ept-reference` skill | Task 1.3 | EPT/CoW context |
| `/deploy-test` | Task 1.1 (local), Task 2+ (SSH) | Build + deploy |
| `intel-pt-reference` skill | Task 2.2 | Intel PT context |
| `/submit-task` | Task 1.1+ | PR creation |
| `.claude/rules/kernel-code.md` | Task 1.1 | Path-specific enforcement |

---

## 7. Complete File Manifest

```
/mnt/d/fuzzer/
├── CLAUDE.md                              ← Project memory (loaded every session)
├── docs/
│   └── claude-code-agent-guide.md         ← This file
└── .claude/
    ├── agents/
    │   ├── kernel-dev.md                  ← VMX/EPT/PT kernel code writer
    │   ├── tester.md                      ← Test runner (local + SSH)
    │   └── task-planner.md                ← Read-only implementation planner
    ├── skills/
    │   ├── start-task/SKILL.md            ← /start-task <X.Y>
    │   ├── continue-task/SKILL.md         ← /continue-task <X.Y>
    │   ├── phase-status/SKILL.md          ← /phase-status
    │   ├── deploy-test/SKILL.md           ← /deploy-test [test-name]
    │   ├── submit-task/SKILL.md           ← /submit-task <X.Y>
    │   ├── vmx-reference/SKILL.md         ← Auto: VMX domain knowledge
    │   ├── ept-reference/SKILL.md         ← Auto: EPT/CoW domain knowledge
    │   ├── intel-pt-reference/SKILL.md    ← Auto: Intel PT domain knowledge
    │   └── phantom-conventions/SKILL.md   ← Auto: coding conventions
    └── rules/
        └── kernel-code.md                 ← Path rules for kernel/**/*.c
```

### Skills vs Agents

**Skills** are prompt expansions — they inject context into the current session. They are either:
- **User-invocable:** `/start-task`, `/continue-task`, `/phase-status`, `/deploy-test`, `/submit-task`
- **Auto-invocable:** Claude decides to load `vmx-reference` when it sees VMX code, etc.

**Agents** are sub-processes with their own tool access. Spawned by Claude when a specialised role is needed:
- `kernel-dev` has access to Write/Edit tools — it **writes code**
- `tester` has access to Bash — it **runs commands**
- `task-planner` is read-only — it **produces plans without modifying files**

---

## 8. Recommended Workflow for Each Task

```
1. /start-task <X.Y>
   → Read task file, check existing progress, create git branch,
     insert PHANTOM_PROGRESS marker, output implementation brief

2. Delegate planning to task-planner agent
   → Read-only analysis of master plan + task file
   → Output: which functions, structs, files, algorithms

3. Delegate implementation to kernel-dev agent
   → vmx-reference / ept-reference / intel-pt-reference auto-loaded
   → phantom-conventions auto-loaded
   → .claude/rules/kernel-code.md enforced on kernel/**/*.c

4. Delegate testing to tester agent
   → Build, deploy (local or SSH), capture dmesg
   → Report pass/fail with evidence

5. Update PHANTOM_PROGRESS checkpoint after each sub-step

6. /submit-task <X.Y>
   → Verify all tests pass, commit, push, create PR
```
