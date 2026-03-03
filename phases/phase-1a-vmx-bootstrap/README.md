# Phase 1a: VMX Bootstrap + Basic EPT (Weeks 1–6)

> Part of [Project Phantom Development Plan](../../project-phantom-dev-plan-v2.md)

## Goal

A kernel module that enters VMX root, configures a minimal VMCS, boots a trivial guest, and handles basic EPT mappings (read-only, no CoW yet). No snapshot/restore yet.

## Notes

- **GATE — kdump and serial console must be verified before Week 3 VMCS work begins.**
- Host kernel compiled with `CONFIG_KASAN`, `CONFIG_KMEMLEAK`, `CONFIG_LOCKDEP`, `CONFIG_DEBUG_ATOMIC_SLEEP` (mandatory during Phase 1–2).
- sparse + smatch configured to run on every commit with zero warnings required.
- 30% overhead budgeted for host kernel panic debugging (nested KVM, kdump analysis, VMCS debugging).

## Tasks

| Task | Title | Week(s) | Depends On |
|------|-------|---------|------------|
| [1.1](task-1.1-dev-environment-vmx-bootstrap.md) | Development Environment + VMX Bootstrap | 1–2 | Task 0.1 |
| [1.2](task-1.2-vmcs-configuration-guest-execution.md) | VMCS Configuration + Guest Execution | 3–4 | Task 1.1 |
| [1.3](task-1.3-basic-rw-ept.md) | Basic Read/Write EPT | 5 | Task 1.2 |
| [1.4](task-1.4-first-cow-fault-page-pool.md) | First CoW Fault + Page Pool | 6 | Task 1.3 |

## Phase Exit Criteria

Module loads/unloads cleanly on all designated cores; guest executes trivial code and communicates via VMCALL; basic R/W EPT with correct MMIO/RAM/reserved classification; CoW fault handler allocates private pages and tracks dirty list; serial console and kdump verified working before any EPT CoW code.
