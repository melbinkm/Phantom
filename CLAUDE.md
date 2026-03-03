# Project Phantom — Claude Code Memory

## Project Overview

**Phantom** is a bare-metal hypervisor fuzzer implemented as a Linux kernel module (`phantom.ko`). It takes exclusive VMX-root ownership on dedicated hardware, replacing the KVM + QEMU stack with a minimal, fuzzing-optimised micro-hypervisor.

**Key properties:**
- GPL-2.0-only Linux kernel module
- Exclusive VMX-root mode (kvm_intel must be unloaded)
- EPT Copy-on-Write snapshot engine for fast iteration
- Intel PT coverage (kernel configures, userspace decodes)
- kAFL/Nyx hypercall ABI compatibility
- AFL++ frontend integration via `/dev/phantom` ioctl + mmap

**Master plan:** `project-phantom-dev-plan-v2.md`
**Task files:** `phases/phase-*/task-*.md` (20 tasks across 5 phases)

---

## Architecture Summary

```
USERSPACE:   AFL++ mutator | kAFL frontend | PT Decode Daemon (libipt)
                           ↕ /dev/phantom (ioctl + mmap)
KERNEL:      phantom.ko → VMX Core | EPT Manager (CoW) | Intel PT (ToPA)
HARDWARE:    Intel VT-x (VMX) | EPT + A/D bits | Intel PT
```

**Components:**
- `VMX Core` — VMXON/VMXOFF, VMCS management, VM entry/exit dispatch
- `EPT Manager` — 4-level EPT, CoW fault handler, snapshot/restore, dirty list
- `Intel PT` — IA32_RTIT_CTL config, ToPA double-buffer, eventfd notification
- `Hypercall Handler` — nyx_api ABI (ACQUIRE/RELEASE/PANIC/KASAN)
- `debug.c` — VMCS dump, EPT walker, dirty list inspector, trace_printk

---

## Current Phase Tracking

```
CURRENT_PHASE: 0
```

| Phase | Name | Status | Notes |
|-------|------|--------|-------|
| 0 | Feasibility Spike | not started | VMX spike in nested KVM |
| 1a | VMX Bootstrap + Basic EPT | not started | tasks 1.1–1.4 |
| 1b | CoW Snapshot Engine | not started | tasks 1.5–1.8 |
| 2 | Fuzzing Pipeline | not started | tasks 2.1–2.4 |
| 3 | Kernel Fuzzing | not started | tasks 3.1–3.4 |
| 4 | Campaigns + Publication | not started | tasks 4.1–4.3 |

---

## Active Gates

| Gate | Condition | Phase |
|------|-----------|-------|
| Determinism | 1000/1000 identical PT traces for identical input | Phase 3 entry |
| Performance (Class A) | <100μs snapshot restore for 500-page dirty set | Phase 3 entry |
| kdump/serial console | Verified working before any VMX code | Phase 1a entry |

---

## Coding Conventions

- **Style:** Linux kernel coding style (tabs, 80-char lines, kernel-doc comments)
- **License:** `SPDX-License-Identifier: GPL-2.0-only` on every source file
- **Naming:** `phantom_` prefix for all exported symbols and structs
- **Logging:**
  - `pr_info` / `pr_err` for module load/unload messages
  - `trace_printk` (NOT `printk`) on hot paths (VM entry/exit, CoW faults)
  - `pr_debug` NEVER on hot paths — disabled in production, too slow even in dev
- **Error handling:** goto-cleanup pattern for all functions with allocated resources
- **Hot path rules:** no `printk`, no sleeping functions (`kmalloc(GFP_KERNEL)` etc.), no dynamic allocation in the VM exit handler
- **Benchmarking:** `rdtsc` bracketing for all microbenchmarks; 30-run methodology, report median + p25/p75
- **Memory:** `alloc_pages_node(cpu_to_node(cpu), ...)` for NUMA-local allocation

---

## Source File Layout

```
kernel/
  phantom_main.c    — module init/cleanup, chardev registration
  vmx_core.c        — VMXON/VMXOFF, VMCS management, VM exit dispatch
  ept.c             — EPT page table construction, GPA classification
  ept_cow.c         — CoW fault handler, page pool, dirty list
  pt_config.c       — Intel PT MSR + ToPA setup, double-buffer, PMI handler
  hypercall.c       — nyx_api ABI hypercall handler
  nmi.c             — NMI-exiting handler, APIC self-NMI re-delivery
  snapshot.c        — VMCS save/restore, XSAVE/XRSTOR integration
  debug.c           — VMCS dump, EPT walker, dirty list inspector, trace macros
  interface.c       — /dev/phantom chardev, ioctl dispatch
  memory.c          — global memory accounting, max_memory_mb enforcement
  compat.h          — kernel version compatibility (6.8–6.14)
userspace/
  phantom-pt-decode/ — libipt wrapper → AFL 64KB edge bitmap
tests/
benchmarks/
```

---

## Build and Test Commands

```bash
# Build
make -C kernel/

# Load/unload
sudo insmod kernel/phantom.ko
sudo rmmod phantom

# Check load success
dmesg | tail -20

# Run tests (local nested KVM)
bash tests/run_tests.sh

# Deploy to bare-metal (Phase 2+)
scp kernel/phantom.ko phantom-bench:/tmp/
ssh phantom-bench "sudo rmmod phantom 2>/dev/null; sudo insmod /tmp/phantom.ko"
ssh phantom-bench "sudo dmesg | tail -30"
```

---

## Performance Targets

| Metric | Class A Target | Class B Target |
|--------|---------------|----------------|
| Exec/sec | 50k–500k | 30k–100k |
| Snapshot restore | <5μs (tiny) to ~50μs (500 pages) | 10–100μs |
| Coverage overhead | <1% | <1% |
| Input injection | <1μs | <1μs |

**Comparison baseline:** kAFL/Nyx at 10k–20k exec/sec.
**Expected speedup:** 3–10x for Class B (kernel), 10–50x for Class A (standalone parsers).

---

## SSH Configuration

For Phase 2+ bare-metal testing, configure `~/.ssh/config`:

```
Host phantom-bench
    HostName <bare-metal-IP>
    User <username>
    IdentityFile ~/.ssh/phantom_bench_key
```

Verify connectivity: `ssh phantom-bench "uname -r"`

---

## Key Constraints

1. `kvm_intel` must be unloaded before loading `phantom.ko`
2. Each instance is pinned to a dedicated physical core (no migration)
3. No floating point in kernel code
4. No INVEPT on 4KB RO→RW CoW promotion (EPT violation invalidates faulting GPA)
5. INVEPT required on 2MB→4KB split and after snapshot restore (one batched INVEPT)
6. PT timing packets disabled: CYCEn=MTCEn=TSCEn=PTWEn=0 for determinism
7. XRSTOR must be bracketed with `kernel_fpu_begin()` / `kernel_fpu_end()`

---

## Links

- Master plan: `project-phantom-dev-plan-v2.md`
- Error handling: `phases/appendices/appendix-a-error-handling.md`
- Debugging tooling: `phases/appendices/appendix-b-debugging-tooling.md`
- Agent guide: `docs/claude-code-agent-guide.md`
