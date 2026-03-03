# Task 1.1: Development Environment + VMX Bootstrap

> **Phase:** VMX Bootstrap + Basic EPT | **Week(s):** 1–2 | **Depends on:** [Task 0.1](../phase-0-spike/task-0.1-vmx-feasibility-spike.md)

## Objective

Establish the full development environment with crash-recovery tooling verified and working, then implement a clean `phantom.ko` skeleton that enters and exits VMX root mode on all designated cores.

## What to Build

- Development environment: Ubuntu 24.04, kernel 6.x (target range: 6.8–6.14), nested KVM for safe development (`kvm_intel nested=1` on outer host), serial console to second machine (hard requirement — not optional), kdump + crash utility installed and tested before writing any VMX code (Week 1 deliverable), automated VM rebuild scripts for fast iteration after kernel panic
- Kernel module skeleton (`phantom.ko`): module init/cleanup with proper error handling, `/dev/phantom` chardev registration, CPU feature detection (VT-x, EPT, Intel PT, PML, PT-in-VMX, XSAVE)
- VMX ownership check: on each designated core, check `CR4.VMXE` via `read_cr4()` — if already set, VMX is in use on that core; attempt `VMXON` and if it fails with CF=1 (VMX-already-active error), another entity owns VMX on that core; abort module load with a diagnostic message identifying which cores have a VMX conflict (CR4.VMXE is a fast pre-check but is still a TOCTOU check; the VMXON attempt is definitive)
- Advisory warning (not a hard gate): if `kvm_intel` module is loaded, emit `pr_warn("kvm_intel is loaded — VMX conflict likely; unload it first")`; the actual VMX ownership check via VMXON is the enforcement mechanism
- `debug.c` skeleton: `pr_info` → `trace_printk` for hot-path events from day one
- VMX bootstrap: `VMXON` on designated cores via `smp_call_function_single`, VMXON region allocation (page-aligned, revision ID set), `VMXOFF` in module cleanup, basic VMCS allocation and `VMCLEAR`/`VMPTRLD`
- Partial VMXON recovery: if VMXON fails on core N, execute VMXOFF on cores 0..N-1 before returning error; module load fails cleanly — prevents VMX state leak on multi-core init failure
- CI from day one: host kernel compiled with `CONFIG_KASAN`, `CONFIG_KMEMLEAK`, `CONFIG_LOCKDEP`, `CONFIG_DEBUG_ATOMIC_SLEEP` (mandatory during Phase 1–2 per §9 analysis requirements); sparse + smatch configured to run on every commit with zero warnings required — Phase 4 expands this to a full public GitHub Actions runner but the tooling is established here

## Implementation Guidance

### VMX Ownership Check Pseudocode

```c
static int vmx_check_and_take_ownership(int cpu)
{
    u64 cr4;
    u32 err;

    /* Fast pre-check: if VMXE already set, VMX is likely in use */
    cr4 = read_cr4();
    if (cr4 & X86_CR4_VMXE) {
        pr_warn("phantom: CPU%d: CR4.VMXE already set — VMX likely active\n", cpu);
        /* Still attempt VMXON — the attempt is the definitive check */
    }

    /* Set CR4.VMXE to allow VMXON */
    write_cr4(cr4 | X86_CR4_VMXE);

    /* Allocate and prepare VMXON region */
    per_cpu(vmxon_region, cpu) = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!per_cpu(vmxon_region, cpu))
        return -ENOMEM;

    u32 revision = rdmsr(MSR_IA32_VMX_BASIC) & 0x7fffffff;
    *(u32 *)page_address(per_cpu(vmxon_region, cpu)) = revision;

    u64 phys = page_to_phys(per_cpu(vmxon_region, cpu));

    /* Attempt VMXON — this is the authoritative ownership check */
    asm volatile("vmxon %1; setc %0"
                 : "=qm"(err) : "m"(phys) : "cc", "memory");

    if (err) {
        /* CF=1: VMX is already active on this core */
        pr_err("phantom: CPU%d: VMXON failed (CF=1) — VMX already active\n", cpu);
        write_cr4(cr4);  /* Restore original CR4 */
        return -EBUSY;
    }

    pr_info("phantom: CPU%d: VMX root entered successfully\n", cpu);
    return 0;
}
```

### Partial VMXON Recovery (Multi-Core Init)

```c
static int phantom_vmxon_all_cores(void)
{
    int cpu, last_success = -1;

    for_each_cpu(cpu, phantom_cpumask) {
        int ret = smp_call_function_single(cpu, vmx_check_and_take_ownership_wrapper, NULL, 1);
        if (ret || per_cpu(vmxon_failed, cpu)) {
            /* Roll back: VMXOFF on cores 0..last_success */
            for (int j = 0; j <= last_success; j++) {
                smp_call_function_single(cpumask_nth(phantom_cpumask, j),
                                         vmxoff_wrapper, NULL, 1);
            }
            pr_err("phantom: VMXON failed on CPU%d; rolled back cores 0..%d\n",
                   cpu, last_success);
            return -EIO;
        }
        last_success++;
    }
    return 0;
}
```

### GPL-Only Symbol Dependencies

The following GPL-only kernel symbols are required (document each with justification):

| Symbol | Used For | GPL Status |
|--------|----------|-----------|
| `alloc_percpu()` | Per-CPU VMCS region allocation | `EXPORT_SYMBOL_GPL` in 6.x |
| `smp_call_function_single()` | Per-CPU VMXON/VMXOFF | `EXPORT_SYMBOL_GPL` in 6.x |
| `alloc_pages_node()` | NUMA-local allocation | `EXPORT_SYMBOL_GPL` in 6.x |

**Verification procedure:** `grep -rn 'EXPORT_SYMBOL[^(]*(smp_call_function_single)' $(KERNEL_SRC)`

Document all in `docs/gpl-symbols.md` with per-version verification results.

### Kernel Version Compatibility

Target kernel range: Linux 6.8 through 6.14. All version-specific API differences go in `kernel/compat.h`:

```c
/* kernel/compat.h */
#include <linux/version.h>

#if KERNEL_VERSION(6, 8, 0) <= LINUX_VERSION_CODE
#  define PHANTOM_USE_NEW_API 1
#endif
```

### CI Configuration (from Day One)

Self-hosted GitHub Actions runner on a machine with nested KVM enabled:
- Test VM: Ubuntu 24.04 guest with Phantom module
- Tests run in nested KVM (outer host → KVM → test VM → Phantom → guest)
- Host kernel compiled with: `CONFIG_KASAN`, `CONFIG_KMEMLEAK`, `CONFIG_LOCKDEP`, `CONFIG_DEBUG_ATOMIC_SLEEP`
- Static analysis: sparse + smatch, zero warnings required on every commit

### debug.c Skeleton (from Week 1)

```c
/* debug.c — set up from week 1; hot-path events use trace_printk not printk */

/* VMCS dump on unexpected VM exit */
void phantom_dump_vmcs(int instance, int cpu, u32 exit_reason, u64 iteration)
{
    trace_printk("PHANTOM VMCS DUMP [instance=%d, cpu=%d, exit_reason=%u, iteration=%llu]\n",
                 instance, cpu, exit_reason, iteration);
    trace_printk("  GUEST_RIP=0x%llx GUEST_RSP=0x%llx GUEST_RFLAGS=0x%llx\n",
                 vmcs_read(GUEST_RIP), vmcs_read(GUEST_RSP), vmcs_read(GUEST_RFLAGS));
    /* ... all fields ... */
}

/* Hot-path: VM entry/exit events */
#define PHANTOM_TRACE_VM_ENTRY(inst)  trace_printk("VMX_ENTRY inst=%d\n", inst)
#define PHANTOM_TRACE_VM_EXIT(inst, reason) \
    trace_printk("VMX_EXIT inst=%d reason=%u\n", inst, reason)
```

## Key Data Structures

```c
/* Per-CPU VMX state */
struct phantom_vmx_cpu_state {
    struct page *vmxon_region;   /* 4KB VMXON region, page-aligned              */
    struct page *vmcs_region;    /* 4KB VMCS region per vCPU                    */
    bool         vmx_active;     /* True after successful VMXON                 */
    int          pinned_cpu;     /* Physical CPU this instance is pinned to     */
};
DEFINE_PER_CPU(struct phantom_vmx_cpu_state, phantom_vmx_state);

/* VMXON region layout (Intel SDM Vol. 3C §24.2) */
struct vmxon_region {
    u32 revision_id;  /* IA32_VMX_BASIC[30:0] — must match before VMXON */
    u8  data[4092];   /* Processor-managed */
};
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/phantom_main.c` | Module init/cleanup, chardev registration |
| `kernel/vmx_core.c` | VMXON/VMXOFF, VMCS allocation, feature detection |
| `kernel/debug.c` | trace_printk skeleton, VMCS dump format |
| `kernel/compat.h` | Kernel version compatibility abstractions |
| `kernel/interface.c` | `/dev/phantom` chardev, basic ioctl skeleton |

## Reference Sections

- §2.2: VMX-root exclusivity — VMXON conflict detection, kvm_intel advisory, authoritative check
- §6.9: Kernel compatibility/GPL symbols — version handling, symbol dependency table, verification procedure
- §9: CI and runtime configs — KASAN/KMEMLEAK/LOCKDEP requirements, sparse/smatch CI setup
- §5.6 (Appendix B §1–4): debug.c skeleton — trace_printk hot path, VMCS dump format, VMCS field validator

## Tests to Run

- `insmod phantom.ko` and `rmmod phantom.ko` complete without errors (pass = dmesg shows clean entry and exit, no residual VMX state)
- `/dev/phantom` responds to a basic ioctl (pass = ioctl returns without error)
- kdump captures a deliberate test panic and produces a usable dump (pass = dump file written, `crash` utility can open it)
- Serial console displays kernel output on second machine during boot (pass = message visible on remote terminal)
- sparse and smatch produce zero warnings on the initial `phantom.ko` skeleton (pass = CI clean on first commit)

## Deliverables

Module enters and exits VMX root mode on all designated cores; `/dev/phantom` chardev responds to ioctl; kdump and serial console verified working.

## Exit Criteria

**GATE — kdump and serial console must be verified before Week 3 VMCS work begins.** Module loads and unloads cleanly on all designated cores. `/dev/phantom` responds to ioctl.
