---
name: phantom-conventions
description: Phantom project coding conventions and architecture. Auto-load when writing any Phantom source code.
user-invocable: false
disable-model-invocation: false
---

# Phantom Coding Conventions

## License Header (Mandatory)

Every source file must start with:
```c
// SPDX-License-Identifier: GPL-2.0-only
```

## Naming Conventions

- **All exported symbols:** `phantom_` prefix — `phantom_vmx_enter()`, `struct phantom_instance`, `PHANTOM_RESULT_OK`
- **Static file-scope helpers:** no prefix required, but use descriptive names
- **Error codes (ioctl return):** `PHANTOM_ERROR_*` negative values
- **Result codes (iteration outcome):** `PHANTOM_RESULT_*` non-negative values
- **Struct fields:** snake_case, no Hungarian notation

## Error Handling: goto-Cleanup Pattern

```c
int phantom_instance_create(struct phantom_instance *inst, int cpu)
{
    int ret;

    inst->vmcs = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!inst->vmcs) { ret = -ENOMEM; goto err_vmcs; }

    inst->cow_pool.pages = kvmalloc_array(inst->cow_pool.capacity,
                                          sizeof(struct page *), GFP_KERNEL);
    if (!inst->cow_pool.pages) { ret = -ENOMEM; goto err_pool; }

    ret = phantom_topa_alloc(&inst->pt, cpu);
    if (ret) goto err_topa;

    return 0;

err_topa:
    kvfree(inst->cow_pool.pages);
err_pool:
    __free_page(inst->vmcs);
err_vmcs:
    return ret;
}
```

Error categories (from Appendix A):
- **Hardware errors:** log VMCS dump, mark instance `PHANTOM_STATE_FAILED`, return `PHANTOM_ERROR_HARDWARE`
- **Guest errors:** abort iteration, restore snapshot, set result code, return to userspace — instance still usable
- **Resource errors:** pool/dirty overflow — abort, restore, return error code — instance still usable
- **Host errors:** NMI-safe handler, APIC self-NMI re-delivery

## Hot-Path Rules (VMX exit handler, CoW fault handler)

**NEVER on hot paths:**
- `printk`, `pr_info`, `pr_err`, `pr_debug`, or any printk variant
- `kmalloc(GFP_KERNEL)` or any sleeping allocator
- `msleep()`, `schedule()`, or any sleeping function
- `mutex_lock()` — use spinlocks only if needed

**ALWAYS on hot paths:**
- `trace_printk` for debug events (guarded with `#ifdef PHANTOM_DEBUG`)
- Pre-allocated resources (pool, dirty list, XSAVE area — all allocated at instance creation)
- `rdtsc_ordered()` / `rdtsc()` for timing measurements

## Logging Policy

| Context | Function | Notes |
|---------|----------|-------|
| Module load/unload | `pr_info`, `pr_err` | Once-per-event, not hot path |
| VMX conflict warning | `pr_warn` | Advisory only |
| Hot path events | `trace_printk` | Guarded by `PHANTOM_DEBUG` |
| VMCS dump | `trace_printk` | Structured format, not printk |
| Benchmark timing | `pr_info` | Post-benchmark summary only |

## Memory Allocation

```c
/* NUMA-local allocation — always use this for per-instance pages */
int node = cpu_to_node(cpu);
page = alloc_pages_node(node, GFP_KERNEL, 0);

/* Not this — ignores NUMA locality */
page = alloc_page(GFP_KERNEL);  /* BAD: 40–80ns remote penalty */

/* Track all allocations for memory accounting */
atomic64_add(size, &phantom_allocated_bytes);
```

## Benchmarking Convention

```c
/* Always use rdtsc_ordered() for microbenchmarks */
u64 t0 = rdtsc_ordered();
/* operation */
u64 t1 = rdtsc_ordered();
u64 cycles = t1 - t0;

/* Report format: median + p25/p75 over 30 runs, first 5 discarded (warmup) */
/* Example: "restore: 847 cycles [p25=821, p75=903] (n=25)" */
```

## Debug Build Guards

```c
#ifdef PHANTOM_DEBUG
/* VMCS field validator — compiled out in production */
static int phantom_validate_vmcs(void) { ... }

/* Hot-path trace macros */
#define PHANTOM_TRACE_VM_ENTRY(inst) \
    trace_printk("VMX_ENTRY inst=%d iter=%llu\n", (inst)->id, (inst)->iteration)
#define PHANTOM_TRACE_COW(gpa, priv) \
    trace_printk("COW gpa=0x%llx priv=0x%llx\n", gpa, priv)
#else
#define PHANTOM_TRACE_VM_ENTRY(inst)   do {} while(0)
#define PHANTOM_TRACE_COW(gpa, priv)   do {} while(0)
#endif
```

## Source File Layout

```
kernel/
  phantom_main.c    — module init/cleanup, chardev registration
  vmx_core.c        — VMXON/VMXOFF, VMCS management, VM exit dispatch
  ept.c             — EPT construction, GPA classification, walker
  ept_cow.c         — CoW fault handler, page pool, dirty list
  pt_config.c       — Intel PT MSR config, ToPA setup, double-buffer
  hypercall.c       — nyx_api ABI (ACQUIRE/RELEASE/PANIC/KASAN)
  nmi.c             — NMI-exiting handler, APIC self-NMI re-delivery
  snapshot.c        — VMCS save/restore, XSAVE/XRSTOR
  debug.c           — VMCS dump, EPT walker, dirty list inspector
  interface.c       — /dev/phantom chardev, ioctl dispatch
  memory.c          — global memory accounting
  compat.h          — kernel version compatibility (6.8–6.14)
```

## Hypercall Interface (nyx_api ABI)

Hypercalls are delivered via VMCALL instruction. Guest sets RAX to the hypercall number:

```c
#define NYX_HYPERCALL_ACQUIRE    0  /* Guest: ready for next iteration, get payload */
#define NYX_HYPERCALL_RELEASE    1  /* Guest: iteration complete, normal exit */
#define NYX_HYPERCALL_PANIC      2  /* Guest: detected crash, save context */
#define NYX_HYPERCALL_KASAN      3  /* Guest: KASAN violation detected */
#define NYX_HYPERCALL_SNAPSHOT   4  /* Guest: take snapshot here */
```

## debugfs Counters

Expose health metrics via debugfs at `/sys/kernel/debug/phantom/instance_N/`:
- `dirty_count` — current dirty list entries
- `dirty_overflows` — dirty list overflow events
- `pool_exhaustions` — pool exhaustion events
- `topa_overflows` — PT ToPA overflow events
- `decode_lag_events` — PT decode lag count per 1000 iterations
- `snapshot_restore_cycles` — last snapshot restore latency in cycles

## Kernel Version Compatibility

Target: Linux 6.8–6.14. All version-specific differences in `kernel/compat.h`:

```c
#include <linux/version.h>
#if KERNEL_VERSION(6, 8, 0) <= LINUX_VERSION_CODE
#  define PHANTOM_USE_NEW_API 1
#endif
```

## GPL-Only Symbols (Document Each)

| Symbol | Purpose |
|--------|---------|
| `alloc_percpu()` | Per-CPU VMCS region allocation |
| `smp_call_function_single()` | Per-CPU VMXON/VMXOFF |
| `alloc_pages_node()` | NUMA-local allocation |
| `eventfd_signal()` | PT iteration notification |

Document all in `docs/gpl-symbols.md` with per-version verification results.
