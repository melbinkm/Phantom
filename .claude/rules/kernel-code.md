---
paths:
  - "kernel/**/*.c"
  - "kernel/**/*.h"
---

# Phantom Kernel Code Rules

These rules apply to all files under `kernel/`.

## License Header

Every source file must begin with:

```c
// SPDX-License-Identifier: GPL-2.0-only
```

No exceptions. Files missing this header will be rejected by sparse.

## Symbol Naming

All exported symbols (functions, structs, enums, macros) must use the `phantom_` prefix:

- Functions: `phantom_vmx_enter()`, `phantom_cow_fault()`, `phantom_pt_reset()`
- Structs: `struct phantom_instance`, `struct phantom_pool`, `struct dirty_entry`
- Module-level macros: `PHANTOM_RESULT_OK`, `PHANTOM_ERROR_HARDWARE`

Static (file-scope) helpers do not require the prefix but should still be descriptive.

## No Floating Point

Floating point is forbidden in kernel code. The kernel does not save/restore FPU state by default. Use integer arithmetic for all calculations.

For latency percentages and ratios, multiply by 1000 and divide (fixed-point).

## Error Path Cleanup (goto Pattern)

All functions that allocate resources must use the goto-cleanup pattern:

```c
int phantom_instance_create(...)
{
    int ret;

    inst->vmcs = alloc_page(GFP_KERNEL);
    if (!inst->vmcs) { ret = -ENOMEM; goto err_vmcs; }

    inst->pool.pages = kvmalloc_array(...);
    if (!inst->pool.pages) { ret = -ENOMEM; goto err_pool; }

    return 0;

err_pool:
    free_page((unsigned long)page_address(inst->vmcs));
err_vmcs:
    return ret;
}
```

Never return an error without freeing all previously allocated resources.

## Hot-Path Functions

Functions called on every VM entry/exit or every CoW fault are "hot path". Hot-path functions must NOT:

- Call `printk`, `pr_info`, `pr_err`, `pr_debug`, or any printk variant
- Call `kmalloc(GFP_KERNEL)` or any sleeping allocator
- Call `msleep()`, `schedule()`, or any function that may sleep
- Take any mutex (spinlocks are allowed if held for a short critical section)

Use `trace_printk` for debug tracing on hot paths (controlled by `PHANTOM_DEBUG`).

## Memory Allocation

Use NUMA-local allocation for all per-instance memory:

```c
int node = cpu_to_node(cpu);
page = alloc_pages_node(node, GFP_KERNEL, order);
```

Not `alloc_pages(GFP_KERNEL, order)` — that ignores NUMA locality and adds 40–80ns latency for remote accesses.

## Benchmarking

All timing measurements must use `rdtsc` bracketing:

```c
u64 t0 = rdtsc_ordered();
/* operation being measured */
u64 t1 = rdtsc_ordered();
u64 cycles = t1 - t0;
```

Never use `ktime_get()` or `jiffies` for microbenchmarks — too coarse.
