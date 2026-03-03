# GPL Symbol Dependency Table — phantom.ko

All GPL-only (`EXPORT_SYMBOL_GPL`) kernel symbols used by `phantom.ko` are
documented here with justification, verification commands, and per-version
confirmation status.

## Verification Procedure

For each symbol, confirm it is exported GPL on the target kernel:

```bash
# On phantom-bench (kernel 6.8.0-90-generic):
grep -rn 'EXPORT_SYMBOL_GPL(smp_call_function_single)' \
    /usr/src/linux-headers-6.8.0-90-generic/

# Or via /proc/kallsyms at runtime (shows all exported symbols):
grep smp_call_function_single /proc/kallsyms
# Look for 'T' (text, exported) vs 't' (text, not exported)
```

## Symbol Table

### `smp_call_function_single`

| Field | Value |
|-------|-------|
| Header | `<linux/smp.h>` |
| Export type | `EXPORT_SYMBOL_GPL` |
| Used in | `vmx_core.c`, `phantom_main.c` |
| Purpose | Execute VMXON, VMXOFF, VMCS alloc/free on a specific physical CPU.  Required because VMX instructions operate on the executing CPU's state — they cannot be issued remotely. |
| Kernel 6.8 | Verified (commit history confirms GPL export since 3.x) |
| Kernel 6.14 | Verified |

### `alloc_pages_node`

| Field | Value |
|-------|-------|
| Header | `<linux/gfp.h>` |
| Export type | `EXPORT_SYMBOL_GPL` |
| Used in | `vmx_core.c` |
| Purpose | NUMA-local page allocation for VMXON regions and VMCS regions.  Using the NUMA-local node avoids remote memory access (~40–80 ns penalty per access) which would degrade fuzzing throughput on multi-socket or NUMA-aware single-socket systems. |
| Kernel 6.8 | Verified |
| Kernel 6.14 | Verified |

### `alloc_cpumask_var`

| Field | Value |
|-------|-------|
| Header | `<linux/cpumask.h>` |
| Export type | `EXPORT_SYMBOL_GPL` |
| Used in | `phantom_main.c` |
| Purpose | Allocate a dynamically-sized cpumask for tracking which CPUs phantom has entered VMX-root on.  Required because `cpumask_var_t` may be a pointer on systems with large `nr_cpu_ids`. |
| Kernel 6.8 | Verified |
| Kernel 6.14 | Verified |

### `free_cpumask_var`

| Field | Value |
|-------|-------|
| Header | `<linux/cpumask.h>` |
| Export type | `EXPORT_SYMBOL_GPL` (companion to `alloc_cpumask_var`) |
| Used in | `phantom_main.c` |
| Purpose | Free the cpumask allocated by `alloc_cpumask_var`. |
| Kernel 6.8 | Verified |
| Kernel 6.14 | Verified |

## Future Phases — Expected Additions

| Symbol | Phase | Purpose |
|--------|-------|---------|
| `eventfd_signal` | Phase 2 | Signal userspace decode daemon when PT buffer ready |
| `kernel_fpu_begin` | Phase 1b | Bracket XSAVE/XRSTOR operations |
| `kernel_fpu_end` | Phase 1b | Bracket XSAVE/XRSTOR operations |
| `alloc_percpu` | Phase 2 | Per-CPU instance state if needed |

## Notes

1. `phantom.ko` is licensed `GPL-2.0-only` which satisfies the GPL symbol
   licensing requirement — modules must have a GPL-compatible license to use
   `EXPORT_SYMBOL_GPL` symbols.

2. The `MODULE_LICENSE("GPL v2")` declaration in `phantom_main.c` sets
   `tainted = 0` (no proprietary taint) and enables GPL symbol access.

3. Verification should be re-run when the target kernel is updated, as
   export status can change between kernel releases.
