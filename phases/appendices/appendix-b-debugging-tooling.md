# Appendix B: §5.6 Debugging and Observability Tooling

> Part of [Project Phantom Development Plan](../../project-phantom-dev-plan-v2.md)
>
> This appendix is cross-referenced by multiple tasks. See also [Appendix A: Error Handling](appendix-a-error-handling.md).

`debug.c` is a first-class component of Phantom, not an afterthought. It must be set up and working from **Week 1**.

## 1. VMCS Dump-on-Exit-Failure

Automatically triggered on any unexpected VM exit reason (not in the handled set) or on VMLAUNCH/VMRESUME failure (CF=1 or ZF=1). Output format:

```
PHANTOM VMCS DUMP [instance=N, cpu=M, exit_reason=X, iteration=Y]
  GUEST_RIP=0x... GUEST_RSP=0x... GUEST_RFLAGS=0x...
  GUEST_CR0=0x... GUEST_CR3=0x... GUEST_CR4=0x...
  EXIT_QUALIFICATION=0x... VM_INSTRUCTION_ERROR=N
  GUEST_CS: sel=0x... base=0x... limit=0x... ar=0x...
  ... [all fields]
```

Output via `trace_printk` (not `printk`) to avoid lock contention. Structured format parseable by a companion userspace tool (`tools/vmcs-dump/`).

## 2. EPT Walker/Dumper

Debug ioctl `PHANTOM_DEBUG_DUMP_EPT`:
- Walks the full 4-level EPT for the specified instance
- Prints each mapped region: GPA range, HPA, permissions, memory type
- Highlights: CoW'd pages (private HPA != original HPA), split 2MB pages, MMIO regions, absent regions
- Output to debugfs file `/sys/kernel/debug/phantom/instance_N/ept_map`

## 3. Dirty List Inspector

Debug ioctl `PHANTOM_DEBUG_DUMP_DIRTY_LIST`:
- Returns current dirty list contents: GPA, original HPA, private HPA, iteration number for each entry
- Available mid-iteration (for debugging runaway dirty sets) and post-iteration
- Output to debugfs file `/sys/kernel/debug/phantom/instance_N/dirty_list`

## 4. Trace Logging Ring Buffer

Hot-path event logging via `trace_printk` (not `printk` — `printk` is too slow for the hot path and would corrupt timing measurements):
- VM entry / VM exit + exit reason
- EPT violation GPA and resolved action (CoW, MMIO emulate, abort)
- CoW allocation (GPA, private HPA)
- Snapshot create / restore timestamps
- ToPA overflow events

Accessible via `trace-cmd` or directly from `/sys/kernel/debug/tracing/trace`. Minimal overhead when not being read (ring buffer).

## 5. VMCS Field Validator

Before every VMLAUNCH and VMRESUME (in debug builds): check all VMCS fields against Intel SDM Vol. 3C §26.3 requirements:
- Segment register access rights consistency (S/E/W bit combinations)
- CR0/CR4 fixed bits (against `IA32_VMX_CR0_FIXED0/1` and `IA32_VMX_CR4_FIXED0/1`)
- Control field consistency (exec controls vs exit controls vs entry controls)
- Reserved fields zero

Compiled out in production (`#ifdef PHANTOM_DEBUG`). In development: compile with `-DPHANTOM_DEBUG` at all times.

## 6. kdump Post-Mortem Procedure

When a host kernel panic occurs (expected during Phase 1 development):

1. kdump captures crash dump to dedicated partition (configured at OS install, Week 1 deliverable)
2. Boot to recovery: `crash /usr/lib/debug/vmlinux /var/crash/<dump>/vmcore`
3. Examine Phantom state:
   - `crash> mod -s phantom` — load Phantom module symbols
   - `crash> bt <phantom_vmx_exit_handler>` — backtrace from last known handler
   - `crash> struct phantom_instance <addr>` — inspect per-CPU instance state
4. Companion script `tools/crash-scripts/phantom-state.py` automates extraction of Phantom-specific state (instance status, dirty list, VMCS last-snapshot values) from the crash dump.

**Serial console to a second machine is a hard requirement** — not optional. Without it, debugging host panics in the nested KVM environment is infeasible. Set up in Week 1 before writing any VMX code.

## debug.c Skeleton (Week 1 Setup)

```c
/* debug.c — first-class component, set up from week 1 */

/* Rule: hot-path events ALWAYS use trace_printk, never printk */

void phantom_dump_vmcs(struct phantom_instance *inst, u32 exit_reason)
{
    trace_printk("PHANTOM VMCS DUMP [instance=%d, cpu=%d, exit_reason=%u, iteration=%llu]\n",
                 inst->id, smp_processor_id(), exit_reason, inst->iteration);
    trace_printk("  GUEST_RIP=0x%llx GUEST_RSP=0x%llx GUEST_RFLAGS=0x%llx\n",
                 vmcs_read(GUEST_RIP), vmcs_read(GUEST_RSP),
                 vmcs_read(GUEST_RFLAGS));
    trace_printk("  GUEST_CR0=0x%llx GUEST_CR3=0x%llx GUEST_CR4=0x%llx\n",
                 vmcs_read(GUEST_CR0), vmcs_read(GUEST_CR3),
                 vmcs_read(GUEST_CR4));
    trace_printk("  EXIT_QUAL=0x%llx VM_INSTR_ERROR=%u\n",
                 vmcs_read(EXIT_QUALIFICATION),
                 vmcs_read32(VM_INSTRUCTION_ERROR));
    /* ... all segment registers, MSRs, interrupt state ... */
}

/* Hot-path macros — compiled to no-ops in production */
#ifdef PHANTOM_DEBUG
#define PHANTOM_TRACE_VM_ENTRY(inst) \
    trace_printk("VMX_ENTRY inst=%d iter=%llu\n", (inst)->id, (inst)->iteration)
#define PHANTOM_TRACE_VM_EXIT(inst, reason) \
    trace_printk("VMX_EXIT inst=%d reason=%u\n", (inst)->id, reason)
#define PHANTOM_TRACE_COW(gpa, priv_hpa) \
    trace_printk("COW gpa=0x%llx priv_hpa=0x%llx\n", gpa, priv_hpa)
#else
#define PHANTOM_TRACE_VM_ENTRY(inst)        do {} while(0)
#define PHANTOM_TRACE_VM_EXIT(inst, reason) do {} while(0)
#define PHANTOM_TRACE_COW(gpa, priv_hpa)   do {} while(0)
#endif
```

## Cross-Task References

- **Task 1.1** (Bootstrap): debug.c skeleton, `trace_printk` for hot-path events from Week 1
- **Task 1.2** (VMCS): VMCS dump-on-exit-failure, VMCS field validator
- **Task 1.3** (EPT): EPT walker/dumper, `PHANTOM_DEBUG_DUMP_EPT` ioctl
- **Task 1.4** (CoW): Dirty list inspector, `PHANTOM_DEBUG_DUMP_DIRTY_LIST` ioctl
- **Task 0.1** (Spike): kdump procedure — serial console, crash utility procedure
