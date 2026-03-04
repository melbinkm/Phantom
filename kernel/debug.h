// SPDX-License-Identifier: GPL-2.0-only
/*
 * debug.h — PHANTOM_DEBUG-gated trace macros and debug declarations
 *
 * Hot-path events use trace_printk(), not printk().  All macros are
 * compiled to no-ops when PHANTOM_DEBUG is not defined.
 *
 * VMCS dump and field validator are defined in debug.c and are only
 * called from slow-path contexts (module init, unexpected VM exit).
 *
 * EPT walker (phantom_walk_ept / phantom_debug_dump_ept) uses
 * trace_printk to output GPA→HPA mappings without printk overhead.
 */
#ifndef PHANTOM_DEBUG_H
#define PHANTOM_DEBUG_H

#include <linux/types.h>
#include <linux/compiler.h>

/* Forward declarations to avoid circular includes */
struct phantom_ept_state;
struct phantom_vmx_cpu_state;

/* ------------------------------------------------------------------
 * Hot-path trace macros — active only when PHANTOM_DEBUG is defined.
 * ------------------------------------------------------------------ */

#ifdef PHANTOM_DEBUG

#define PHANTOM_TRACE_VM_ENTRY(cpu_id)					\
	trace_printk("PHANTOM VMX_ENTRY cpu=%d\n", (cpu_id))

#define PHANTOM_TRACE_VM_EXIT(cpu_id, reason)				\
	trace_printk("PHANTOM VMX_EXIT cpu=%d reason=%u\n",		\
		     (cpu_id), (reason))

#define PHANTOM_TRACE_COW(gpa, priv_hpa)				\
	trace_printk("PHANTOM COW gpa=0x%llx priv=0x%llx\n",		\
		     (u64)(gpa), (u64)(priv_hpa))

#define PHANTOM_TRACE_SNAPSHOT(cpu_id, dirty_n)				\
	trace_printk("PHANTOM SNAPSHOT_RESTORE cpu=%d dirty=%u\n",	\
		     (cpu_id), (dirty_n))

#define PHANTOM_TRACE_HYPERCALL(cpu_id, nr)				\
	trace_printk("PHANTOM HYPERCALL cpu=%d nr=%llu\n",		\
		     (cpu_id), (u64)(nr))

#else /* !PHANTOM_DEBUG */

#define PHANTOM_TRACE_VM_ENTRY(cpu_id)		do {} while (0)
#define PHANTOM_TRACE_VM_EXIT(cpu_id, reason)	do {} while (0)
#define PHANTOM_TRACE_COW(gpa, priv_hpa)	do {} while (0)
#define PHANTOM_TRACE_SNAPSHOT(cpu_id, dn)	do {} while (0)
#define PHANTOM_TRACE_HYPERCALL(cpu_id, nr)	do {} while (0)

#endif /* PHANTOM_DEBUG */

/* ------------------------------------------------------------------
 * Slow-path debug functions (defined in debug.c)
 * ------------------------------------------------------------------ */

/**
 * phantom_dump_vmcs - Dump current VMCS guest-state to trace ring buffer.
 * @inst_id:    Instance identifier (for log correlation).
 * @cpu:        Physical CPU index.
 * @exit_reason: VM-exit reason code.
 * @iteration:  Fuzzing iteration counter.
 *
 * Must only be called from VMX-root context with a current VMCS loaded.
 * Uses trace_printk — never printk — so safe from interrupt context.
 */
void phantom_dump_vmcs(int inst_id, int cpu, u32 exit_reason,
		       u64 iteration);

#ifdef PHANTOM_DEBUG
/**
 * phantom_validate_vmcs - Validate VMCS guest state against SDM §26.3.
 *
 * Checks CR0/CR4 fixed bits, CS access rights, IA-32e consistency,
 * VMCS link pointer, and activity state.
 *
 * Returns 0 if all checks pass, -EINVAL on any violation.
 * Compiled out (not available) in non-debug builds.
 */
int phantom_validate_vmcs(void);
#endif

/**
 * phantom_debug_init - Initialise debug subsystem.
 * Returns 0 always.
 */
int phantom_debug_init(void);

/**
 * phantom_debug_exit - Tear down debug subsystem.
 */
void phantom_debug_exit(void);

/**
 * phantom_walk_ept - Walk the 4-level EPT and emit mappings via trace_printk.
 * @ept: EPT state to walk.
 *
 * Traverses all levels of the EPT and prints each mapped GPA range,
 * its HPA, permissions, and memory type.  Output goes to the trace
 * ring buffer — read via /sys/kernel/debug/tracing/trace.
 *
 * Slow-path only.  Must NOT be called from a VM-exit handler.
 */
void phantom_walk_ept(struct phantom_ept_state *ept);

/**
 * phantom_debug_dump_ept - Wrapper: dump EPT for a given VMX CPU state.
 * @state: Per-CPU VMX state (must have pages_allocated set).
 *
 * Calls phantom_walk_ept() on state->ept.
 * Returns 0 on success, -EINVAL if pages not allocated.
 */
int phantom_debug_dump_ept(struct phantom_vmx_cpu_state *state);

/**
 * phantom_debug_dump_dirty_list - Dump CoW dirty list entries.
 * @state: Per-CPU VMX state (must have dirty_list allocated).
 *
 * Emits each dirty entry via trace_printk:
 *   "DIRTY_ENTRY gpa=0x%llx orig=0x%llx priv=0x%llx iter=%u"
 * Also emits dirty overflow count if non-zero:
 *   "DIRTY_OVERFLOW count=N"
 *
 * Output goes to /sys/kernel/debug/tracing/trace.
 * Returns 0 on success, -EINVAL if dirty_list not allocated.
 */
int phantom_debug_dump_dirty_list(struct phantom_vmx_cpu_state *state);

/**
 * phantom_debug_dump_dirty_overflow - Emit dirty list overflow count.
 * @state: Per-CPU VMX state.
 *
 * Emits one trace_printk line: "DIRTY_OVERFLOW count=N"
 * Returns 0 always (even if overflow count is zero).
 */
int phantom_debug_dump_dirty_overflow(struct phantom_vmx_cpu_state *state);

#endif /* PHANTOM_DEBUG_H */
