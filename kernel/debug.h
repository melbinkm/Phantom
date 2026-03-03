// SPDX-License-Identifier: GPL-2.0-only
/*
 * debug.h — PHANTOM_DEBUG-gated trace macros and debug declarations
 *
 * Hot-path events use trace_printk(), not printk().  All macros are
 * compiled to no-ops when PHANTOM_DEBUG is not defined.
 *
 * VMCS dump and field validator are defined in debug.c and are only
 * called from slow-path contexts (module init, unexpected VM exit).
 */
#ifndef PHANTOM_DEBUG_H
#define PHANTOM_DEBUG_H

#include <linux/types.h>
#include <linux/compiler.h>

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

#endif /* PHANTOM_DEBUG_H */
