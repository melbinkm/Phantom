// SPDX-License-Identifier: GPL-2.0-only
/*
 * debug.h — PHANTOM_DEBUG-gated trace macros and debug declarations
 *
 * Hot-path events use trace_printk(), not printk().  All macros are
 * compiled to no-ops when PHANTOM_DEBUG is not defined.
 *
 * VMCS dump and EPT walker are defined in debug.c and are only called
 * from slow-path contexts (module init, unexpected VM exit).
 */
#ifndef PHANTOM_DEBUG_H
#define PHANTOM_DEBUG_H

#include <linux/types.h>
#include <linux/compiler.h>

/* ------------------------------------------------------------------
 * Hot-path trace macros — active only when PHANTOM_DEBUG is defined.
 * Using trace_printk keeps them completely off the critical path in
 * production: the macro expands to nothing and the compiler eliminates
 * any dead code around the call site.
 * ------------------------------------------------------------------ */

#ifdef PHANTOM_DEBUG

#define PHANTOM_TRACE_VM_ENTRY(inst_id)					\
	trace_printk("PHANTOM VMX_ENTRY inst=%d\n", (inst_id))

#define PHANTOM_TRACE_VM_EXIT(inst_id, reason)				\
	trace_printk("PHANTOM VMX_EXIT inst=%d reason=%u\n",		\
		     (inst_id), (reason))

#define PHANTOM_TRACE_COW(gpa, priv_hpa)				\
	trace_printk("PHANTOM COW gpa=0x%llx priv=0x%llx\n",		\
		     (u64)(gpa), (u64)(priv_hpa))

#define PHANTOM_TRACE_SNAPSHOT(inst_id, dirty_n)			\
	trace_printk("PHANTOM SNAPSHOT_RESTORE inst=%d dirty=%u\n",	\
		     (inst_id), (dirty_n))

#define PHANTOM_TRACE_HYPERCALL(inst_id, nr)				\
	trace_printk("PHANTOM HYPERCALL inst=%d nr=%llu\n",		\
		     (inst_id), (u64)(nr))

#else /* !PHANTOM_DEBUG */

#define PHANTOM_TRACE_VM_ENTRY(inst_id)		do {} while (0)
#define PHANTOM_TRACE_VM_EXIT(inst_id, reason)	do {} while (0)
#define PHANTOM_TRACE_COW(gpa, priv_hpa)	do {} while (0)
#define PHANTOM_TRACE_SNAPSHOT(inst_id, dn)	do {} while (0)
#define PHANTOM_TRACE_HYPERCALL(inst_id, nr)	do {} while (0)

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

/**
 * phantom_debug_init - Initialise debug subsystem (no-op stub for 1.1).
 *
 * Reserved for future debugfs node creation.
 * Returns 0 always.
 */
int phantom_debug_init(void);

/**
 * phantom_debug_exit - Tear down debug subsystem.
 */
void phantom_debug_exit(void);

#endif /* PHANTOM_DEBUG_H */
