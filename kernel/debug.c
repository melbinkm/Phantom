// SPDX-License-Identifier: GPL-2.0-only
/*
 * debug.c — VMCS dump, trace skeleton, and debug subsystem init
 *
 * All hot-path events use trace_printk() (guarded by PHANTOM_DEBUG).
 * The VMCS dump is a slow-path diagnostic tool called only on unexpected
 * VM exits.  It also uses trace_printk so it does not bloat the main
 * printk ring buffer during normal operation.
 *
 * VMCS read helpers use vmcs_read{32,64} from asm/vmx.h where available;
 * for task 1.1 the VMCS dump is a stub that will be expanded in 1.3 once
 * we have a working VMCS with meaningful guest state.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>

#include "phantom.h"
#include "debug.h"

/* ------------------------------------------------------------------
 * phantom_dump_vmcs
 *
 * In task 1.1, the VMCS has been allocated and cleared but no guest
 * state has been written to it.  The full field dump is implemented in
 * task 1.3 after VMCS guest-state initialisation.  This stub records
 * the exit context so that at least the exit reason and iteration
 * counter appear in trace records on any unexpected exit.
 * ------------------------------------------------------------------ */

/**
 * phantom_dump_vmcs - Dump VMCS exit context to trace ring buffer.
 * @inst_id:     Instance identifier (for log correlation).
 * @cpu:         Physical CPU index.
 * @exit_reason: VM-exit reason code from exit-reason VMCS field.
 * @iteration:   Fuzzing iteration counter at time of exit.
 *
 * Uses trace_printk — never printk.  Safe from interrupt context.
 * Full field dump will be wired up in task 1.3.
 */
void phantom_dump_vmcs(int inst_id, int cpu, u32 exit_reason,
		       u64 iteration)
{
	trace_printk("PHANTOM VMCS DUMP [inst=%d cpu=%d exit_reason=%u "
		     "iter=%llu]\n",
		     inst_id, cpu, exit_reason, iteration);

	/*
	 * Full guest-state dump (RIP, RSP, RFLAGS, CR0, CR3, CR4,
	 * segment registers, MSRs) is added in task 1.3 once
	 * phantom_vmcs_read() helpers are in place.
	 *
	 * Placeholder comment preserved to mark the extension point.
	 */
	trace_printk("PHANTOM VMCS DUMP: (full field dump available "
		     "after task 1.3)\n");
}

/* ------------------------------------------------------------------
 * Debug subsystem init/exit
 *
 * Currently a no-op; reserved for future debugfs node creation
 * (snapshot_restore_cycles, dirty_count, pool_exhaustions, etc.)
 * that are specified in later phases.
 * ------------------------------------------------------------------ */

/**
 * phantom_debug_init - Initialise debug subsystem.
 *
 * Returns 0 always.
 */
int phantom_debug_init(void)
{
	pr_info("phantom: debug subsystem initialised\n");
	return 0;
}

/**
 * phantom_debug_exit - Tear down debug subsystem.
 */
void phantom_debug_exit(void)
{
	pr_info("phantom: debug subsystem exiting\n");
}
