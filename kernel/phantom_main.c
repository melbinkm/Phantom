// SPDX-License-Identifier: GPL-2.0-only
/*
 * phantom_main.c — module entry/exit, chardev wiring, VMXON orchestration
 *
 * Module init sequence (goto-cleanup pattern):
 *   1. phantom_vmx_check_cpu_features()     — hard gates
 *   2. alloc_cpumask_var()                  — cpumask allocation
 *   3. phantom_parse_cores_param()           — parse "cores=" parameter
 *   4. phantom_kvm_intel_check()            — advisory kvm_intel warning
 *   5. phantom_debug_init()                 — debug subsystem
 *   6. phantom_chardev_register()           — /dev/phantom
 *   7. phantom_vmxon_all()                  — VMXON on each core
 *   8. phantom_vmcs_alloc_all()             — VMCS alloc + VMPTRLD
 *   9. pdev->initialized = true
 *
 * Module cleanup (reverse order, every resource freed):
 *   phantom_vmcs_free_all()
 *   phantom_vmxoff_all()
 *   phantom_chardev_unregister()
 *   phantom_debug_exit()
 *   free_cpumask_var()
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/smp.h>
#include <linux/rcupdate.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>

#include "phantom.h"
#include "vmx_core.h"
#include "interface.h"
#include "debug.h"

/* ------------------------------------------------------------------
 * Module parameters
 * ------------------------------------------------------------------ */

/* Comma-separated physical CPU numbers to use for VMX-root fuzzing.
 * Default "0" is safe for development inside a nested KVM guest.
 * Production runs should specify isolated CPUs (e.g. "2,3,4,5").
 */
char *phantom_cores = "0";
module_param(phantom_cores, charp, 0444);
MODULE_PARM_DESC(phantom_cores,
	"Comma-separated physical CPU indices to use (default: \"0\")");

int phantom_max_memory_mb = 512;
module_param(phantom_max_memory_mb, int, 0444);
MODULE_PARM_DESC(phantom_max_memory_mb,
	"Maximum aggregate guest memory in MB (default: 512)");

/* ------------------------------------------------------------------
 * Global device context
 * ------------------------------------------------------------------ */

struct phantom_dev phantom_global_dev;
EXPORT_SYMBOL_GPL(phantom_global_dev);

/* ------------------------------------------------------------------
 * Core parameter parser
 * ------------------------------------------------------------------ */

/**
 * phantom_parse_cores_param - Parse phantom_cores string into cpumask.
 * @mask: Output cpumask (must be allocated by caller).
 *
 * Accepts a comma-separated list of decimal CPU numbers.
 * Each CPU is validated: must be online and < nr_cpu_ids.
 *
 * Returns 0 on success, -EINVAL on malformed input, -ENODEV if any
 * specified CPU is offline.
 */
int phantom_parse_cores_param(cpumask_var_t mask)
{
	char *buf, *tok, *pos;
	int ret = 0;

	cpumask_clear(mask);

	buf = kstrdup(phantom_cores, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	pos = buf;
	while ((tok = strsep(&pos, ",")) != NULL) {
		long cpu_id;

		if (*tok == '\0')
			continue;

		ret = kstrtol(tok, 10, &cpu_id);
		if (ret) {
			pr_err("phantom: invalid CPU id '%s' in cores= param\n",
			       tok);
			ret = -EINVAL;
			goto out;
		}

		if (cpu_id < 0 || cpu_id >= nr_cpu_ids) {
			pr_err("phantom: CPU %ld out of range [0, %d)\n",
			       cpu_id, nr_cpu_ids);
			ret = -EINVAL;
			goto out;
		}

		if (!cpu_online(cpu_id)) {
			pr_err("phantom: CPU %ld is not online\n", cpu_id);
			ret = -ENODEV;
			goto out;
		}

		cpumask_set_cpu(cpu_id, mask);
	}

	if (cpumask_empty(mask)) {
		pr_err("phantom: cores= parameter produced an empty CPU set\n");
		ret = -EINVAL;
		goto out;
	}

	pr_info("phantom: target CPUs: %*pbl\n",
		cpumask_pr_args(mask));

out:
	kfree(buf);
	return ret;
}

/* ------------------------------------------------------------------
 * Advisory kvm_intel conflict check
 * ------------------------------------------------------------------ */

/**
 * phantom_kvm_intel_check - Advisory check for kvm_intel VMX conflict.
 *
 * Checks CR4.VMXE on the CURRENT CPU only (the calling context).
 * Cross-CPU IPIs via smp_call_function_single are intentionally NOT used:
 * after a prior VMLAUNCH+VMXOFF cycle, any function-call IPI to the target
 * CPU causes a triple fault in nested KVM due to KVM L0's post-exit state.
 *
 * The VMXON instruction itself is the authoritative conflict test; this is
 * an advisory pre-check only.  Logs a warning if CR4.VMXE is set on the
 * calling CPU, which indicates another VMX user (e.g. kvm_intel) is active.
 */
void phantom_kvm_intel_check(const struct cpumask *cpumask)
{
	/*
	 * Read CR4.VMXE on the calling CPU only.  We cannot safely IPI
	 * target CPUs here because after a prior VMLAUNCH+VMXOFF cycle,
	 * function-call IPIs to those CPUs trigger triple faults.
	 *
	 * If we are currently running on one of the target CPUs, check it.
	 * Otherwise, skip — VMXON will detect the conflict authoritatively.
	 */
	if (cpumask_test_cpu(smp_processor_id(), cpumask)) {
		if (native_read_cr4() & X86_CR4_VMXE) {
			pr_warn("phantom: CPU%d: CR4.VMXE is already set — "
				"kvm_intel may be loaded; "
				"run: rmmod kvm_intel\n",
				smp_processor_id());
		}
	} else {
		pr_info("phantom: kvm_intel advisory check skipped "
			"(not running on target CPUs — "
			"VMXON will detect conflicts)\n");
	}
}

/* ------------------------------------------------------------------
 * Module init
 * ------------------------------------------------------------------ */

static int __init phantom_init(void)
{
	struct phantom_dev *pdev = &phantom_global_dev;
	int ret;

	pr_info("phantom: loading (version 0x%08x)\n", PHANTOM_VERSION);

	memset(pdev, 0, sizeof(*pdev));

	/* Step 1: CPU feature detection — hard gates */
	ret = phantom_vmx_check_cpu_features(&pdev->features);
	if (ret) {
		pr_err("phantom: CPU feature check failed: %d\n", ret);
		return ret;
	}

	/* Step 2: allocate cpumask */
	if (!alloc_cpumask_var(&pdev->vmx_cpumask, GFP_KERNEL)) {
		pr_err("phantom: failed to allocate cpumask\n");
		return -ENOMEM;
	}

	/* Step 3: parse cores= parameter */
	ret = phantom_parse_cores_param(pdev->vmx_cpumask);
	if (ret)
		goto fail_cpumask;

	/* Step 4: advisory kvm_intel conflict check */
	phantom_kvm_intel_check(pdev->vmx_cpumask);

	/* Step 5: debug subsystem */
	ret = phantom_debug_init();
	if (ret)
		goto fail_cpumask;

	/* Step 6: chardev registration */
	ret = phantom_chardev_register(pdev);
	if (ret) {
		pr_err("phantom: chardev registration failed: %d\n", ret);
		goto fail_debug;
	}

	/*
	 * Step 7: Allocate VMXON region pages and read VMX revision ID.
	 *
	 * phantom_vmxon_all no longer executes the VMXON instruction via
	 * smp_call_function_single.  That IPI-based approach caused a triple
	 * fault on the second module load in nested KVM environments: after the
	 * first load's VMLAUNCH+VMXOFF cycle, KVM L0's nested VMX tracking for
	 * the target CPU is in a post-nested-exit state, and any function-call
	 * IPI to that CPU triggers a crash.
	 *
	 * The VMXON instruction itself now runs inside the vCPU thread in step
	 * 8b below, eliminating all cross-CPU IPIs during VMX init.
	 */
	ret = phantom_vmxon_all(pdev->vmx_cpumask);
	if (ret) {
		pr_err("phantom: VMXON region alloc failed: %d\n", ret);
		goto fail_chardev;
	}

	/*
	 * Step 8: Start per-CPU vCPU kernel threads.
	 *
	 * Each thread is pinned to its target CPU.  At startup, the thread
	 * performs VMXON + VMCS alloc + VMPTRLD locally (IPI-free), then
	 * signals vcpu_init_done.  We wait for that signal in step 8b below.
	 *
	 * This replaces the old phantom_vmcs_alloc_all / smp_call_function_single
	 * approach which was unsafe after a prior VMLAUNCH+VMXOFF cycle.
	 */
	{
		int cpu;

		for_each_cpu(cpu, pdev->vmx_cpumask) {
			struct phantom_vmx_cpu_state *state;

			state = per_cpu_ptr(&phantom_vmx_state, cpu);
			ret = phantom_vcpu_thread_start(state);
			if (ret) {
				pr_err("phantom: CPU%d: vCPU thread start "
				       "failed: %d\n", cpu, ret);
				/* Stop already-started threads */
				{
					int c;

					for_each_cpu(c, pdev->vmx_cpumask) {
						struct phantom_vmx_cpu_state *s;

						if (c == cpu)
							break;
						s = per_cpu_ptr(&phantom_vmx_state,
								c);
						phantom_vcpu_thread_stop(s);
					}
				}
				goto fail_vmxon;
			}
		}
	}

	/*
	 * Step 8b: Wait for each vCPU thread to complete its per-CPU init
	 * (VMXON + VMCS alloc + VMPTRLD).  The thread signals vcpu_init_done
	 * when it is done.
	 */
	{
		int cpu;

		for_each_cpu(cpu, pdev->vmx_cpumask) {
			struct phantom_vmx_cpu_state *state;

			state = per_cpu_ptr(&phantom_vmx_state, cpu);
			ret = phantom_vcpu_thread_wait_init(state);
			if (ret) {
				pr_err("phantom: CPU%d: vCPU init failed: %d\n",
				       cpu, ret);
				/* Stop all threads (each will VMXOFF if needed) */
				{
					int c;

					for_each_cpu(c, pdev->vmx_cpumask) {
						struct phantom_vmx_cpu_state *s;

						s = per_cpu_ptr(&phantom_vmx_state,
								c);
						phantom_vcpu_thread_stop(s);
					}
				}
				goto fail_vmxon;
			}
		}
	}

	pdev->nr_vmx_cores = cpumask_weight(pdev->vmx_cpumask);

	/* Step 9: mark as fully initialised */
	pdev->initialized = true;

	pr_info("phantom: loaded, VMX active on %d core(s)\n",
		pdev->nr_vmx_cores);
	return 0;

fail_vmxon:
	phantom_vmxoff_all(pdev->vmx_cpumask);
fail_chardev:
	phantom_chardev_unregister(pdev);
fail_debug:
	phantom_debug_exit();
fail_cpumask:
	free_cpumask_var(pdev->vmx_cpumask);
	return ret;
}

/* ------------------------------------------------------------------
 * Module cleanup
 * ------------------------------------------------------------------ */

static void __exit phantom_exit(void)
{
	struct phantom_dev *pdev = &phantom_global_dev;

	pr_info("phantom: unloading\n");

	pdev->initialized = false;

	/*
	 * Shutdown order (reverse of init):
	 *
	 * 1. VMCLEAR the VMCS on each target CPU.  This must happen while the
	 *    EPT and guest pages are still valid — the processor may reference
	 *    them internally during the VMCLEAR operation.  VMCLEAR also marks
	 *    the VMCS as "not current", preventing any further VM entries.
	 *
	 * 2. Free the VMCS region page (after VMCLEAR has completed).
	 *
	 * 3. Free EPT and guest memory pages (after the VMCS no longer
	 *    references them as an "active" VMCS).
	 *
	 * 4. VMXOFF to exit VMX root mode.
	 *
	 * This ordering ensures we never free pages that the CPU might still
	 * reference through EPT or VMCS internal state.
	 */
	/*
	 * Step 1: Stop vCPU threads.
	 *
	 * Each thread performs VMCLEAR + VMXOFF locally on its pinned CPU
	 * (no cross-CPU IPIs).  After phantom_vcpu_thread_stop() returns,
	 * VMX root mode has been exited on the target CPU.
	 */
	{
		int cpu;

		for_each_cpu(cpu, pdev->vmx_cpumask) {
			struct phantom_vmx_cpu_state *state;

			state = per_cpu_ptr(&phantom_vmx_state, cpu);
			phantom_vcpu_thread_stop(state);
		}
	}

	/*
	 * Step 2: Wait for KVM L0's deferred nested VMX cleanup.
	 *
	 * After VMXOFF, KVM L0's free_nested() may schedule RCU callbacks
	 * and deferred TLB flushes.  synchronize_rcu() blocks until all
	 * pending RCU grace periods elapse, ensuring KVM's deferred work
	 * completes before rmmod returns.  The next insmod sees clean state.
	 */
	synchronize_rcu();

	/*
	 * Step 3: Free VMCS region pages.
	 * VMCLEAR + VMXOFF already done by vCPU thread in step 1.
	 */
	phantom_vmcs_free_all(pdev->vmx_cpumask);

	/*
	 * Step 4: Free EPT and guest memory pages.
	 * Safe now — VMCLEAR has removed CPU references to the VMCS,
	 * and VMXOFF has exited VMX root mode entirely.
	 */
	{
		int cpu;

		for_each_cpu(cpu, pdev->vmx_cpumask) {
			struct phantom_vmx_cpu_state *state;

			state = per_cpu_ptr(&phantom_vmx_state, cpu);
			phantom_vmcs_teardown(state);
		}
	}

	/*
	 * Step 5: Release VMXON region pages.
	 * phantom_vmxoff_all() skips the VMXOFF SMP call (already done in
	 * step 1) and only frees the vmxon_region backing page.
	 */
	phantom_vmxoff_all(pdev->vmx_cpumask);
	phantom_chardev_unregister(pdev);
	phantom_debug_exit();
	free_cpumask_var(pdev->vmx_cpumask);

	pr_info("phantom: unloaded\n");
}

module_init(phantom_init);
module_exit(phantom_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Phantom Project");
MODULE_DESCRIPTION("Bare-metal hypervisor fuzzer — VMCS + guest execution");
MODULE_VERSION("1.2.0");
