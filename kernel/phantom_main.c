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
#include <asm/cr4.h>

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

struct phantom_cr4_check_work {
	bool vmxe_set;
};

static void phantom_read_cr4_vmxe(void *data)
{
	struct phantom_cr4_check_work *work = data;

	if (read_cr4() & X86_CR4_VMXE)
		work->vmxe_set = true;
}

/**
 * phantom_kvm_intel_check - Advisory check for kvm_intel VMX conflict.
 *
 * Reads CR4.VMXE on each target core.  If set, emits a pr_warn
 * suggesting that kvm_intel be unloaded.  This is a TOCTOU pre-check
 * only; VMXON itself is the authoritative ownership test.
 */
void phantom_kvm_intel_check(const struct cpumask *cpumask)
{
	struct phantom_cr4_check_work work;
	int cpu;

	for_each_cpu(cpu, cpumask) {
		work.vmxe_set = false;
		smp_call_function_single(cpu, phantom_read_cr4_vmxe,
					 &work, 1);
		if (work.vmxe_set) {
			pr_warn("phantom: CPU%d: CR4.VMXE is already set — "
				"kvm_intel may be loaded; "
				"run: rmmod kvm_intel\n", cpu);
		}
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

	/* Step 7: VMXON on all target cores */
	ret = phantom_vmxon_all(pdev->vmx_cpumask);
	if (ret) {
		pr_err("phantom: VMXON failed: %d\n", ret);
		goto fail_chardev;
	}

	/* Step 8: VMCS allocation and VMPTRLD on all target cores */
	ret = phantom_vmcs_alloc_all(pdev->vmx_cpumask);
	if (ret) {
		pr_err("phantom: VMCS allocation failed: %d\n", ret);
		goto fail_vmxon;
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

	phantom_vmcs_free_all(pdev->vmx_cpumask);
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
MODULE_DESCRIPTION("Bare-metal hypervisor fuzzer — VMX bootstrap");
MODULE_VERSION("1.1.0");
