// SPDX-License-Identifier: GPL-2.0-only
/*
 * vmx_core.c — VMX bootstrap: feature detection, VMXON/VMXOFF, VMCS alloc
 *
 * Responsibilities:
 *   - CPU feature detection (VT-x, EPT, Intel PT, XSAVE)
 *   - Per-CPU VMXON region allocation and VMXON execution
 *   - Per-CPU VMXOFF and CR4 restoration
 *   - Per-CPU VMCS allocation, VMCLEAR, VMPTRLD
 *   - Partial-failure rollback on multi-core init
 *
 * All operations that touch VMX hardware run via
 * smp_call_function_single() so they execute on the correct physical
 * CPU.  The calling thread's CPU is irrelevant.
 *
 * Hot-path discipline: no printk, no sleeping functions, no dynamic
 * allocation in VMXON/VMXOFF paths.  Allocation happens before the
 * smp_call, error codes propagate via per-CPU state fields.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/percpu.h>
#include <asm/processor.h>
#include <asm/cpufeature.h>
#include <asm/cpuid.h>
#include <asm/msr.h>
#include <asm/tlbflush.h>
#include <asm/io.h>
#include <asm/vmx.h>

#include "phantom.h"
#include "vmx_core.h"
#include "debug.h"

/* Per-CPU VMX state — one entry per physical CPU */
DEFINE_PER_CPU(struct phantom_vmx_cpu_state, phantom_vmx_state);
EXPORT_SYMBOL_GPL(phantom_vmx_state);

/* ------------------------------------------------------------------
 * Low-level VMX instruction wrappers
 *
 * These inline functions encode the three VMXON return conditions from
 * Intel SDM Vol. 3C §30.3:
 *   CF=1  →  VMX already active (or other hard error)   → -EBUSY
 *   ZF=1  →  VM-instruction error (see VM_INSTRUCTION_ERROR) → -EIO
 *   both clear → success
 * ------------------------------------------------------------------ */

static inline int __vmxon(u64 phys_addr)
{
	u8 err_cf, err_zf;

	asm volatile(
		"vmxon %[addr]\n\t"
		"setc  %[cf]\n\t"
		"setz  %[zf]"
		: [cf] "=qm" (err_cf),
		  [zf] "=qm" (err_zf)
		: [addr] "m" (phys_addr)
		: "cc", "memory");

	if (err_cf)
		return -EBUSY;	/* VMX already active on this core */
	if (err_zf)
		return -EIO;	/* VM-instruction error */
	return 0;
}

static inline void __vmxoff(void)
{
	asm volatile("vmxoff" : : : "cc", "memory");
}

static inline int __vmclear(u64 phys_addr)
{
	u8 err_cf, err_zf;

	asm volatile(
		"vmclear %[addr]\n\t"
		"setc    %[cf]\n\t"
		"setz    %[zf]"
		: [cf] "=qm" (err_cf),
		  [zf] "=qm" (err_zf)
		: [addr] "m" (phys_addr)
		: "cc", "memory");

	if (err_cf || err_zf)
		return -EIO;
	return 0;
}

static inline int __vmptrld(u64 phys_addr)
{
	u8 err_cf, err_zf;

	asm volatile(
		"vmptrld %[addr]\n\t"
		"setc    %[cf]\n\t"
		"setz    %[zf]"
		: [cf] "=qm" (err_cf),
		  [zf] "=qm" (err_zf)
		: [addr] "m" (phys_addr)
		: "cc", "memory");

	if (err_cf || err_zf)
		return -EIO;
	return 0;
}

/* ------------------------------------------------------------------
 * Feature detection
 * ------------------------------------------------------------------ */

/**
 * phantom_vmx_check_cpu_features - Detect and validate CPU VMX capabilities.
 * @feat: Output structure populated on success.
 *
 * Hard requirements (return -ENODEV if missing):
 *   - VT-x (CPUID.1:ECX[5])
 *   - EPT enabled in secondary proc-based controls
 *   - EPT 4-level page walk
 *   - EPT WB memory type
 *
 * Advisory (logged only, not fatal for task 1.1):
 *   - EPT 2MB pages
 *   - EPT A/D bits
 *   - Intel PT
 *   - XSAVE
 */
int phantom_vmx_check_cpu_features(struct phantom_cpu_features *feat)
{
	u32 ecx_1, ebx_7;
	u64 vmx_basic, ept_vpid_cap;
	u64 secondary_ctls_msr;
	int ret;

	memset(feat, 0, sizeof(*feat));

	/* VT-x: CPUID leaf 1, ECX bit 5 */
	ecx_1 = cpuid_ecx(1);
	feat->vtx = !!(ecx_1 & BIT(5));
	if (!feat->vtx) {
		pr_err("phantom: VT-x (VMX) not supported by this CPU\n");
		return -ENODEV;
	}

	/* Read VMX basic capabilities */
	ret = rdmsrl_safe(MSR_IA32_VMX_BASIC, &vmx_basic);
	if (ret) {
		pr_err("phantom: failed to read MSR_IA32_VMX_BASIC\n");
		return -ENODEV;
	}
	feat->vmx_revision = (u32)(vmx_basic & VMX_BASIC_REVISION_MASK);
	feat->true_ctls    = !!(vmx_basic & VMX_BASIC_TRUE_CTLS);

	pr_info("phantom: VMX revision ID: 0x%08x, TRUE controls: %s\n",
		feat->vmx_revision, feat->true_ctls ? "yes" : "no");

	/*
	 * Secondary proc-based controls availability: bit 31 of the
	 * primary proc-based controls "allowed-1" field.  If the TRUE
	 * controls MSR is available use that; otherwise use the legacy one.
	 */
	{
		u64 ctls_msr_id = feat->true_ctls ?
			MSR_IA32_VMX_TRUE_PROCBASED_CTLS :
			MSR_IA32_VMX_PROCBASED_CTLS;
		u64 ctls_val;

		if (rdmsrl_safe(ctls_msr_id, &ctls_val)) {
			pr_err("phantom: failed to read proc-based CTL MSR\n");
			return -ENODEV;
		}
		/*
		 * Allowed-1 bits are in the high 32 bits of the MSR.
		 * Bit 31 of allowed-1 = secondary controls may be enabled.
		 */
		if (!(ctls_val & BIT_ULL(63))) {
			pr_err("phantom: secondary proc-based controls "
			       "not supported\n");
			return -ENODEV;
		}
	}

	/* Secondary proc-based controls: EPT enable (SECONDARY_EXEC_ENABLE_EPT
	 * = BIT(1)).  The "allowed-1" mask lives in the high 32 bits of the
	 * MSR.  Bit 1 in the high half = bit 33 of the 64-bit MSR value.
	 */
	if (rdmsrl_safe(MSR_IA32_VMX_PROCBASED_CTLS2, &secondary_ctls_msr)) {
		pr_err("phantom: failed to read MSR_IA32_VMX_PROCBASED_CTLS2\n");
		return -ENODEV;
	}
	feat->ept = !!(secondary_ctls_msr &
		       ((u64)SECONDARY_EXEC_ENABLE_EPT << 32));
	if (!feat->ept) {
		pr_err("phantom: EPT not supported by this CPU\n");
		return -ENODEV;
	}

	/* EPT/VPID capability details */
	if (rdmsrl_safe(MSR_IA32_VMX_EPT_VPID_CAP, &ept_vpid_cap)) {
		pr_err("phantom: failed to read MSR_IA32_VMX_EPT_VPID_CAP\n");
		return -ENODEV;
	}

	/* Use kernel-defined EPT capability bit names from <asm/vmx.h> */
	feat->ept_4lvl = !!(ept_vpid_cap & VMX_EPT_PAGE_WALK_4_BIT);
	feat->ept_wb   = !!(ept_vpid_cap & VMX_EPTP_WB_BIT);
	feat->ept_2mb  = !!(ept_vpid_cap & VMX_EPT_2MB_PAGE_BIT);
	feat->ept_ad   = !!(ept_vpid_cap & VMX_EPT_AD_BIT);

	if (!feat->ept_4lvl) {
		pr_err("phantom: EPT 4-level page walk not supported\n");
		return -ENODEV;
	}
	if (!feat->ept_wb) {
		pr_err("phantom: EPT WB memory type not supported\n");
		return -ENODEV;
	}

	/* Advisory capabilities */
	if (!feat->ept_2mb)
		pr_info("phantom: EPT 2MB pages not supported (advisory)\n");
	if (!feat->ept_ad)
		pr_info("phantom: EPT A/D bits not supported (advisory)\n");

	/* Intel PT: CPUID leaf 7, EBX bit 25 */
	ebx_7 = cpuid_ebx(7);
	feat->intel_pt = !!(ebx_7 & BIT(25));
	if (!feat->intel_pt)
		pr_info("phantom: Intel PT not detected (advisory for Phase 1)\n");

	/* XSAVE: CPUID leaf 1, ECX bit 26 */
	feat->xsave = !!(ecx_1 & BIT(26));
	if (!feat->xsave)
		pr_info("phantom: XSAVE not supported (advisory for Phase 1)\n");

	pr_info("phantom: CPU features: EPT(4lvl=%d wb=%d 2mb=%d ad=%d) "
		"PT=%d XSAVE=%d\n",
		feat->ept_4lvl, feat->ept_wb, feat->ept_2mb, feat->ept_ad,
		feat->intel_pt, feat->xsave);

	return 0;
}

/* ------------------------------------------------------------------
 * Per-CPU VMXON worker
 *
 * Runs on the target CPU via smp_call_function_single().
 * The page pointer is pre-allocated by the calling thread; this
 * function only sets the revision ID, enables CR4.VMXE, and executes
 * VMXON.  On failure it restores CR4 and sets state->init_err.
 * ------------------------------------------------------------------ */

struct phantom_vmxon_work {
	u32  revision_id;
	int  result;		/* output: 0 or negative errno */
};

static void phantom_vmxon_cpu(void *data)
{
	struct phantom_vmxon_work *work = data;
	struct phantom_vmx_cpu_state *state;
	unsigned long cr4;
	u64 phys;
	u32 *rev_ptr;
	int cpu, ret;
	bool we_set_vmxe = false;

	cpu   = smp_processor_id();
	state = this_cpu_ptr(&phantom_vmx_state);

	state->cpu      = cpu;
	state->init_err = 0;

	/* Read current CR4 via hardware register (not the shadow, in case
	 * another module changed it without updating the per-CPU shadow).
	 * native_read_cr4() is a static inline — no export required.
	 */
	cr4 = native_read_cr4();
	state->saved_cr4 = cr4;

	/* Advisory pre-check: if CR4.VMXE is already set, another entity
	 * may own VMX on this core.  We still attempt VMXON — the hardware
	 * response (CF flag) is the authoritative ownership test.
	 */
	if (cr4 & X86_CR4_VMXE) {
		pr_warn("phantom: CPU%d: CR4.VMXE already set — "
			"VMX likely active (conflict possible)\n", cpu);
	} else {
		/* Set CR4.VMXE via cr4_set_bits() which updates both the
		 * hardware register and the per-CPU shadow atomically.
		 */
		cr4_set_bits(X86_CR4_VMXE);
		we_set_vmxe = true;
	}

	/* Write revision ID into the pre-allocated VMXON region */
	rev_ptr  = (u32 *)page_address(state->vmxon_region);
	*rev_ptr = work->revision_id;

	/* Physical address of the VMXON region */
	phys = page_to_phys(state->vmxon_region);

	/* Execute VMXON — this is the authoritative VMX ownership check */
	ret = __vmxon(phys);
	if (ret) {
		pr_err("phantom: CPU%d: VMXON failed (err=%d) — "
		       "is kvm_intel loaded?\n", cpu, ret);
		if (we_set_vmxe)
			cr4_clear_bits(X86_CR4_VMXE);
		state->vmx_active = false;
		state->init_err   = ret;
		work->result      = ret;
		return;
	}

	state->vmx_active = true;
	work->result      = 0;
	pr_info("phantom: CPU%d: VMX root entered successfully\n", cpu);
}

/* ------------------------------------------------------------------
 * Per-CPU VMXOFF worker
 * ------------------------------------------------------------------ */

static void phantom_vmxoff_cpu(void *data)
{
	struct phantom_vmx_cpu_state *state = this_cpu_ptr(&phantom_vmx_state);

	if (!state->vmx_active)
		return;

	__vmxoff();

	/* Restore CR4.VMXE to its pre-VMXON state.
	 * If we set VMXE (saved_cr4 did not have it), clear it now.
	 * If it was already set before us, leave it set.
	 */
	if (!(state->saved_cr4 & X86_CR4_VMXE))
		cr4_clear_bits(X86_CR4_VMXE);

	state->vmx_active = false;

	pr_info("phantom: CPU%d: VMX root exited\n", smp_processor_id());
}

/* ------------------------------------------------------------------
 * Public: phantom_vmxon_all
 * ------------------------------------------------------------------ */

/**
 * phantom_vmxon_all - Enter VMX root on every CPU in cpumask.
 *
 * Allocates VMXON regions (NUMA-local) for all target CPUs first, then
 * executes VMXON on each.  On partial failure, rolls back VMXOFF on
 * already-entered cores and frees all pages.
 */
int phantom_vmxon_all(const struct cpumask *cpumask)
{
	struct phantom_vmx_cpu_state *state;
	struct phantom_vmxon_work work;
	int cpu, n = 0, ret = 0;

	/* Read the revision ID from the BSP — it is the same on all cores */
	{
		u64 vmx_basic;

		if (rdmsrl_safe(MSR_IA32_VMX_BASIC, &vmx_basic)) {
			pr_err("phantom: failed to read VMX_BASIC for revision\n");
			return -EIO;
		}
		work.revision_id = (u32)(vmx_basic & VMX_BASIC_REVISION_MASK);
	}

	/* Phase 1: pre-allocate VMXON region pages (NUMA-local) */
	for_each_cpu(cpu, cpumask) {
		int node = cpu_to_node(cpu);

		state = per_cpu_ptr(&phantom_vmx_state, cpu);
		memset(state, 0, sizeof(*state));
		state->cpu = cpu;

		state->vmxon_region = alloc_pages_node(node,
						       GFP_KERNEL | __GFP_ZERO,
						       0);
		if (!state->vmxon_region) {
			pr_err("phantom: CPU%d: failed to alloc VMXON region\n",
			       cpu);
			ret = -ENOMEM;
			goto fail_alloc;
		}
	}

	/* Phase 2: execute VMXON on each CPU in order */
	for_each_cpu(cpu, cpumask) {
		work.result = 0;
		smp_call_function_single(cpu, phantom_vmxon_cpu, &work, 1);

		if (work.result) {
			ret = work.result;
			pr_err("phantom: VMXON failed on CPU%d; "
			       "rolling back %d core(s)\n", cpu, n);
			goto fail_vmxon;
		}
		n++;
	}

	return 0;

fail_vmxon:
	/* Roll back VMXOFF on the n cores that succeeded */
	{
		int j = 0;

		for_each_cpu(cpu, cpumask) {
			if (j >= n)
				break;
			smp_call_function_single(cpu, phantom_vmxoff_cpu,
						 NULL, 1);
			j++;
		}
	}

fail_alloc:
	/* Free all pre-allocated VMXON region pages */
	for_each_cpu(cpu, cpumask) {
		state = per_cpu_ptr(&phantom_vmx_state, cpu);
		if (state->vmxon_region) {
			__free_page(state->vmxon_region);
			state->vmxon_region = NULL;
		}
	}
	return ret;
}

/* ------------------------------------------------------------------
 * Public: phantom_vmxoff_all
 * ------------------------------------------------------------------ */

/**
 * phantom_vmxoff_all - Exit VMX root on all active cores in cpumask.
 */
void phantom_vmxoff_all(const struct cpumask *cpumask)
{
	struct phantom_vmx_cpu_state *state;
	int cpu;

	for_each_cpu(cpu, cpumask) {
		smp_call_function_single(cpu, phantom_vmxoff_cpu, NULL, 1);

		/* Free VMXON region page after VMXOFF */
		state = per_cpu_ptr(&phantom_vmx_state, cpu);
		if (state->vmxon_region) {
			__free_page(state->vmxon_region);
			state->vmxon_region = NULL;
		}
	}
}

/* ------------------------------------------------------------------
 * Per-CPU VMCS allocation worker
 * ------------------------------------------------------------------ */

struct phantom_vmcs_work {
	u32  revision_id;
	int  result;
};

static void phantom_vmcs_alloc_cpu(void *data)
{
	struct phantom_vmcs_work *work = data;
	struct phantom_vmx_cpu_state *state = this_cpu_ptr(&phantom_vmx_state);
	u32 *rev_ptr;
	u64 phys;
	int cpu, ret;

	cpu         = smp_processor_id();
	work->result = 0;

	/* Allocate 4KB VMCS region — NUMA-local */
	state->vmcs_region = alloc_pages_node(cpu_to_node(cpu),
					      GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->vmcs_region) {
		pr_err("phantom: CPU%d: failed to alloc VMCS region\n", cpu);
		work->result = -ENOMEM;
		return;
	}

	/* Write revision ID — bit 31 must be 0 (shadow-VMCS indicator) */
	rev_ptr  = (u32 *)page_address(state->vmcs_region);
	*rev_ptr = work->revision_id & ~BIT(31);

	phys = page_to_phys(state->vmcs_region);

	/* VMCLEAR: reset the VMCS to inactive state */
	ret = __vmclear(phys);
	if (ret) {
		pr_err("phantom: CPU%d: VMCLEAR failed\n", cpu);
		__free_page(state->vmcs_region);
		state->vmcs_region = NULL;
		work->result = ret;
		return;
	}

	/* VMPTRLD: make this VMCS current on the CPU */
	ret = __vmptrld(phys);
	if (ret) {
		pr_err("phantom: CPU%d: VMPTRLD failed\n", cpu);
		__free_page(state->vmcs_region);
		state->vmcs_region = NULL;
		work->result = ret;
		return;
	}

	pr_info("phantom: CPU%d: VMCS allocated and loaded\n", cpu);
}

/* Per-CPU VMCS free worker */
static void phantom_vmcs_free_cpu(void *data)
{
	struct phantom_vmx_cpu_state *state = this_cpu_ptr(&phantom_vmx_state);
	int cpu = smp_processor_id();

	if (!state->vmcs_region)
		return;

	/* VMCLEAR to invalidate the VMCS before freeing */
	{
		u64 phys = page_to_phys(state->vmcs_region);

		__vmclear(phys);
	}

	__free_page(state->vmcs_region);
	state->vmcs_region = NULL;

	pr_info("phantom: CPU%d: VMCS freed\n", cpu);
}

/* ------------------------------------------------------------------
 * Public: phantom_vmcs_alloc_all / phantom_vmcs_free_all
 * ------------------------------------------------------------------ */

/**
 * phantom_vmcs_alloc_all - Allocate VMCS on each CPU in cpumask.
 *
 * Must be called after phantom_vmxon_all() succeeds.
 * Returns 0 on success, -ENOMEM or -EIO on failure.
 */
int phantom_vmcs_alloc_all(const struct cpumask *cpumask)
{
	struct phantom_vmcs_work work;
	struct phantom_vmx_cpu_state *state;
	int cpu, n = 0, ret = 0;
	u64 vmx_basic;

	if (rdmsrl_safe(MSR_IA32_VMX_BASIC, &vmx_basic)) {
		pr_err("phantom: failed to read VMX_BASIC for VMCS revision\n");
		return -EIO;
	}
	work.revision_id = (u32)(vmx_basic & VMX_BASIC_REVISION_MASK);

	for_each_cpu(cpu, cpumask) {
		work.result = 0;
		smp_call_function_single(cpu, phantom_vmcs_alloc_cpu,
					 &work, 1);
		if (work.result) {
			ret = work.result;
			goto fail;
		}
		n++;
	}
	return 0;

fail:
	/* Free successfully allocated VMCS regions */
	{
		int j = 0;

		for_each_cpu(cpu, cpumask) {
			if (j >= n)
				break;
			smp_call_function_single(cpu, phantom_vmcs_free_cpu,
						 NULL, 1);
			j++;
		}
	}

	/* Also free the failed CPU's partially-set state if any */
	for_each_cpu(cpu, cpumask) {
		state = per_cpu_ptr(&phantom_vmx_state, cpu);
		if (state->vmcs_region) {
			__free_page(state->vmcs_region);
			state->vmcs_region = NULL;
		}
	}

	return ret;
}

/**
 * phantom_vmcs_free_all - Free VMCS regions on all target CPUs.
 */
void phantom_vmcs_free_all(const struct cpumask *cpumask)
{
	int cpu;

	for_each_cpu(cpu, cpumask)
		smp_call_function_single(cpu, phantom_vmcs_free_cpu, NULL, 1);
}
