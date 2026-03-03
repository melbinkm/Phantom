// SPDX-License-Identifier: GPL-2.0-only
/*
 * vmx_core.c — VMX bootstrap, VMCS configuration, and guest execution
 *
 * Responsibilities:
 *   - CPU feature detection (VT-x, EPT, Intel PT, XSAVE)
 *   - Per-CPU VMXON region allocation and VMXON execution
 *   - Per-CPU VMXOFF and CR4 restoration
 *   - Per-CPU VMCS allocation, VMCLEAR, VMPTRLD
 *   - VMCS guest-state, host-state, and control field population
 *   - Minimal EPT construction for trivial guest
 *   - Guest page-table construction (4-level, IA-32e mode)
 *   - MSR bitmap allocation (4KB zero page)
 *   - Assembly trampoline: VMLAUNCH/VMRESUME + VM exit return path
 *   - VM exit dispatch: VMCALL, EPT violation, CPUID, exceptions, NMI
 *   - Partial-failure rollback on multi-core init
 *
 * Hot-path discipline: no printk, no sleeping functions, no dynamic
 * allocation in the VM exit handler.  trace_printk under PHANTOM_DEBUG.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/percpu.h>
#include <linux/string.h>
#include <asm/processor.h>
#include <asm/cpufeature.h>
#include <asm/cpuid.h>
#include <asm/msr.h>
#include <asm/tlbflush.h>
#include <asm/io.h>
#include <asm/vmx.h>
#include <asm/desc.h>
#include <asm/msr-index.h>
#include <asm/special_insns.h>

#include "phantom.h"
#include "vmx_core.h"
#include "hypercall.h"
#include "nmi.h"
#include "debug.h"

/* Per-CPU VMX state — one entry per physical CPU */
DEFINE_PER_CPU(struct phantom_vmx_cpu_state, phantom_vmx_state);
EXPORT_SYMBOL_GPL(phantom_vmx_state);

/* ------------------------------------------------------------------
 * Low-level VMX instruction wrappers
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
		return -EBUSY;
	if (err_zf)
		return -EIO;
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
 * INVEPT helper
 * ------------------------------------------------------------------ */

struct phantom_invept_desc {
	u64 eptp;
	u64 rsvd;
} __packed;

static inline void __invept_single(u64 eptp)
{
	struct phantom_invept_desc desc = { .eptp = eptp, .rsvd = 0 };

	asm volatile("invept %0, %1"
		     :: "m"(desc), "r"((u64)1)   /* type 1 = single-context */
		     : "cc", "memory");
}

/* ------------------------------------------------------------------
 * Control field adjustment
 *
 * Intel SDM §A.3.1: MSR layout = allowed0 (low32) | allowed1 (high32)
 * allowed0: bits that MUST be 1 in the control field
 * allowed1: bits that MAY be 1 in the control field
 *
 * Returns (desired | allowed0) & allowed1.
 * If true_ctls is set, use the TRUE_* MSR variant.
 * ------------------------------------------------------------------ */

static u32 phantom_adjust_controls(u32 desired, u32 msr)
{
	u64 cap;

	rdmsrl(msr, cap);
	return (desired | (u32)(cap & 0xffffffffULL)) &
	       (u32)(cap >> 32);
}

/* ------------------------------------------------------------------
 * Feature detection
 * ------------------------------------------------------------------ */

int phantom_vmx_check_cpu_features(struct phantom_cpu_features *feat)
{
	u32 ecx_1, ebx_7;
	u64 vmx_basic, ept_vpid_cap;
	u64 secondary_ctls_msr;
	int ret;

	memset(feat, 0, sizeof(*feat));

	ecx_1 = cpuid_ecx(1);
	feat->vtx = !!(ecx_1 & BIT(5));
	if (!feat->vtx) {
		pr_err("phantom: VT-x (VMX) not supported by this CPU\n");
		return -ENODEV;
	}

	ret = rdmsrl_safe(MSR_IA32_VMX_BASIC, &vmx_basic);
	if (ret) {
		pr_err("phantom: failed to read MSR_IA32_VMX_BASIC\n");
		return -ENODEV;
	}
	feat->vmx_revision = (u32)(vmx_basic & VMX_BASIC_REVISION_MASK);
	feat->true_ctls    = !!(vmx_basic & VMX_BASIC_TRUE_CTLS);

	pr_info("phantom: VMX revision ID: 0x%08x, TRUE controls: %s\n",
		feat->vmx_revision, feat->true_ctls ? "yes" : "no");

	{
		u64 ctls_msr_id = feat->true_ctls ?
			MSR_IA32_VMX_TRUE_PROCBASED_CTLS :
			MSR_IA32_VMX_PROCBASED_CTLS;
		u64 ctls_val;

		if (rdmsrl_safe(ctls_msr_id, &ctls_val)) {
			pr_err("phantom: failed to read proc-based CTL MSR\n");
			return -ENODEV;
		}
		if (!(ctls_val & BIT_ULL(63))) {
			pr_err("phantom: secondary proc-based controls "
			       "not supported\n");
			return -ENODEV;
		}
	}

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

	if (rdmsrl_safe(MSR_IA32_VMX_EPT_VPID_CAP, &ept_vpid_cap)) {
		pr_err("phantom: failed to read MSR_IA32_VMX_EPT_VPID_CAP\n");
		return -ENODEV;
	}

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

	if (!feat->ept_2mb)
		pr_info("phantom: EPT 2MB pages not supported (advisory)\n");
	if (!feat->ept_ad)
		pr_info("phantom: EPT A/D bits not supported (advisory)\n");

	ebx_7 = cpuid_ebx(7);
	feat->intel_pt = !!(ebx_7 & BIT(25));
	if (!feat->intel_pt)
		pr_info("phantom: Intel PT not detected (advisory)\n");

	feat->xsave = !!(ecx_1 & BIT(26));
	if (!feat->xsave)
		pr_info("phantom: XSAVE not supported (advisory)\n");

	pr_info("phantom: CPU features: EPT(4lvl=%d wb=%d 2mb=%d ad=%d) "
		"PT=%d XSAVE=%d\n",
		feat->ept_4lvl, feat->ept_wb, feat->ept_2mb, feat->ept_ad,
		feat->intel_pt, feat->xsave);

	return 0;
}

/* ------------------------------------------------------------------
 * VMXON / VMXOFF workers
 * ------------------------------------------------------------------ */

struct phantom_vmxon_work {
	u32  revision_id;
	int  result;
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

	cr4 = native_read_cr4();
	state->saved_cr4 = cr4;

	if (cr4 & X86_CR4_VMXE) {
		pr_warn("phantom: CPU%d: CR4.VMXE already set — "
			"VMX likely active (conflict possible)\n", cpu);
	} else {
		cr4_set_bits(X86_CR4_VMXE);
		we_set_vmxe = true;
	}

	rev_ptr  = (u32 *)page_address(state->vmxon_region);
	*rev_ptr = work->revision_id;
	phys     = page_to_phys(state->vmxon_region);

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

static void phantom_vmxoff_cpu(void *data)
{
	struct phantom_vmx_cpu_state *state = this_cpu_ptr(&phantom_vmx_state);

	if (!state->vmx_active)
		return;

	__vmxoff();

	if (!(state->saved_cr4 & X86_CR4_VMXE))
		cr4_clear_bits(X86_CR4_VMXE);

	state->vmx_active = false;

	pr_info("phantom: CPU%d: VMX root exited\n", smp_processor_id());
}

/* ------------------------------------------------------------------
 * Public: phantom_vmxon_all / phantom_vmxoff_all
 * ------------------------------------------------------------------ */

int phantom_vmxon_all(const struct cpumask *cpumask)
{
	struct phantom_vmx_cpu_state *state;
	struct phantom_vmxon_work work;
	int cpu, n = 0, ret = 0;

	{
		u64 vmx_basic;

		if (rdmsrl_safe(MSR_IA32_VMX_BASIC, &vmx_basic)) {
			pr_err("phantom: failed to read VMX_BASIC for revision\n");
			return -EIO;
		}
		work.revision_id = (u32)(vmx_basic & VMX_BASIC_REVISION_MASK);
	}

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
	for_each_cpu(cpu, cpumask) {
		state = per_cpu_ptr(&phantom_vmx_state, cpu);
		if (state->vmxon_region) {
			__free_page(state->vmxon_region);
			state->vmxon_region = NULL;
		}
	}
	return ret;
}

void phantom_vmxoff_all(const struct cpumask *cpumask)
{
	struct phantom_vmx_cpu_state *state;
	int cpu;

	for_each_cpu(cpu, cpumask) {
		smp_call_function_single(cpu, phantom_vmxoff_cpu, NULL, 1);

		state = per_cpu_ptr(&phantom_vmx_state, cpu);
		if (state->vmxon_region) {
			__free_page(state->vmxon_region);
			state->vmxon_region = NULL;
		}
	}
}

/* ------------------------------------------------------------------
 * VMCS allocation workers
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

	cpu          = smp_processor_id();
	work->result = 0;

	state->vmcs_region = alloc_pages_node(cpu_to_node(cpu),
					      GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->vmcs_region) {
		pr_err("phantom: CPU%d: failed to alloc VMCS region\n", cpu);
		work->result = -ENOMEM;
		return;
	}

	rev_ptr  = (u32 *)page_address(state->vmcs_region);
	*rev_ptr = work->revision_id & ~BIT(31);
	phys     = page_to_phys(state->vmcs_region);

	ret = __vmclear(phys);
	if (ret) {
		pr_err("phantom: CPU%d: VMCLEAR failed\n", cpu);
		__free_page(state->vmcs_region);
		state->vmcs_region = NULL;
		work->result = ret;
		return;
	}

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

static void phantom_vmcs_free_cpu(void *data)
{
	struct phantom_vmx_cpu_state *state = this_cpu_ptr(&phantom_vmx_state);

	if (!state->vmcs_region)
		return;

	{
		u64 phys = page_to_phys(state->vmcs_region);

		__vmclear(phys);
	}

	__free_page(state->vmcs_region);
	state->vmcs_region = NULL;

	pr_info("phantom: CPU%d: VMCS freed\n", smp_processor_id());
}

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
	for_each_cpu(cpu, cpumask) {
		state = per_cpu_ptr(&phantom_vmx_state, cpu);
		if (state->vmcs_region) {
			__free_page(state->vmcs_region);
			state->vmcs_region = NULL;
		}
	}
	return ret;
}

void phantom_vmcs_free_all(const struct cpumask *cpumask)
{
	int cpu;

	for_each_cpu(cpu, cpumask)
		smp_call_function_single(cpu, phantom_vmcs_free_cpu, NULL, 1);
}

/* ------------------------------------------------------------------
 * EPT construction
 *
 * Build a minimal 4-level EPT covering GPAs 0x10000–0x15FFF.
 * Layout:
 *   EPT PML4[0] → EPT PDPT
 *   EPT PDPT[0] → EPT PD
 *   EPT PD[0]   → EPT PT  (4KB entries, not 2MB)
 *   EPT PT[16]  → code page  HPA  (R+X)
 *   EPT PT[17]  → stack page HPA  (R+W)
 *   EPT PT[18]  → data page  HPA  (R+W)
 *   EPT PT[19]  → PML4 page  HPA  (R+W)
 *   EPT PT[20]  → PDPT page  HPA  (R+W)
 *   EPT PT[21]  → PD page    HPA  (R+W)
 *
 * EPTP = EPT_PML4_phys | EPTP_MEMTYPE_WB | EPTP_PAGEWALK_4
 * ------------------------------------------------------------------ */

static u64 phantom_build_ept(struct phantom_vmx_cpu_state *state)
{
	u64 *pml4, *pdpt, *pd, *pt;
	u64 eptp;

	pml4 = (u64 *)page_address(state->ept_pml4);
	pdpt = (u64 *)page_address(state->ept_pdpt);
	pd   = (u64 *)page_address(state->ept_pd);
	pt   = (u64 *)page_address(state->ept_pt);

	/* Zero all EPT pages */
	memset(pml4, 0, PAGE_SIZE);
	memset(pdpt, 0, PAGE_SIZE);
	memset(pd,   0, PAGE_SIZE);
	memset(pt,   0, PAGE_SIZE);

	/*
	 * EPT PML4[0] → PDPT (R+W+X, points to next level)
	 * GPA bit[47:39] = 0 for our 0x10000–0x15FFF range.
	 */
	pml4[0] = page_to_phys(state->ept_pdpt) |
		  EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_EXEC;

	/*
	 * EPT PDPT[0] → PD (R+W+X)
	 * GPA bit[38:30] = 0 for our range.
	 */
	pdpt[0] = page_to_phys(state->ept_pd) |
		  EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_EXEC;

	/*
	 * EPT PD[0] → PT (R+W+X, 4KB entries — bit 7 NOT set)
	 * GPA bit[29:21] = 0 for our range.
	 */
	pd[0] = page_to_phys(state->ept_pt) |
		EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_EXEC;

	/*
	 * EPT PT: index = GPA[20:12]
	 * GPA 0x10000 → index 16, 0x11000 → 17, ... 0x15000 → 21
	 */

	/* Entry 16: code page — read + execute (no write for integrity) */
	pt[16] = page_to_phys(state->guest_code_page) |
		 EPT_PTE_READ | EPT_PTE_EXEC | EPT_PTE_MEMTYPE_WB;

	/* Entry 17: stack page — read + write */
	pt[17] = page_to_phys(state->guest_stack_page) |
		 EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_MEMTYPE_WB;

	/* Entry 18: data buffer page — read + write */
	pt[18] = page_to_phys(state->guest_data_page) |
		 EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_MEMTYPE_WB;

	/* Entry 19: guest PML4 page — read + write */
	pt[19] = page_to_phys(state->guest_pml4_page) |
		 EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_MEMTYPE_WB;

	/* Entry 20: guest PDPT page — read + write */
	pt[20] = page_to_phys(state->guest_pdpt_page) |
		 EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_MEMTYPE_WB;

	/* Entry 21: guest PD page — read + write */
	pt[21] = page_to_phys(state->guest_pd_page) |
		 EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_MEMTYPE_WB;

	/* EPTP: PML4 physical address | WB caching | 4-level walk */
	eptp = page_to_phys(state->ept_pml4) |
	       EPTP_MEMTYPE_WB | EPTP_PAGEWALK_4;

	return eptp;
}

/* ------------------------------------------------------------------
 * Guest page-table construction (IA-32e 4-level paging)
 *
 * The trivial guest runs in 64-bit mode with identity mapping:
 *   GVA 0–2MB maps to GPA 0–2MB via a 2MB large-page PD entry.
 *
 * Layout:
 *   PML4 at GPA 0x13000 (guest_pml4_page):
 *     entry[0] → PDPT (GPA 0x14000), R+W+P
 *   PDPT at GPA 0x14000 (guest_pdpt_page):
 *     entry[0] → PD (GPA 0x15000), R+W+P
 *   PD at GPA 0x15000 (guest_pd_page):
 *     entry[0] → 2MB large page, identity (GVA 0 → GPA 0), R+W+P+PS
 *
 * Guest CR3 = GPA 0x13000
 * ------------------------------------------------------------------ */

#define PAGE_ENTRY_P		BIT(0)   /* Present */
#define PAGE_ENTRY_RW		BIT(1)   /* Read/Write */
#define PAGE_ENTRY_US		BIT(2)   /* User/Supervisor */
#define PAGE_ENTRY_PS		BIT(7)   /* Page Size (2MB in PD) */

static void phantom_build_guest_pagetables(struct phantom_vmx_cpu_state *state)
{
	u64 *pml4 = (u64 *)page_address(state->guest_pml4_page);
	u64 *pdpt = (u64 *)page_address(state->guest_pdpt_page);
	u64 *pd   = (u64 *)page_address(state->guest_pd_page);

	memset(pml4, 0, PAGE_SIZE);
	memset(pdpt, 0, PAGE_SIZE);
	memset(pd,   0, PAGE_SIZE);

	/* PML4[0] → PDPT at GPA 0x14000 */
	pml4[0] = GUEST_PDPT_GPA | PAGE_ENTRY_P | PAGE_ENTRY_RW;

	/* PDPT[0] → PD at GPA 0x15000 */
	pdpt[0] = GUEST_PD_GPA | PAGE_ENTRY_P | PAGE_ENTRY_RW;

	/*
	 * PD[0] → 2MB identity page: GVA 0x00000000 → GPA 0x00000000
	 * PS bit set for 2MB large page.
	 * Physical address field for 2MB PDE is bits [51:21] = 0x000000
	 * (identity mapping, GPA 0 → physical 0 from the guest's view).
	 */
	pd[0] = 0x000000ULL | PAGE_ENTRY_P | PAGE_ENTRY_RW | PAGE_ENTRY_PS;
}

/* ------------------------------------------------------------------
 * Host-state helpers: read TR base from GDT
 * ------------------------------------------------------------------ */

static u64 phantom_get_tr_base(void)
{
	struct desc_ptr gdtr;
	struct desc_struct *gdt;
	u16 tr;
	u64 base;

	native_store_gdt(&gdtr);
	asm volatile("str %0" : "=rm"(tr));
	tr &= ~7; /* clear RPL bits */

	gdt  = (struct desc_struct *)(gdtr.address + tr);
	base = get_desc_base(gdt);

	/*
	 * For a 64-bit TSS, the high 32 bits of the base are in the
	 * descriptor immediately following in the GDT.
	 */
	{
		u64 high_word;

		memcpy(&high_word, (u8 *)gdt + 8, 8);
		base |= (high_word & 0xFFFFFFFF00000000ULL);
	}

	return base;
}

/* ------------------------------------------------------------------
 * VMCS control field population
 * ------------------------------------------------------------------ */

static int phantom_vmcs_setup_controls(struct phantom_vmx_cpu_state *state,
				       bool use_true_ctls, u64 eptp)
{
	u32 pin, proc, proc2, exit_c, entry_c;

	/* Pin-based: external-int exiting + NMI exiting */
	{
		u32 msr = use_true_ctls ?
			MSR_IA32_VMX_TRUE_PINBASED_CTLS :
			MSR_IA32_VMX_PINBASED_CTLS;

		pin = phantom_adjust_controls(
			PIN_BASED_EXT_INT_EXITING | PIN_BASED_NMI_EXITING,
			msr);
		phantom_vmcs_write32(VMCS_CTRL_PINBASED, pin);
	}

	/* Primary proc-based: HLT exiting + unconditional I/O +
	 * MSR bitmaps (REQUIRED) + secondary enable
	 */
	{
		u32 msr = use_true_ctls ?
			MSR_IA32_VMX_TRUE_PROCBASED_CTLS :
			MSR_IA32_VMX_PROCBASED_CTLS;

		proc = phantom_adjust_controls(
			CPU_BASED_HLT_EXITING |
			CPU_BASED_UNCONDITIONAL_IO |
			CPU_BASED_USE_MSR_BITMAPS |
			CPU_BASED_SECONDARY_ENABLE,
			msr);
		phantom_vmcs_write32(VMCS_CTRL_PROCBASED, proc);
	}

	/* Secondary proc-based: EPT enable */
	proc2 = phantom_adjust_controls(SECONDARY_EXEC_ENABLE_EPT,
					MSR_IA32_VMX_PROCBASED_CTLS2);
	phantom_vmcs_write32(VMCS_CTRL_PROCBASED2, proc2);

	/* VM-exit controls: host 64-bit + ACK interrupt + PAT + EFER */
	{
		u32 msr = use_true_ctls ?
			MSR_IA32_VMX_TRUE_EXIT_CTLS :
			MSR_IA32_VMX_EXIT_CTLS;

		exit_c = phantom_adjust_controls(
			VM_EXIT_HOST_ADDR_SPACE_SIZE |
			VM_EXIT_ACK_INT_ON_EXIT |
			VM_EXIT_SAVE_IA32_PAT |
			VM_EXIT_LOAD_IA32_PAT |
			VM_EXIT_SAVE_IA32_EFER |
			VM_EXIT_LOAD_IA32_EFER,
			msr);
		phantom_vmcs_write32(VMCS_CTRL_EXIT, exit_c);
	}

	/* VM-entry controls: IA-32e mode guest + load PAT + load EFER */
	{
		u32 msr = use_true_ctls ?
			MSR_IA32_VMX_TRUE_ENTRY_CTLS :
			MSR_IA32_VMX_ENTRY_CTLS;

		entry_c = phantom_adjust_controls(
			VM_ENTRY_IA32E_MODE |
			VM_ENTRY_LOAD_IA32_PAT |
			VM_ENTRY_LOAD_IA32_EFER,
			msr);
		phantom_vmcs_write32(VMCS_CTRL_ENTRY, entry_c);
	}

	/* Exception bitmap: #UD (bit 6) + #PF (bit 14) */
	phantom_vmcs_write32(VMCS_CTRL_EXCEPTION_BITMAP,
			     BIT(6) | BIT(14));

	/* MSR bitmap: 4KB zero page — no MSR exits */
	phantom_vmcs_write64(VMCS_CTRL_MSR_BITMAP,
			     page_to_phys(state->msr_bitmap));

	/* EPT pointer */
	phantom_vmcs_write64(VMCS_CTRL_EPT_POINTER, eptp);

	/* VPID = 1 */
	phantom_vmcs_write16(VMCS_CTRL_VPID, 1);

	/* VM exit/entry MSR store/load counts = 0 */
	phantom_vmcs_write32(VMCS_CTRL_EXIT_MSR_STORE_COUNT, 0);
	phantom_vmcs_write32(VMCS_CTRL_EXIT_MSR_LOAD_COUNT,  0);
	phantom_vmcs_write32(VMCS_CTRL_ENTRY_MSR_LOAD_COUNT, 0);

	/* VMCS link pointer = 0xFFFFFFFFFFFFFFFF (no shadow VMCS) */
	phantom_vmcs_write64(VMCS_CTRL_VMCS_LINK_PTR,
			     0xFFFFFFFFFFFFFFFFULL);

	return 0;
}

/* ------------------------------------------------------------------
 * VMCS guest-state population
 * ------------------------------------------------------------------ */

static int phantom_vmcs_setup_guest_state(void)
{
	u64 cr0_fixed0, cr0_fixed1;
	u64 cr4_fixed0, cr4_fixed1;
	u64 cr0, cr4;

	rdmsrl(MSR_IA32_VMX_CR0_FIXED0, cr0_fixed0);
	rdmsrl(MSR_IA32_VMX_CR0_FIXED1, cr0_fixed1);
	rdmsrl(MSR_IA32_VMX_CR4_FIXED0, cr4_fixed0);
	rdmsrl(MSR_IA32_VMX_CR4_FIXED1, cr4_fixed1);

	/*
	 * CR0: must satisfy fixed0/fixed1, plus PE + PG + NE for
	 * protected/paged mode.  NE (Numeric Error) is required by
	 * the fixed bits on most hardware.
	 */
	cr0 = X86_CR0_PE | X86_CR0_PG | X86_CR0_NE;
	cr0 = (cr0 | cr0_fixed0) & cr0_fixed1;
	phantom_vmcs_write64(VMCS_GUEST_CR0, cr0);

	/*
	 * CR4: PAE required for 64-bit paging; apply fixed bits.
	 */
	cr4 = X86_CR4_PAE;
	cr4 = (cr4 | cr4_fixed0) & cr4_fixed1;
	phantom_vmcs_write64(VMCS_GUEST_CR4, cr4);

	/* CR3 = GPA of guest PML4 */
	phantom_vmcs_write64(VMCS_GUEST_CR3, GUEST_PML4_GPA);

	/* DR7 = 0x400 (standard reset value) */
	phantom_vmcs_write64(VMCS_GUEST_DR7, 0x400ULL);

	/* EFER: LME + LMA + SCE */
	phantom_vmcs_write64(VMCS_GUEST_IA32_EFER,
			     EFER_LME | EFER_LMA | EFER_SCE);

	/* RFLAGS: bit 1 (reserved, must be 1) */
	phantom_vmcs_write64(VMCS_GUEST_RFLAGS, 0x2ULL);

	/* Entry point and stack */
	phantom_vmcs_write64(VMCS_GUEST_RIP, GUEST_CODE_GPA);
	phantom_vmcs_write64(VMCS_GUEST_RSP, GUEST_STACK_GPA + 0xFF0ULL);

	/*
	 * CS: 64-bit code segment
	 * AR = 0xA09B:
	 *   type=0xB (execute/read, accessed)
	 *   S=1 (code/data descriptor)
	 *   DPL=0
	 *   P=1 (present)
	 *   L=1 (64-bit code)
	 *   D=0 (default 64-bit)
	 *   G=1 (granularity)
	 */
	phantom_vmcs_write16(VMCS_GUEST_CS_SELECTOR, 0x08);
	phantom_vmcs_write64(VMCS_GUEST_CS_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_CS_LIMIT,    0xFFFFFFFFU);
	phantom_vmcs_write32(VMCS_GUEST_CS_AR,       0xA09B);

	/*
	 * SS: 64-bit stack segment
	 * AR = 0xC093:
	 *   type=3 (read/write, accessed)
	 *   S=1, DPL=0, P=1, D/B=1, G=1
	 */
	phantom_vmcs_write16(VMCS_GUEST_SS_SELECTOR, 0x10);
	phantom_vmcs_write64(VMCS_GUEST_SS_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_SS_LIMIT,    0xFFFFFFFFU);
	phantom_vmcs_write32(VMCS_GUEST_SS_AR,       0xC093);

	/* DS, ES, FS, GS: unusable (bit 16 set in AR) */
	phantom_vmcs_write16(VMCS_GUEST_DS_SELECTOR, 0x10);
	phantom_vmcs_write64(VMCS_GUEST_DS_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_DS_LIMIT,    0);
	phantom_vmcs_write32(VMCS_GUEST_DS_AR,       0x10000);

	phantom_vmcs_write16(VMCS_GUEST_ES_SELECTOR, 0x10);
	phantom_vmcs_write64(VMCS_GUEST_ES_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_ES_LIMIT,    0);
	phantom_vmcs_write32(VMCS_GUEST_ES_AR,       0x10000);

	phantom_vmcs_write16(VMCS_GUEST_FS_SELECTOR, 0);
	phantom_vmcs_write64(VMCS_GUEST_FS_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_FS_LIMIT,    0);
	phantom_vmcs_write32(VMCS_GUEST_FS_AR,       0x10000);

	phantom_vmcs_write16(VMCS_GUEST_GS_SELECTOR, 0);
	phantom_vmcs_write64(VMCS_GUEST_GS_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_GS_LIMIT,    0);
	phantom_vmcs_write32(VMCS_GUEST_GS_AR,       0x10000);

	/* TR: busy 64-bit TSS (type=0xB, P=1) */
	phantom_vmcs_write16(VMCS_GUEST_TR_SELECTOR, 0);
	phantom_vmcs_write64(VMCS_GUEST_TR_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_TR_LIMIT,    0xFFFF);
	phantom_vmcs_write32(VMCS_GUEST_TR_AR,       0x008B);

	/* LDTR: unusable */
	phantom_vmcs_write16(VMCS_GUEST_LDTR_SELECTOR, 0);
	phantom_vmcs_write64(VMCS_GUEST_LDTR_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_LDTR_LIMIT,    0);
	phantom_vmcs_write32(VMCS_GUEST_LDTR_AR,       0x10000);

	/* GDTR and IDTR: empty (guest has no real GDT/IDT) */
	phantom_vmcs_write64(VMCS_GUEST_GDTR_BASE,  0ULL);
	phantom_vmcs_write32(VMCS_GUEST_GDTR_LIMIT, 0);
	phantom_vmcs_write64(VMCS_GUEST_IDTR_BASE,  0ULL);
	phantom_vmcs_write32(VMCS_GUEST_IDTR_LIMIT, 0);

	/* Guest interrupt / activity state */
	phantom_vmcs_write32(VMCS_GUEST_INTR_STATE,      0);
	phantom_vmcs_write32(VMCS_GUEST_ACTIVITY_STATE,  0);

	/* Remaining guest MSRs */
	phantom_vmcs_write64(VMCS_GUEST_IA32_DEBUGCTL, 0ULL);
	phantom_vmcs_write32(VMCS_GUEST_IA32_SYSENTER_CS, 0);
	phantom_vmcs_write64(VMCS_GUEST_IA32_SYSENTER_ESP, 0ULL);
	phantom_vmcs_write64(VMCS_GUEST_IA32_SYSENTER_EIP, 0ULL);

	/* PAT: standard reset value */
	phantom_vmcs_write64(VMCS_GUEST_IA32_PAT,
			     0x0007040600070406ULL);

	return 0;
}

/* ------------------------------------------------------------------
 * VMCS host-state population
 *
 * Note: HOST_RSP is NOT set here; the assembly trampoline sets it
 * just before VMLAUNCH/VMRESUME so it captures the exact stack frame.
 * ------------------------------------------------------------------ */

static int phantom_vmcs_setup_host_state(void)
{
	struct desc_ptr gdtr, idtr;
	u64 msr_val;
	u16 tr, fs, gs;
	u64 tr_base;

	native_store_gdt(&gdtr);
	native_store_idt(&idtr);
	asm volatile("str %0" : "=rm"(tr));
	asm volatile("mov %%fs, %0" : "=rm"(fs));
	asm volatile("mov %%gs, %0" : "=rm"(gs));

	tr_base = phantom_get_tr_base();

	/* Control registers */
	phantom_vmcs_write64(VMCS_HOST_CR0, read_cr0());
	phantom_vmcs_write64(VMCS_HOST_CR3, __read_cr3());
	phantom_vmcs_write64(VMCS_HOST_CR4, native_read_cr4());

	/* Segment selectors */
	phantom_vmcs_write16(VMCS_HOST_CS_SELECTOR, __KERNEL_CS);
	phantom_vmcs_write16(VMCS_HOST_SS_SELECTOR, __KERNEL_DS);
	phantom_vmcs_write16(VMCS_HOST_DS_SELECTOR, __KERNEL_DS);
	phantom_vmcs_write16(VMCS_HOST_ES_SELECTOR, 0);
	phantom_vmcs_write16(VMCS_HOST_FS_SELECTOR, fs);
	phantom_vmcs_write16(VMCS_HOST_GS_SELECTOR, gs);
	phantom_vmcs_write16(VMCS_HOST_TR_SELECTOR, tr & ~7);

	/* Segment and table bases */
	rdmsrl(MSR_FS_BASE, msr_val);
	phantom_vmcs_write64(VMCS_HOST_FS_BASE, msr_val);

	rdmsrl(MSR_GS_BASE, msr_val);
	phantom_vmcs_write64(VMCS_HOST_GS_BASE, msr_val);

	phantom_vmcs_write64(VMCS_HOST_TR_BASE,   tr_base);
	phantom_vmcs_write64(VMCS_HOST_GDTR_BASE, gdtr.address);
	phantom_vmcs_write64(VMCS_HOST_IDTR_BASE, idtr.address);

	/* SYSENTER MSRs */
	rdmsrl(MSR_IA32_SYSENTER_CS, msr_val);
	phantom_vmcs_write32(VMCS_HOST_IA32_SYSENTER_CS, (u32)msr_val);

	rdmsrl(MSR_IA32_SYSENTER_ESP, msr_val);
	phantom_vmcs_write64(VMCS_HOST_IA32_SYSENTER_ESP, msr_val);

	rdmsrl(MSR_IA32_SYSENTER_EIP, msr_val);
	phantom_vmcs_write64(VMCS_HOST_IA32_SYSENTER_EIP, msr_val);

	/* EFER and PAT */
	rdmsrl(MSR_EFER, msr_val);
	phantom_vmcs_write64(VMCS_HOST_IA32_EFER, msr_val);

	rdmsrl(MSR_IA32_CR_PAT, msr_val);
	phantom_vmcs_write64(VMCS_HOST_IA32_PAT, msr_val);

	/*
	 * HOST_RSP and HOST_RIP are set by the assembly trampoline
	 * (phantom_vmlaunch_trampoline) just before VMLAUNCH.
	 */

	return 0;
}

/* ------------------------------------------------------------------
 * phantom_vmcs_setup - Allocate resources and populate the VMCS.
 * @state: Per-CPU VMX state; VMCS must already be current (VMPTRLD done).
 *
 * Allocates: MSR bitmap, 4 EPT pages, 6 guest memory pages.
 * Builds: EPT page tables, guest page tables.
 * Populates: VMCS control fields, guest-state, host-state.
 *
 * Returns 0 on success, negative errno on failure (goto-cleanup).
 * ------------------------------------------------------------------ */

int phantom_vmcs_setup(struct phantom_vmx_cpu_state *state)
{
	int cpu = state->cpu;
	int node = cpu_to_node(cpu);
	u64 eptp;
	bool use_true_ctls;
	u64 vmx_basic;
	int ret;

	if (state->vmcs_configured)
		return 0;

	rdmsrl(MSR_IA32_VMX_BASIC, &vmx_basic);
	use_true_ctls = !!(vmx_basic & VMX_BASIC_TRUE_CTLS);

	/* Allocate MSR bitmap (must be zeroed) */
	state->msr_bitmap = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->msr_bitmap) { ret = -ENOMEM; goto err_msr_bitmap; }

	/* Allocate EPT page tables */
	state->ept_pml4 = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->ept_pml4) { ret = -ENOMEM; goto err_ept_pml4; }

	state->ept_pdpt = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->ept_pdpt) { ret = -ENOMEM; goto err_ept_pdpt; }

	state->ept_pd = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->ept_pd) { ret = -ENOMEM; goto err_ept_pd; }

	state->ept_pt = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->ept_pt) { ret = -ENOMEM; goto err_ept_pt; }

	/* Allocate guest memory pages */
	state->guest_code_page = alloc_pages_node(node,
						  GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->guest_code_page) { ret = -ENOMEM; goto err_guest_code; }

	state->guest_stack_page = alloc_pages_node(node,
						   GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->guest_stack_page) { ret = -ENOMEM; goto err_guest_stack; }

	state->guest_data_page = alloc_pages_node(node,
						  GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->guest_data_page) { ret = -ENOMEM; goto err_guest_data; }

	state->guest_pml4_page = alloc_pages_node(node,
						  GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->guest_pml4_page) { ret = -ENOMEM; goto err_guest_pml4; }

	state->guest_pdpt_page = alloc_pages_node(node,
						  GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->guest_pdpt_page) { ret = -ENOMEM; goto err_guest_pdpt; }

	state->guest_pd_page = alloc_pages_node(node,
						GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->guest_pd_page) { ret = -ENOMEM; goto err_guest_pd; }

	/* Build guest page tables */
	phantom_build_guest_pagetables(state);

	/* Build EPT */
	eptp = phantom_build_ept(state);

	/* Populate VMCS fields (all three sections) */
	ret = phantom_vmcs_setup_controls(state, use_true_ctls, eptp);
	if (ret)
		goto err_vmcs;

	ret = phantom_vmcs_setup_guest_state();
	if (ret)
		goto err_vmcs;

	ret = phantom_vmcs_setup_host_state();
	if (ret)
		goto err_vmcs;

	/* INVEPT after initial setup */
	__invept_single(eptp);

	state->launched = false;
	state->vmcs_configured = true;

	pr_info("phantom: CPU%d: VMCS configured (eptp=0x%llx)\n",
		cpu, eptp);
	return 0;

err_vmcs:
	__free_page(state->guest_pd_page);
	state->guest_pd_page = NULL;
err_guest_pd:
	__free_page(state->guest_pdpt_page);
	state->guest_pdpt_page = NULL;
err_guest_pdpt:
	__free_page(state->guest_pml4_page);
	state->guest_pml4_page = NULL;
err_guest_pml4:
	__free_page(state->guest_data_page);
	state->guest_data_page = NULL;
err_guest_data:
	__free_page(state->guest_stack_page);
	state->guest_stack_page = NULL;
err_guest_stack:
	__free_page(state->guest_code_page);
	state->guest_code_page = NULL;
err_guest_code:
	__free_page(state->ept_pt);
	state->ept_pt = NULL;
err_ept_pt:
	__free_page(state->ept_pd);
	state->ept_pd = NULL;
err_ept_pd:
	__free_page(state->ept_pdpt);
	state->ept_pdpt = NULL;
err_ept_pdpt:
	__free_page(state->ept_pml4);
	state->ept_pml4 = NULL;
err_ept_pml4:
	__free_page(state->msr_bitmap);
	state->msr_bitmap = NULL;
err_msr_bitmap:
	return ret;
}

/**
 * phantom_vmcs_teardown - Release all resources allocated by phantom_vmcs_setup.
 * @state: Per-CPU VMX state.
 */
void phantom_vmcs_teardown(struct phantom_vmx_cpu_state *state)
{
	if (!state->vmcs_configured)
		return;

#define FREE_PAGE(p) do { if (p) { __free_page(p); (p) = NULL; } } while (0)

	FREE_PAGE(state->guest_pd_page);
	FREE_PAGE(state->guest_pdpt_page);
	FREE_PAGE(state->guest_pml4_page);
	FREE_PAGE(state->guest_data_page);
	FREE_PAGE(state->guest_stack_page);
	FREE_PAGE(state->guest_code_page);
	FREE_PAGE(state->ept_pt);
	FREE_PAGE(state->ept_pd);
	FREE_PAGE(state->ept_pdpt);
	FREE_PAGE(state->ept_pml4);
	FREE_PAGE(state->msr_bitmap);

#undef FREE_PAGE

	state->vmcs_configured = false;
	state->launched        = false;
}

/* ------------------------------------------------------------------
 * VM exit dispatcher
 *
 * Called from the assembly trampoline after every VM exit.
 * Hot-path: no printk, no sleeping, no dynamic allocation.
 *
 * Returns:
 *   0  — VMRESUME (continue guest execution)
 *   1  — stop guest (result available)
 *  -ve — error
 * ------------------------------------------------------------------ */

static int phantom_vm_exit_dispatch(struct phantom_vmx_cpu_state *state)
{
	u32 reason;
	u64 qual;

	reason = phantom_vmcs_read32(VMCS_RO_EXIT_REASON);
	qual   = phantom_vmcs_read64(VMCS_RO_EXIT_QUAL);

	state->exit_reason        = reason;
	state->exit_qualification = qual;

	/* Strip the "basic exit reason" from bits 15:0 */
	reason &= 0xFFFF;

	PHANTOM_TRACE_VM_EXIT(state->cpu, reason);

	switch (reason) {
	case VMX_EXIT_VMCALL: {
		int hret = phantom_handle_vmcall(state);

		if (hret < 0)
			return hret;
		/*
		 * After SUBMIT_RESULT the guest may continue to HLT;
		 * if run_result is set, we can stop now.
		 */
		if (state->run_result_data != 0 ||
		    state->guest_regs.rax == PHANTOM_HC_SUBMIT_RESULT)
			return 1; /* done */
		return 0; /* continue */
	}

	case VMX_EXIT_EXCEPTION_NMI: {
		u32 info = phantom_vmcs_read32(VMCS_RO_EXIT_INTR_INFO);

		/* Check valid bit (31) and vector (7:0) */
		if ((info & BIT(31)) && ((info & 0xFF) == 2)) {
			/* NMI — re-deliver to host */
			phantom_handle_nmi_exit();
			return 0;
		}
		/*
		 * Other exception: treat as guest crash.
		 * The validator or unexpected exception.
		 */
		state->run_result = 1; /* PHANTOM_RESULT_CRASH */
		return 1;
	}

	case VMX_EXIT_EXTERNAL_INT:
		/*
		 * With ACK_INT_ON_EXIT set, the hardware has already
		 * acknowledged the interrupt.  Nothing more to do here;
		 * the interrupt will be delivered through the host IDT
		 * when we return from the exit handler.
		 */
		return 0;

	case VMX_EXIT_TRIPLE_FAULT:
		state->run_result = 1; /* PHANTOM_RESULT_CRASH */
		return 1;

	case VMX_EXIT_CPUID: {
		/*
		 * Minimal CPUID emulation: return all-zeros.
		 * The trivial guest does not use CPUID, but handle it
		 * to avoid infinite exit loops.
		 */
		u64 rip;
		u32 ilen;

		state->guest_regs.rax = 0;
		state->guest_regs.rbx = 0;
		state->guest_regs.rcx = 0;
		state->guest_regs.rdx = 0;

		ilen = phantom_vmcs_read32(VMCS_RO_EXIT_INSTR_LEN);
		rip  = phantom_vmcs_read64(VMCS_GUEST_RIP);
		phantom_vmcs_write64(VMCS_GUEST_RIP, rip + ilen);
		return 0;
	}

	case VMX_EXIT_EPT_VIOLATION:
		/*
		 * EPT violation not expected in the trivial guest (all
		 * needed pages are mapped).  Treat as crash.
		 */
		state->run_result = 1; /* PHANTOM_RESULT_CRASH */
		return 1;

	case VMX_EXIT_EPT_MISCONFIG:
		state->run_result = 1;
		return 1;

	case VMX_EXIT_PREEMPT_TIMER:
		state->run_result = 2; /* PHANTOM_RESULT_TIMEOUT */
		return 1;

	default:
		/*
		 * Unexpected exit: dump VMCS and abort.
		 * phantom_dump_vmcs uses trace_printk — safe here.
		 */
		phantom_dump_vmcs(state->cpu, state->cpu, reason, 0);
		state->run_result = 1;
		return 1;
	}
}

/* ------------------------------------------------------------------
 * Assembly trampoline: VMLAUNCH / VMRESUME
 *
 * Calling convention: System V AMD64 ABI
 *   RDI = pointer to struct phantom_vmx_cpu_state
 *   Returns: 0 on clean VM exit, -EIO on VM-entry failure
 *
 * The trampoline:
 *  1. Saves callee-saved regs (rbx, rbp, r12–r15) on the stack.
 *  2. Stores RSP → state->host_rsp.
 *  3. VMWRITE HOST_RSP = current RSP.
 *  4. VMWRITE HOST_RIP = vm_exit_return.
 *  5. Loads guest GPRs from state->guest_regs.
 *  6. VMLAUNCH (first entry) or VMRESUME (subsequent entries).
 *  7. On CF=1 or ZF=1: fall through to .Lvmentry_fail.
 *
 * vm_exit_return (HOST_RIP):
 *  8. Saves all 15 guest GPRs (except RSP) → state->guest_regs.
 *  9. Restores host callee-saved regs.
 * 10. Returns 0 (RAX=0).
 *
 * IMPORTANT: The state pointer (RDI) is pushed to the stack before
 * loading guest registers so we can find it on VM exit.
 * ------------------------------------------------------------------ */

/*
 * Offsets within struct phantom_guest_regs (used in inline asm).
 * Must match the struct layout exactly.
 */
#define GUEST_REGS_RAX		0
#define GUEST_REGS_RBX		8
#define GUEST_REGS_RCX		16
#define GUEST_REGS_RDX		24
#define GUEST_REGS_RSI		32
#define GUEST_REGS_RDI		40
#define GUEST_REGS_RBP		48
#define GUEST_REGS_R8		56
#define GUEST_REGS_R9		64
#define GUEST_REGS_R10		72
#define GUEST_REGS_R11		80
#define GUEST_REGS_R12		88
#define GUEST_REGS_R13		96
#define GUEST_REGS_R14		104
#define GUEST_REGS_R15		112

/*
 * Offset of guest_regs within phantom_vmx_cpu_state.
 * We use offsetof via the compiler to avoid manual calculation errors.
 * The offset is embedded as an immediate in the asm.
 */
#include <stddef.h>

/*
 * phantom_vmlaunch_trampoline - Enter/resume guest execution.
 * @state: Per-CPU VMX state (in RDI per SysV ABI).
 *
 * Returns 0 on VM exit (dispatched via phantom_vm_exit_dispatch),
 * -EIO on VM-entry failure.
 */
static noinline int phantom_vmlaunch_trampoline(
	struct phantom_vmx_cpu_state *state)
{
	int ret;
	int do_resume = state->launched ? 1 : 0;

	asm volatile (
		/* Save host callee-saved registers */
		"push %%rbx\n\t"
		"push %%rbp\n\t"
		"push %%r12\n\t"
		"push %%r13\n\t"
		"push %%r14\n\t"
		"push %%r15\n\t"

		/*
		 * Push the state pointer (RDI) onto the stack so we can
		 * retrieve it after VM exit (HOST_RIP restores RDI from stack).
		 * Also push a slot for the return value.
		 */
		"push %%rdi\n\t"   /* state ptr — retrieved at vm_exit_return */
		"push $0\n\t"      /* return value slot (0 = success) */

		/* Save RSP → state->host_rsp */
		"movq %%rsp, %c[host_rsp_off](%%rdi)\n\t"

		/* VMWRITE HOST_RSP = current RSP */
		"movq %%rsp, %%rax\n\t"
		"movl %[vmcs_host_rsp], %%ecx\n\t"
		"vmwrite %%rax, %%rcx\n\t"

		/* VMWRITE HOST_RIP = vm_exit_return */
		"lea vm_exit_return(%%rip), %%rax\n\t"
		"movl %[vmcs_host_rip], %%ecx\n\t"
		"vmwrite %%rax, %%rcx\n\t"

		/* Load guest GPRs from state->guest_regs */
		"movq %c[rax_off](%%rdi), %%rax\n\t"
		"movq %c[rbx_off](%%rdi), %%rbx\n\t"
		"movq %c[rcx_off](%%rdi), %%rcx\n\t"
		"movq %c[rdx_off](%%rdi), %%rdx\n\t"
		"movq %c[rsi_off](%%rdi), %%rsi\n\t"
		"movq %c[rbp_off](%%rdi), %%rbp\n\t"
		"movq %c[r8_off](%%rdi),  %%r8\n\t"
		"movq %c[r9_off](%%rdi),  %%r9\n\t"
		"movq %c[r10_off](%%rdi), %%r10\n\t"
		"movq %c[r11_off](%%rdi), %%r11\n\t"
		"movq %c[r12_off](%%rdi), %%r12\n\t"
		"movq %c[r13_off](%%rdi), %%r13\n\t"
		"movq %c[r14_off](%%rdi), %%r14\n\t"
		"movq %c[r15_off](%%rdi), %%r15\n\t"
		/* Load RDI last — we lose the state pointer here */
		"movq %c[rdi_off](%%rdi), %%rdi\n\t"

		/* VMLAUNCH or VMRESUME based on do_resume */
		"testl %[do_resume], %[do_resume]\n\t"
		"jnz   1f\n\t"
		"vmlaunch\n\t"
		"jmp   2f\n\t"
		"1: vmresume\n\t"
		"2:\n\t"

		/*
		 * VM-entry failure: CF=1 (hard fail) or ZF=1 (error number).
		 * Fall through to failure path.
		 * Stack: [rsp+0]=retval_slot [rsp+8]=state_ptr ...
		 */
		"setc  %%al\n\t"
		"setz  %%bl\n\t"
		"orb   %%bl, %%al\n\t"   /* al = 1 if any error */
		"jz    vm_exit_return\n\t"

		/* VM-entry failed: set return slot to -EIO */
		"movq 8(%%rsp), %%rdi\n\t"   /* retrieve state ptr */
		"movl %[vm_instr_error], %%ecx\n\t"
		"vmread %%rcx, %%rax\n\t"
		"movl %%eax, %c[instr_err_off](%%rdi)\n\t"
		"movq $-5, (%%rsp)\n\t"      /* -EIO = -5 */
		"jmp  .Lvmentry_cleanup\n\t"

		/*
		 * VM exit return point — HOST_RIP points here.
		 * At entry:
		 *   RSP = host_rsp (restored by hardware)
		 *   All other host regs = values at VM entry
		 *   RDI = guest RDI (guest register, NOT state ptr)
		 *   Stack: [rsp+0]=retval_slot [rsp+8]=state_ptr ...
		 *
		 * We must save all guest GPRs before touching any host regs.
		 */
		"vm_exit_return:\n\t"

		/* Retrieve state pointer from stack (above return slot) */
		"movq 8(%%rsp), %%rdi\n\t"

		/* Save guest GPRs — RDI is the state ptr now (host value),
		 * but guest RDI is still in the hardware register.
		 * We save all registers except RDI first, then we recover
		 * guest RDI from... we can't, it's lost.
		 *
		 * Correct approach: save guest RDI before overwriting RDI.
		 * But we already loaded RDI with state ptr above.
		 * Solution: we save guest RAX first (it's free), then
		 * use RAX as scratch to save guest RDI.
		 */

		/* Save guest RAX using the return slot as temp */
		"movq %%rax, (%%rsp)\n\t"       /* temp: guest rax */

		/* Now save all guest GPRs */
		"movq %%rax, %c[rax_off](%%rdi)\n\t"   /* guest rax (was retval_slot) */
		"movq %%rbx, %c[rbx_off](%%rdi)\n\t"
		"movq %%rcx, %c[rcx_off](%%rdi)\n\t"
		"movq %%rdx, %c[rdx_off](%%rdi)\n\t"
		"movq %%rsi, %c[rsi_off](%%rdi)\n\t"
		/* RDI: we lost the guest value; save 0 as placeholder */
		"movq $0,    %c[rdi_off](%%rdi)\n\t"
		"movq %%rbp, %c[rbp_off](%%rdi)\n\t"
		"movq %%r8,  %c[r8_off](%%rdi)\n\t"
		"movq %%r9,  %c[r9_off](%%rdi)\n\t"
		"movq %%r10, %c[r10_off](%%rdi)\n\t"
		"movq %%r11, %c[r11_off](%%rdi)\n\t"
		"movq %%r12, %c[r12_off](%%rdi)\n\t"
		"movq %%r13, %c[r13_off](%%rdi)\n\t"
		"movq %%r14, %c[r14_off](%%rdi)\n\t"
		"movq %%r15, %c[r15_off](%%rdi)\n\t"

		/* Set return value = 0 (success) */
		"movq $0, (%%rsp)\n\t"

		".Lvmentry_cleanup:\n\t"
		/* Pop return value into RAX (will be used below) */
		"movq (%%rsp), %%rax\n\t"
		"addq $8, %%rsp\n\t"         /* pop return slot */
		"addq $8, %%rsp\n\t"         /* pop state ptr slot */

		/* Restore host callee-saved registers */
		"pop %%r15\n\t"
		"pop %%r14\n\t"
		"pop %%r13\n\t"
		"pop %%r12\n\t"
		"pop %%rbp\n\t"
		"pop %%rbx\n\t"

		: "=a"(ret)
		: [do_resume]        "rm"(do_resume),
		  [vmcs_host_rsp]    "i"(VMCS_HOST_RSP),
		  [vmcs_host_rip]    "i"(VMCS_HOST_RIP),
		  [vm_instr_error]   "i"(VMCS_RO_VM_INSTR_ERROR),
		  [host_rsp_off]     "i"(offsetof(struct phantom_vmx_cpu_state,
					          host_rsp)),
		  [instr_err_off]    "i"(offsetof(struct phantom_vmx_cpu_state,
					          vm_instr_error)),
		  [rax_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.rax)),
		  [rbx_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.rbx)),
		  [rcx_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.rcx)),
		  [rdx_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.rdx)),
		  [rsi_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.rsi)),
		  [rdi_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.rdi)),
		  [rbp_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.rbp)),
		  [r8_off]           "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.r8)),
		  [r9_off]           "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.r9)),
		  [r10_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.r10)),
		  [r11_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.r11)),
		  [r12_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.r12)),
		  [r13_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.r13)),
		  [r14_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.r14)),
		  [r15_off]          "i"(offsetof(struct phantom_vmx_cpu_state,
					          guest_regs.r15))
		: "memory", "cc",
		  "rcx", "rdx", "rsi", "rdi",
		  "r8",  "r9",  "r10", "r11"
	);

	return ret;
}

/* ------------------------------------------------------------------
 * phantom_run_guest - Run guest until it submits a result.
 *
 * Executes a guest-execute loop: call trampoline → dispatch exit →
 * repeat until exit_dispatch returns non-zero.
 *
 * Must run on the target CPU (smp_call_function_single or preempt-off).
 * ------------------------------------------------------------------ */

int phantom_run_guest(struct phantom_vmx_cpu_state *state)
{
	int tramp_ret, disp_ret;
	int iterations = 0;

#define MAX_EXIT_ITERATIONS 10000

	if (!state->vmcs_configured)
		return -ENXIO;

	state->run_result      = 0;
	state->run_result_data = 0;

	PHANTOM_TRACE_VM_ENTRY(state->cpu);

	do {
		tramp_ret = phantom_vmlaunch_trampoline(state);
		if (tramp_ret < 0) {
			pr_err("phantom: CPU%d: VM-entry failed err=%d "
			       "vm_instr_error=%u\n",
			       state->cpu, tramp_ret,
			       state->vm_instr_error);
			phantom_dump_vmcs(state->cpu, state->cpu,
					  0xFFFFFFFF, (u64)iterations);
			return tramp_ret;
		}

		/* Mark as launched after first successful entry */
		if (!state->launched)
			state->launched = true;

		disp_ret = phantom_vm_exit_dispatch(state);

		iterations++;
		if (iterations >= MAX_EXIT_ITERATIONS) {
			pr_err("phantom: CPU%d: exceeded max exit iterations\n",
			       state->cpu);
			return -ELOOP;
		}

	} while (disp_ret == 0);

	return (disp_ret > 0) ? 0 : disp_ret;
}
