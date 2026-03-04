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
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/sched.h>
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
#include <asm/linkage.h>       /* ASM_RET: retpoline-safe ret instruction */

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

/*
 * __invept_all - INVEPT type 2 (all-context invalidation).
 *
 * Invalidates all EPT TLB entries for ALL EPTPs on this logical
 * processor.  Used during teardown to ensure KVM L0 has no cached
 * references to our (soon to be freed) EPT page tables.
 */
static inline void __invept_all(void)
{
	struct phantom_invept_desc desc = { .eptp = 0, .rsvd = 0 };

	asm volatile("invept %0, %1"
		     :: "m"(desc), "r"((u64)2)   /* type 2 = all-context */
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

/*
 * phantom_vmxoff_cpu — helper used only by phantom_vmxoff_all for the
 * (now rare) case where a CPU still has vmx_active=true.  After our fix,
 * the vCPU thread always runs VMXOFF locally, so vmx_active will be false
 * by the time phantom_vmxoff_all is called.  The function is kept for
 * correctness on abnormal paths (e.g. vCPU thread never started).
 */
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
 *
 * phantom_vmxon_all now ONLY allocates the VMXON backing page and reads
 * the VMX revision ID.  The actual VMXON instruction is executed by the
 * vCPU thread on its own CPU (no smp_call_function_single IPI needed).
 *
 * Background: after the first load's VMLAUNCH+VMXOFF cycle, KVM L0's
 * nested VMX tracking for the target CPU is in a post-nested-exit state.
 * Any cross-CPU function-call IPI (smp_call_function_single) to that CPU
 * — even after VMXOFF — causes a triple fault in the guest kernel.
 *
 * The fix: the vCPU thread performs VMXON + VMCS alloc + VMPTRLD locally
 * on its own CPU at startup, then signals vcpu_init_done.  Module init
 * waits on vcpu_init_done.  Zero cross-CPU IPIs during the VMX init path.
 * ------------------------------------------------------------------ */

int phantom_vmxon_all(const struct cpumask *cpumask)
{
	struct phantom_vmx_cpu_state *state;
	u64 vmx_basic;
	u32 revision_id;
	int cpu, ret = 0;

	/*
	 * Read VMX revision ID from BSP (same value on all logical CPUs
	 * on the same physical package).
	 */
	if (rdmsrl_safe(MSR_IA32_VMX_BASIC, &vmx_basic)) {
		pr_err("phantom: failed to read VMX_BASIC for revision\n");
		return -EIO;
	}
	revision_id = (u32)(vmx_basic & VMX_BASIC_REVISION_MASK);

	for_each_cpu(cpu, cpumask) {
		int node = cpu_to_node(cpu);

		state = per_cpu_ptr(&phantom_vmx_state, cpu);
		memset(state, 0, sizeof(*state));
		state->cpu            = cpu;
		state->vmx_revision_id = revision_id;

		/*
		 * Allocate the VMXON region backing page.  This can be done
		 * from any CPU — only the physical address matters for VMXON.
		 * The actual VMXON instruction runs in the vCPU thread.
		 */
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

	return 0;

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
		state = per_cpu_ptr(&phantom_vmx_state, cpu);

		/*
		 * Skip the SMP call if the vCPU thread already executed
		 * VMXOFF locally (via kthread_complete_and_exit stop path).
		 * Sending a function-call IPI to a CPU where nested VMX
		 * state was active can hang in nested KVM environments.
		 *
		 * After the vCPU thread runs VMXOFF it sets vmx_active=false,
		 * so we can safely check the flag here.
		 */
		if (state->vmx_active) {
			smp_call_function_single(cpu, phantom_vmxoff_cpu,
						 NULL, 1);
		} else {
			pr_info("phantom: CPU%d: VMX already inactive "
				"(vCPU thread ran VMXOFF)\n", cpu);
		}

		if (state->vmxon_region) {
			__free_page(state->vmxon_region);
			state->vmxon_region = NULL;
		}
	}
}

/*
 * phantom_vmcs_alloc_all is now a no-op: VMCS allocation and VMPTRLD are
 * performed by the vCPU thread on its own CPU (see phantom_vcpu_init_on_cpu).
 * This eliminates cross-CPU IPIs (smp_call_function_single) which caused
 * triple faults in nested KVM after a prior VMLAUNCH+VMXOFF cycle.
 *
 * The function is retained for source compatibility; it always returns 0.
 */
int phantom_vmcs_alloc_all(const struct cpumask *cpumask)
{
	return 0;
}

void phantom_vmcs_free_all(const struct cpumask *cpumask)
{
	struct phantom_vmx_cpu_state *state;
	int cpu;

	/*
	 * After phantom_vcpu_thread_stop() returns, the vCPU thread has
	 * already executed VMCLEAR + VMXOFF on the target CPU and exited
	 * via kthread_complete_and_exit().  The VMCS backing page is no
	 * longer referenced by any CPU (VMCLEAR removed it from "current"
	 * state; VMXOFF exited VMX root mode entirely).
	 *
	 * We only need to free the backing page here.  No SMP callbacks
	 * are needed or used — in a KVM nested VMX environment any
	 * cross-CPU IPI after VMLAUNCH causes a triple fault.
	 */
	for_each_cpu(cpu, cpumask) {
		state = per_cpu_ptr(&phantom_vmx_state, cpu);
		if (state->vmcs_region) {
			__free_page(state->vmcs_region);
			state->vmcs_region = NULL;
			pr_info("phantom: CPU%d: VMCS region freed\n", cpu);
		}
	}
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
	u64 high_word;

	native_store_gdt(&gdtr);
	asm volatile("str %0" : "=rm"(tr));
	tr &= ~7; /* clear RPL bits */

	gdt  = (struct desc_struct *)(gdtr.address + tr);
	base = get_desc_base(gdt);

	/*
	 * 64-bit TSS descriptor layout (Intel SDM Vol 3A, Table 3-2):
	 *
	 * Word 0 (bytes  0– 7): standard segment descriptor encoding
	 *   bits 39:16 = Base[23:0], bits 63:56 = Base[31:24]
	 *   get_desc_base() extracts Base[31:0] from word 0.
	 *
	 * Word 1 (bytes  8–15): extension for 64-bit descriptor
	 *   bits 31: 0 (of word 1) = Base[63:32]  ← LOWER 32 bits
	 *   bits 63:32 (of word 1) = Reserved, must be 0
	 *
	 * Bug history: the original code used mask 0xFFFFFFFF00000000ULL
	 * which extracted the UPPER 32 bits of word 1 (the reserved field,
	 * always 0), yielding a truncated base address missing bits 63:32.
	 * This caused the TSS base stored in HOST_TR_BASE to be the low
	 * 32 bits only (e.g. 0x000000004377f000 instead of 0xfffffe4916fb1000).
	 * On VM exit, the CPU loaded this wrong TSS base, corrupting IST
	 * entries and causing a triple fault ~100ms later when the first
	 * IST-based interrupt (NMI, double fault) fired.
	 */
	memcpy(&high_word, (u8 *)gdt + 8, 8);
	base |= (high_word & 0x00000000FFFFFFFFULL) << 32;

	return base;
}

/* ------------------------------------------------------------------
 * VMCS control field population
 * ------------------------------------------------------------------ */

static int phantom_vmcs_setup_controls(struct phantom_vmx_cpu_state *state,
				       bool use_true_ctls, u64 eptp)
{
	u32 pin, proc, proc2, exit_c, entry_c;

	/*
	 * Pin-based: external-int exiting + NMI exiting.
	 *
	 * NOTE: VMX preemption timer (PIN_BASED_PREEMPT_TIMER) is deliberately
	 * NOT enabled for nested KVM testing.  In a nested VMX environment,
	 * the L0 KVM hypervisor may propagate the preemption timer expiry to L1
	 * as an asynchronous VM exit AFTER L1's guest (L2) has already exited.
	 * This causes a spurious EXIT_REASON_PREEMPT_TIMER exit in phantom's
	 * context, crashing the guest kernel.
	 *
	 * For Phase 2+ bare-metal deployment, re-enable with appropriate
	 * handling to guard against this spurious exit.
	 */
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

	/* VM-exit controls: host 64-bit + PAT + EFER.
	 *
	 * NOTE: VM_EXIT_ACK_INT_ON_EXIT is deliberately NOT set.
	 *
	 * When PIN_BASED_EXT_INT_EXITING causes an external interrupt to
	 * exit from L2 to L1, the CPU must still deliver the interrupt to
	 * L1's IDT.  With VM_EXIT_ACK_INT_ON_EXIT set, the CPU acknowledges
	 * the interrupt (sends EOI to the virtual APIC) before exiting,
	 * which means the interrupt is dismissed without ever running L1's
	 * handler (e.g., the Linux timer interrupt handler).
	 *
	 * Without VM_EXIT_ACK_INT_ON_EXIT, the external interrupt remains
	 * pending at the virtual APIC.  After the exit handler calls
	 * local_irq_enable(), the APIC delivers the interrupt via L1's IDT
	 * normally, allowing the Linux timer and other interrupt handlers to
	 * run.  This prevents L1's APIC timer from being silently swallowed
	 * by phantom.ko, which would cause scheduler failures and eventually
	 * a triple fault 100-500ms after VMXOFF.
	 */
	{
		u32 msr = use_true_ctls ?
			MSR_IA32_VMX_TRUE_EXIT_CTLS :
			MSR_IA32_VMX_EXIT_CTLS;

		exit_c = phantom_adjust_controls(
			VM_EXIT_HOST_ADDR_SPACE_SIZE |
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

	/*
	 * Exception bitmap: intercept all 32 exception vectors (0xFFFFFFFF).
	 * This ensures any guest exception exits to us rather than going to
	 * the guest IDT (which is empty — limit=0).  Without this, any
	 * exception in the guest causes a double fault then triple fault.
	 * The exit handler (phantom_vm_exit_dispatch) logs the vector and
	 * treats it as a crash.
	 */
	phantom_vmcs_write32(VMCS_CTRL_EXCEPTION_BITMAP, 0xFFFFFFFFU);

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
	asm volatile("sidt %0" : "=m"(idtr));
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
 * phantom_vmcs_setup - Allocate all pages needed for VMCS execution.
 *
 * MUST be called from process context (sleepable, GFP_KERNEL OK).
 * Allocates: MSR bitmap, 4 EPT pages, 6 guest memory pages.
 * Builds: EPT page tables, guest page tables (memset + pointer writes).
 *
 * Does NOT write VMCS fields — call phantom_vmcs_configure_fields()
 * on the target CPU afterwards.
 *
 * Idempotent: returns 0 immediately if pages_allocated is already set.
 *
 * Returns 0 on success, negative errno on failure (goto-cleanup).
 * ------------------------------------------------------------------ */

int phantom_vmcs_setup(struct phantom_vmx_cpu_state *state)
{
	int cpu = state->cpu;
	int node = cpu_to_node(cpu);
	int ret;

	if (state->pages_allocated)
		return 0;

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

	/*
	 * Build page tables while still in process context.
	 * These writes go to the allocated pages (not VMCS fields),
	 * so they are safe here.
	 */
	phantom_build_guest_pagetables(state);
	phantom_build_ept(state); /* result (eptp) used in configure_fields */

	state->pages_allocated = true;
	pr_info("phantom: CPU%d: pages allocated\n", cpu);
	return 0;

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

/* ------------------------------------------------------------------
 * phantom_vmcs_configure_fields - Write VMCS control and state fields.
 *
 * MUST run on the target CPU (VMCS must be current via VMPTRLD).
 * Safe in interrupt context — no sleeping allocations.
 * Idempotent once vmcs_configured is set.
 *
 * Pages must have been allocated by phantom_vmcs_setup() first.
 *
 * Returns 0 on success, negative errno on failure.
 * ------------------------------------------------------------------ */

int phantom_vmcs_configure_fields(struct phantom_vmx_cpu_state *state)
{
	u64 vmx_basic;
	bool use_true_ctls;
	u64 eptp;
	int cpu = state->cpu;
	int ret;

	if (state->vmcs_configured)
		return 0;

	if (!state->pages_allocated) {
		pr_err("phantom: CPU%d: configure_fields called before alloc\n",
		       cpu);
		return -ENXIO;
	}

	rdmsrl(MSR_IA32_VMX_BASIC, vmx_basic);
	use_true_ctls = !!(vmx_basic & VMX_BASIC_TRUE_CTLS);

	/*
	 * Rebuild EPT on this CPU to get the correct EPTP value.
	 * The EPT page tables were built in phantom_vmcs_setup(); we call
	 * phantom_build_ept() again to get the EPTP (it's idempotent — same
	 * physical addresses → same result).
	 */
	eptp = phantom_build_ept(state);

	/* Populate VMCS control fields */
	ret = phantom_vmcs_setup_controls(state, use_true_ctls, eptp);
	if (ret)
		return ret;

	/* Populate VMCS guest-state fields */
	ret = phantom_vmcs_setup_guest_state();
	if (ret)
		return ret;

	/* Populate VMCS host-state fields (reads current CPU state) */
	ret = phantom_vmcs_setup_host_state();
	if (ret)
		return ret;

	/* INVEPT after initial setup */
	__invept_single(eptp);

	state->launched = false;
	state->vmcs_configured = true;

	pr_info("phantom: CPU%d: VMCS configured (eptp=0x%llx)\n",
		cpu, eptp);
	return 0;
}

/**
 * phantom_vmcs_teardown - Release all resources allocated by phantom_vmcs_setup.
 * @state: Per-CPU VMX state.
 */
void phantom_vmcs_teardown(struct phantom_vmx_cpu_state *state)
{
	/*
	 * Guard on pages_allocated (not vmcs_configured): pages may have been
	 * allocated in process context but VMCS fields not yet written if the
	 * module unloads before the first ioctl completes the two-phase setup.
	 */
	if (!state->pages_allocated)
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

	state->pages_allocated = false;
	state->vmcs_configured = false;
	state->launched        = false;
}

/* ------------------------------------------------------------------
 * vCPU kernel thread — dedicated per-CPU thread for guest execution.
 *
 * Problem solved: smp_call_function_single delivers the IPI callback
 * with local IRQs disabled.  In a nested KVM environment, after the
 * first VMLAUNCH/VMRESUME cycle, KVM's internal vCPU state is in a
 * post-nested-exit condition.  A subsequent IPI to the same CPU may
 * not be processed (the KVM vCPU doesn't service generic IPIs after a
 * nested VMX round trip), causing smp_call_function_single to spin
 * indefinitely.
 *
 * Solution: create a dedicated kernel thread pinned to the target CPU.
 * The thread waits on a completion for work, runs the guest, signals
 * completion back to the ioctl, and loops.  Kernel threads are proper
 * kernel tasks; the scheduler moves them to their pinned CPU normally,
 * and they are not subject to the nested-VMX IPI delivery issue.
 *
 * IPI-free init: the thread also performs VMXON + VMCS alloc + VMPTRLD
 * locally at startup (phantom_vcpu_init_on_cpu), eliminating the
 * smp_call_function_single calls that previously caused triple faults
 * on the second module load in nested KVM environments.
 * ------------------------------------------------------------------ */

/*
 * phantom_vcpu_init_on_cpu - Per-CPU VMX init: VMXON + VMCS alloc + VMPTRLD.
 *
 * Called from the vCPU thread, running on state->cpu.  No cross-CPU
 * IPIs involved.  This replaces the smp_call_function_single approach
 * used in phantom_vmxon_cpu / phantom_vmcs_alloc_cpu.
 *
 * Root cause of second-load crash: after VMLAUNCH+VMXOFF, KVM L0's
 * nested VMX tracking for this CPU is in a post-nested-exit state.
 * Any function-call IPI to this CPU in that state causes a triple
 * fault.  Running VMXON locally in the thread avoids all IPIs.
 *
 * Returns 0 on success, negative errno on failure.
 */
static int phantom_vcpu_init_on_cpu(struct phantom_vmx_cpu_state *state)
{
	u32 *rev_ptr;
	u64 phys;
	unsigned long cr4;
	bool we_set_vmxe = false;
	int cpu = smp_processor_id();
	int ret;

	/* Sanity: must be running on the right CPU */
	if (WARN_ON(cpu != state->cpu))
		return -EINVAL;

	/* ----------------------------------------------------------
	 * Step 1: VMXON
	 * ---------------------------------------------------------- */
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
	*rev_ptr = state->vmx_revision_id;
	phys     = page_to_phys(state->vmxon_region);

	ret = __vmxon(phys);
	if (ret) {
		pr_err("phantom: CPU%d: VMXON failed (err=%d) — "
		       "is kvm_intel loaded?\n", cpu, ret);
		if (we_set_vmxe)
			cr4_clear_bits(X86_CR4_VMXE);
		state->vmx_active = false;
		state->init_err   = ret;
		return ret;
	}

	state->vmx_active = true;
	pr_info("phantom: CPU%d: VMX root entered successfully\n", cpu);

	/* ----------------------------------------------------------
	 * Step 2: VMCS alloc + VMCLEAR + VMPTRLD
	 * ---------------------------------------------------------- */
	state->vmcs_region = alloc_pages_node(cpu_to_node(cpu),
					      GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->vmcs_region) {
		pr_err("phantom: CPU%d: failed to alloc VMCS region\n", cpu);
		__vmxoff();
		if (we_set_vmxe)
			cr4_clear_bits(X86_CR4_VMXE);
		state->vmx_active = false;
		return -ENOMEM;
	}

	{
		u32 *vmcs_rev = (u32 *)page_address(state->vmcs_region);

		*vmcs_rev = state->vmx_revision_id & ~BIT(31);
	}
	phys = page_to_phys(state->vmcs_region);

	ret = __vmclear(phys);
	if (ret) {
		pr_err("phantom: CPU%d: VMCLEAR failed\n", cpu);
		__free_page(state->vmcs_region);
		state->vmcs_region = NULL;
		__vmxoff();
		if (we_set_vmxe)
			cr4_clear_bits(X86_CR4_VMXE);
		state->vmx_active = false;
		return ret;
	}

	ret = __vmptrld(phys);
	if (ret) {
		pr_err("phantom: CPU%d: VMPTRLD failed\n", cpu);
		__free_page(state->vmcs_region);
		state->vmcs_region = NULL;
		__vmxoff();
		if (we_set_vmxe)
			cr4_clear_bits(X86_CR4_VMXE);
		state->vmx_active = false;
		return ret;
	}

	pr_info("phantom: CPU%d: VMCS allocated and loaded\n", cpu);
	return 0;
}

/* Timeout for vCPU thread's initial idle wait (before first VMLAUNCH): 50ms */
#define VCPU_THREAD_TIMEOUT_MS		50

/*
 * phantom_vcpu_fn - vCPU kernel thread main function.
 *
 * Pinned to state->cpu.  Two-phase wakeup strategy:
 *
 * Phase 1 — before first VMLAUNCH (safe to sleep):
 *   Uses wait_for_completion_interruptible_timeout() with 50ms timeout.
 *   The ioctl signals via complete(vcpu_run_start), which sends a
 *   RESCHEDULE IPI to CPU0.  This is safe because KVM L0's nested VMX
 *   tracking is not yet active (no VMLAUNCH has occurred).
 *
 * Phase 2 — after first VMLAUNCH (MUST NOT sleep):
 *   In KVM nested VMX (L0=KVM, L1=phantom, L2=guest), after the first
 *   VMLAUNCH, KVM L0's nested VMX tracking for this vCPU becomes "dirty"
 *   even after the guest exits.  Any RESCHEDULE IPI (0xfd) sent to CPU0
 *   while this state persists causes a TRIPLE FAULT — instantly resetting
 *   the guest kernel without any error output.
 *
 *   Root cause: complete() sends RESCHEDULE IPI to wake the thread.
 *   smp_call_function_single() sends FUNCTION-CALL IPI.  Both are fatal.
 *
 *   Solution: busy-wait via cpu_relax() on the vcpu_work_ready flag.
 *   The ioctl handler sets this flag without sending any IPI.
 *   cpu_relax() yields the CPU for a short time without sleeping —
 *   the thread remains TASK_RUNNING on CPU0 and never goes to
 *   TASK_INTERRUPTIBLE.  A sleeping task needs an IPI to be woken;
 *   a TASK_RUNNING busy-waiting task does not.
 *
 * Stop protocol — kthread_stop() is safe in BOTH phases:
 *
 *   kthread_stop() sets KTHREAD_SHOULD_STOP and calls wake_up_process().
 *   wake_up_process() only sends a RESCHEDULE IPI if the target thread
 *   is in TASK_SLEEPING state.  Key invariant:
 *
 *     Phase 1: no VMLAUNCH yet — RESCHEDULE IPI is safe.
 *     Phase 2: thread is TASK_RUNNING (busy-waiting) — wake_up_process()
 *              is a no-op.  No IPI is sent.
 *
 *   In Phase 2, the thread polls kthread_should_stop() in its loop and
 *   exits cleanly by returning from this function (standard kthread exit).
 *   kthread_stop() waits for the return via the kthread-internal
 *   completion — no extra completion or flag needed.
 *
 *   This design ensures:
 *     1. No cross-CPU IPIs after VMLAUNCH (Phase 2 safety).
 *     2. Proper module reference release (thread returns, not do_exit).
 *     3. No WARN in do_exit (kthread exits via normal function return).
 *     4. phantom_vmxoff_all() skips smp_call for CPUs where vmx_active=0.
 */
static int phantom_vcpu_fn(void *data)
{
	struct phantom_vmx_cpu_state *state = data;
	bool vmlaunch_done = false;  /* true after first VMLAUNCH */
	int ret;

	pr_info("phantom: CPU%d: vCPU thread started (pid=%d)\n",
		state->cpu, current->pid);

	/*
	 * Perform VMXON + VMCS alloc + VMPTRLD locally on this CPU.
	 *
	 * This MUST happen here in the thread, not via smp_call_function_single
	 * from another CPU.  After a prior VMLAUNCH+VMXOFF cycle (first module
	 * load), KVM L0's nested VMX tracking for this CPU is in a post-nested-
	 * exit state.  Any function-call IPI to this CPU in that state triggers
	 * a triple fault in the guest kernel — even after VMXOFF.
	 *
	 * Running VMXON locally in the pinned thread avoids all cross-CPU IPIs
	 * during VMX init, fixing the second-load crash.
	 */
	state->vcpu_init_result = phantom_vcpu_init_on_cpu(state);
	complete(&state->vcpu_init_done);

	if (state->vcpu_init_result) {
		/* Init failed — cannot proceed; thread exits cleanly. */
		pr_err("phantom: CPU%d: vcpu init failed: %d\n",
		       state->cpu, state->vcpu_init_result);
		return state->vcpu_init_result;
	}

	for (;;) {
		/*
		 * Wait for work or stop request.
		 *
		 * Phase 1 (before first VMLAUNCH): sleep on completion.
		 * Phase 2 (after first VMLAUNCH):  busy-wait on flag.
		 *
		 * Stop mechanism (IPI-free after VMLAUNCH):
		 *   phantom_vcpu_thread_stop() sets vcpu_stop_requested=true
		 *   (plain memory write, no IPI) and waits on vcpu_stopped.
		 *   The thread checks vcpu_stop_requested in both phases.
		 *   After do_stop (VMXOFF), the thread signals vcpu_stopped
		 *   and returns.  phantom_vcpu_thread_stop() then calls
		 *   kthread_stop() — by that point the thread has already
		 *   exited VMX-root mode, so any IPI is harmless.
		 *
		 *   In Phase 1, we also check kthread_should_stop() (from
		 *   kthread_stop() directly) as a fallback for the case where
		 *   stop is requested before VMLAUNCH.
		 */
		if (!vmlaunch_done) {
			/* Phase 1: safe to sleep (no VMLAUNCH yet) */
			long tret;

			/*
			 * Check vcpu_stop_requested first (set without IPI).
			 * Also check kthread_should_stop() for compatibility.
			 */
			if (READ_ONCE(state->vcpu_stop_requested) ||
			    kthread_should_stop())
				goto do_stop;

			tret = wait_for_completion_interruptible_timeout(
				&state->vcpu_run_start,
				msecs_to_jiffies(VCPU_THREAD_TIMEOUT_MS));

			/* Re-check after wakeup */
			if (READ_ONCE(state->vcpu_stop_requested) ||
			    kthread_should_stop())
				goto do_stop;

			/* Timeout or signal — loop back and wait again */
			if (tret <= 0)
				continue;

			/* Completion fired: work is available */
		} else {
			/*
			 * Phase 2: busy-wait — thread must stay TASK_RUNNING.
			 *
			 * CRITICAL: After VMLAUNCH, any RESCHEDULE IPI to
			 * this CPU causes a triple fault in KVM nested mode.
			 * We MUST NOT call kthread_stop() or complete() or any
			 * function that might trigger a wakeup IPI to this CPU.
			 *
			 * Instead, we use vcpu_stop_requested — a plain bool
			 * that the stopper sets via WRITE_ONCE() (no IPI).
			 * The thread polls it here via READ_ONCE().
			 *
			 * We also check kthread_should_stop() as a secondary
			 * mechanism (for cases where kthread_stop() is called
			 * after the thread has already left VMX-root mode and
			 * signaled vcpu_stopped — i.e., after do_stop is done).
			 *
			 * cond_resched() prevents RCU stalls: the scheduler
			 * runs locally on this CPU (TIF_NEED_RESCHED), keeping
			 * the task TASK_RUNNING — no cross-CPU IPI.
			 */
			while (!smp_load_acquire(&state->vcpu_work_ready) &&
			       !READ_ONCE(state->vcpu_stop_requested) &&
			       !kthread_should_stop()) {
				cpu_relax();
				cond_resched();
			}

			if (READ_ONCE(state->vcpu_stop_requested) ||
			    kthread_should_stop())
				goto do_stop;

			/* Work available — consume the flag */
			smp_store_release(&state->vcpu_work_ready, false);
		}

		/* Check for valid run request */
		if ((state->vcpu_run_request & 1) == 0)
			continue;

		/*
		 * Configure VMCS fields (idempotent — skips if already done).
		 * Runs on state->cpu where VMCS is current via VMPTRLD.
		 */
		ret = phantom_vmcs_configure_fields(state);
		if (ret) {
			pr_err("phantom: CPU%d: vcpu configure failed: %d\n",
			       state->cpu, ret);
			state->vcpu_run_result = ret;
			complete(&state->vcpu_run_done);
			continue;
		}

		/*
		 * Reset VMCS guest state for relaunches (bit 1 set).
		 * On first run, configure_fields initialised everything.
		 * On re-launch, reset RIP/RSP/RFLAGS for a clean restart.
		 */
		if (state->vcpu_run_request & 2) {
			phantom_vmcs_write64(VMCS_GUEST_RIP, GUEST_CODE_GPA);
			phantom_vmcs_write64(VMCS_GUEST_RSP,
					     GUEST_STACK_GPA + 0xFF0ULL);
			phantom_vmcs_write32(VMCS_GUEST_INTR_STATE,     0);
			phantom_vmcs_write32(VMCS_GUEST_ACTIVITY_STATE, 0);
			phantom_vmcs_write64(VMCS_GUEST_RFLAGS,         0x2ULL);
		}

		/* Run the guest — pinned to state->cpu */
		state->vcpu_run_result = phantom_run_guest(state);

		/*
		 * After the first VMLAUNCH/VMRESUME, switch to busy-wait mode.
		 * KVM L0's nested VMX tracking is now "dirty" for this CPU:
		 * any subsequent RESCHEDULE IPI will cause a triple fault.
		 * From this point on, the thread never sleeps.
		 */
		vmlaunch_done = true;

		/*
		 * Signal ioctl handler that the run is complete.
		 *
		 * complete() sends a RESCHEDULE IPI to wake the ioctl thread.
		 * That IPI goes to the CPU running the ioctl (e.g., CPU3),
		 * NOT to this thread's CPU (CPU0).  It is therefore safe even
		 * in Phase 2.
		 */
		complete(&state->vcpu_run_done);
	}

	/* UNREACHABLE — loop exits only via goto do_stop below */

do_stop:
	/*
	 * Stop sequence — runs on this CPU, zero cross-CPU IPIs.
	 *
	 * Correct Intel SDM teardown sequence: INVEPT → VMCLEAR → VMXOFF.
	 *
	 * INVEPT type=2 (all-context) flushes all cached EPT mappings for
	 * this LP from KVM L0's TLB before we free the EPT page tables.
	 * This prevents KVM L0 from referencing freed EPT pages after
	 * module unload.
	 *
	 * VMCLEAR marks the VMCS as inactive/not-current in KVM L0's nested
	 * VMX tracking.  This is required for proper KVM state cleanup:
	 * without VMCLEAR, KVM L0's nested_vmx_hardware_disable() (called
	 * from handle_vmxoff) may leave residual state that causes the next
	 * VMXON to trigger a triple fault.
	 *
	 * VMXOFF exits VMX-root mode.  phantom_vmxoff_all() skips this CPU
	 * because vmx_active is set to false here.
	 *
	 * The VMCS backing page is freed by phantom_vmcs_free_all() after
	 * kthread_stop() returns.  By that point, both VMCLEAR and VMXOFF
	 * have completed and no CPU references the VMCS page.
	 */
	if (state->vmx_active) {
		/*
		 * Step 1: VMCLEAR — marks VMCS as inactive and not-current.
		 *
		 * NOTE: INVEPT is intentionally omitted here.  In a nested
		 * KVM environment, INVEPT causes a VMEXIT to KVM L0 and
		 * KVM L0 handles TLB invalidation internally when it processes
		 * our VMCLEAR and VMXOFF exits.  Executing INVEPT before VMXOFF
		 * was found to cause hangs in the vCPU thread (the INVEPT exit
		 * to KVM L0 may not return cleanly in all cases).
		 *
		 * The EPT pages are freed after VMXOFF, by which point KVM L0
		 * has already processed VMXOFF and no longer references them.
		 *
		 * Old comment preserved for history:
		 * "INVEPT type=2 (all-context) flushes all cached EPT mappings
		 *  for this LP from KVM L0's TLB before we free the EPT page
		 *  tables."
		 */

		/*
		 * VMCLEAR — marks VMCS as inactive and not-current.
		 *
		 * VMCLEAR is required before VMXOFF so that KVM L0's nested
		 * VMX state machine properly transitions the VMCS from
		 * "active/current" to "inactive/not-current".  Without this
		 * step (when a guest WAS launched), the subsequent VMXOFF may
		 * leave KVM's nested state inconsistent, causing the next
		 * VMXON to triple-fault.
		 *
		 * IMPORTANT: Only call VMCLEAR if the guest was actually
		 * launched (state->launched is true).  Calling VMCLEAR on a
		 * VMCS that was never the target of VMLAUNCH triggers a KVM
		 * nested VMX bug in certain configurations: KVM attempts to
		 * clean up shadow VMCS state that was never fully initialised,
		 * causing a guest triple fault.
		 *
		 * When no VMLAUNCH occurred (not launched path), VMXOFF alone
		 * is sufficient — KVM's handle_vmxoff sees a "never-launched"
		 * nested VMCS and cleans it up correctly without VMCLEAR.
		 */
		if (state->vmcs_region && state->launched) {
			pr_info("phantom: CPU%d: stop: VMCLEAR (launched)\n",
				state->cpu);
			__vmclear(page_to_phys(state->vmcs_region));
		} else if (state->vmcs_region) {
			pr_info("phantom: CPU%d: stop: skip VMCLEAR "
				"(never launched)\n", state->cpu);
		}

		/*
		 * Step 3: VMXOFF — exits VMX-root mode.
		 */
		pr_info("phantom: CPU%d: stop: VMXOFF\n", state->cpu);
		__vmxoff();
		if (!(state->saved_cr4 & X86_CR4_VMXE))
			cr4_clear_bits(X86_CR4_VMXE);
		state->vmx_active    = false;
		state->launched      = false;
		state->vmcs_configured = false;
	} else if (state->vmcs_region) {
		/*
		 * VMX was not active (init failed before VMXON, or already
		 * cleaned up).  If a VMCS region was allocated, mark it as
		 * unconfigured to avoid phantom_vmcs_free_all accessing it
		 * while it might still be "current" on some CPU.
		 *
		 * In the normal path, state->vmx_active is true whenever
		 * vmcs_region is allocated (phantom_vcpu_init_on_cpu sets
		 * vmx_active=true after VMXON + vmcs_region alloc).
		 */
		state->launched      = false;
		state->vmcs_configured = false;
	}

	/*
	 * Signal that VMX teardown is complete (VMXOFF has run or was not
	 * needed).  phantom_vcpu_thread_stop() waits on this completion
	 * before calling kthread_stop(), ensuring that kthread_stop()'s
	 * wake_up_process() IPI (if any) only arrives after we are out of
	 * VMX-root mode — safe because a post-VMXOFF IPI cannot cause a
	 * nested VMX triple fault.
	 */
	complete(&state->vcpu_stopped);

	return 0;
}

/**
 * phantom_vcpu_thread_start - Create and start the per-CPU vCPU thread.
 * @state: Per-CPU VMX state (state->cpu must be set).
 *
 * Returns 0 on success, negative errno on failure.
 */
int phantom_vcpu_thread_start(struct phantom_vmx_cpu_state *state)
{
	struct task_struct *t;

	init_completion(&state->vcpu_init_done);
	state->vcpu_init_result = -EINPROGRESS;

	init_completion(&state->vcpu_run_start);
	init_completion(&state->vcpu_run_done);
	/*
	 * vcpu_run_request must start at 0.
	 *
	 * Previously set to 1 here, which caused the thread to attempt
	 * phantom_vmcs_configure_fields() on the very first wakeup before
	 * the ioctl had a chance to call phantom_vmcs_setup() (page alloc).
	 * With pages_allocated=false, configure_fields would return -ENXIO,
	 * but the race was a latent bug.  Start at 0: the ioctl sets it to 1
	 * when it is ready to run the guest.
	 */
	state->vcpu_run_request    = 0;
	state->vcpu_run_result     = 0;
	state->vcpu_work_ready     = false;
	state->vcpu_stop_requested = false;
	init_completion(&state->vcpu_stopped);

	t = kthread_create(phantom_vcpu_fn, state,
			   "phantom-vcpu/%d", state->cpu);
	if (IS_ERR(t)) {
		pr_err("phantom: CPU%d: failed to create vCPU thread: %ld\n",
		       state->cpu, PTR_ERR(t));
		return PTR_ERR(t);
	}

	/* Pin the thread to the target CPU */
	kthread_bind(t, state->cpu);

	state->vcpu_thread = t;
	wake_up_process(t);

	pr_info("phantom: CPU%d: vCPU thread created (pid=%d)\n",
		state->cpu, t->pid);
	return 0;
}

/**
 * phantom_vcpu_thread_wait_init - Wait for IPI-free per-CPU VMX init.
 * @state: Per-CPU VMX state for the target CPU.
 *
 * Blocks until the vCPU thread has completed VMXON + VMCS alloc +
 * VMPTRLD on its own CPU.  Called from module init after
 * phantom_vcpu_thread_start(), replacing the old smp_call_function_single
 * approach which caused triple faults on second module load.
 *
 * Returns 0 on success, negative errno if per-CPU init failed.
 */
int phantom_vcpu_thread_wait_init(struct phantom_vmx_cpu_state *state)
{
	wait_for_completion(&state->vcpu_init_done);
	return state->vcpu_init_result;
}

/**
 * phantom_vcpu_thread_stop - Stop and destroy the per-CPU vCPU thread.
 * @state: Per-CPU VMX state.
 *
 * Two-phase IPI-free stop protocol:
 *
 *   Phase A — signal stop without IPI:
 *     Sets vcpu_stop_requested=true via WRITE_ONCE().  This is a plain
 *     memory write with no cross-CPU IPI.  The vCPU thread polls this
 *     flag in both Phase 1 (sleeping) and Phase 2 (busy-wait).
 *
 *   In Phase 1 (before VMLAUNCH): the thread is sleeping in
 *     wait_for_completion_interruptible_timeout().  Setting the flag
 *     alone won't wake it.  We also call complete(&vcpu_run_start) to
 *     unblock the wait — this is safe (no VMLAUNCH has occurred yet,
 *     so the RESCHEDULE IPI from complete() is harmless).
 *
 *   In Phase 2 (after VMLAUNCH): the thread is busy-waiting on
 *     vcpu_stop_requested or vcpu_work_ready.  Setting the flag is
 *     sufficient — the thread polls it on every cpu_relax() iteration.
 *     No RESCHEDULE IPI is sent.
 *
 *   Phase B — wait for VMX teardown:
 *     Waits on vcpu_stopped completion.  The thread signals this after
 *     VMXOFF (in do_stop), confirming VMX-root mode has been exited.
 *
 *   Phase C — kthread cleanup:
 *     Calls kthread_stop() to reclaim kernel thread resources (stack,
 *     task_struct, module reference).  By this point the thread has
 *     already completed do_stop and called complete(&vcpu_stopped), so
 *     it is either returning from phantom_vcpu_fn or has already
 *     returned.  kthread_stop() joins the thread by waiting on the
 *     kthread-internal completion — no IPI is needed because the
 *     thread is TASK_RUNNING (returning) or already exited.
 */
void phantom_vcpu_thread_stop(struct phantom_vmx_cpu_state *state)
{
	if (!state->vcpu_thread)
		return;

	/*
	 * Phase A: signal stop (no IPI).
	 *
	 * Set the stop flag so the thread exits its loop on the next
	 * poll.  For Phase 1 threads (sleeping), also complete the
	 * run_start so they wake up and see the flag.  The complete()
	 * here sends a RESCHEDULE IPI — that is safe because Phase 1
	 * means VMLAUNCH has NOT yet occurred, so the IPI is harmless.
	 */
	WRITE_ONCE(state->vcpu_stop_requested, true);
	complete(&state->vcpu_run_start);  /* wake Phase 1 sleeper (safe) */

	/*
	 * Phase B: wait for VMX teardown.
	 *
	 * Block until the thread has executed do_stop (VMCLEAR + VMXOFF)
	 * and signaled vcpu_stopped.  After this point, VMX-root mode is
	 * inactive on state->cpu and any subsequent IPI is safe.
	 */
	wait_for_completion(&state->vcpu_stopped);

	/*
	 * Phase C: kthread cleanup.
	 *
	 * kthread_stop() reclaims the thread's resources.  The thread
	 * has already completed its VMX work (signaled vcpu_stopped) and
	 * is about to return from phantom_vcpu_fn (or has already done so).
	 * kthread_stop() → wake_up_process() is a no-op (thread is
	 * TASK_RUNNING or already gone) — no IPI.
	 */
	kthread_stop(state->vcpu_thread);
	state->vcpu_thread = NULL;

	pr_info("phantom: CPU%d: vCPU thread stopped (VMCLEAR+VMXOFF done)\n",
		state->cpu);
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
		u32 vec  = info & 0xFF;

		/* Check valid bit (31) and vector (7:0) */
		if ((info & BIT(31)) && (vec == 2)) {
			/* NMI — re-deliver to host */
			phantom_handle_nmi_exit();
			return 0;
		}
		{
			u64 guest_rip = phantom_vmcs_read64(VMCS_GUEST_RIP);
			u32 ec = 0;

			/* Read error code if the exit info says one is valid */
			if (info & BIT(11))
				ec = phantom_vmcs_read32(VMCS_RO_EXIT_INTR_EC);

			pr_err("phantom: CPU%d: EXCEPTION vec=%u "
			       "info=0x%08x ec=0x%x RIP=0x%llx\n",
			       state->cpu, vec, info, ec, guest_rip);
			/*
			 * Encode diagnostics in run_result_data so userspace
			 * can inspect without dmesg:
			 *   bits 63:48 = 0xDEAD (magic)
			 *   bits 47:32 = guest_rip[15:0]
			 *   bits 31:16 = error_code[15:0]
			 *   bits  7:0  = exception vector
			 */
			state->run_result_data =
				(0xDEADULL << 48) |
				((guest_rip & 0xFFFFULL) << 32) |
				((u64)(ec & 0xFFFF) << 16) |
				(u64)vec;
		}
		state->run_result = 1; /* PHANTOM_RESULT_CRASH */
		return 1;
	}

	case VMX_EXIT_EXTERNAL_INT:
		/*
		 * External interrupt caused a VM exit from L2 to L1.
		 *
		 * VM_EXIT_ACK_INT_ON_EXIT is NOT set in our exit controls.
		 * The interrupt remains pending at the virtual APIC.  When
		 * phantom_run_guest() calls local_irq_enable() after this
		 * dispatch returns 0 (continue), the pending interrupt is
		 * delivered naturally to L1's IDT.  This allows the Linux
		 * timer handler, APIC, and scheduler to run normally.
		 *
		 * We return 0 to VMRESUME the guest after the interrupt
		 * has been delivered.
		 */
		return 0;

	case VMX_EXIT_TRIPLE_FAULT: {
		u64 guest_rip = phantom_vmcs_read64(VMCS_GUEST_RIP);
		u64 guest_cr3 = phantom_vmcs_read64(VMCS_GUEST_CR3);

		pr_err("phantom: CPU%d: TRIPLE FAULT at RIP=0x%llx "
		       "CR3=0x%llx qual=0x%llx\n",
		       state->cpu, guest_rip, guest_cr3, qual);
		state->run_result = 1; /* PHANTOM_RESULT_CRASH */
		return 1;
	}

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

	case VMX_EXIT_EPT_VIOLATION: {
		/*
		 * EPT violation not expected in the trivial guest (all
		 * needed pages are mapped).  Treat as crash.
		 */
		u64 gpa = phantom_vmcs_read64(VMCS_RO_GUEST_PHYS_ADDR);
		u64 rip = phantom_vmcs_read64(VMCS_GUEST_RIP);

		pr_err("phantom: CPU%d: EPT VIOLATION GPA=0x%llx "
		       "RIP=0x%llx qual=0x%llx\n",
		       state->cpu, gpa, rip, qual);
		state->run_result = 1; /* PHANTOM_RESULT_CRASH */
		return 1;
	}

	case VMX_EXIT_EPT_MISCONFIG: {
		u64 gpa = phantom_vmcs_read64(VMCS_RO_GUEST_PHYS_ADDR);

		pr_err("phantom: CPU%d: EPT MISCONFIG GPA=0x%llx "
		       "qual=0x%llx\n",
		       state->cpu, gpa, qual);
		state->run_result = 1;
		return 1;
	}

	case VMX_EXIT_PREEMPT_TIMER: {
		u64 guest_rip = phantom_vmcs_read64(VMCS_GUEST_RIP);

		pr_err("phantom: CPU%d: PREEMPT TIMER expired RIP=0x%llx "
		       "(guest hung?)\n",
		       state->cpu, guest_rip);
		state->run_result = 2; /* PHANTOM_RESULT_TIMEOUT */
		return 1;
	}

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
#include <linux/stddef.h>
#include <linux/objtool.h>

/*
 * phantom_vmlaunch_trampoline - Enter/resume guest execution.
 * @state: Per-CPU VMX state (in RDI per SysV ABI).
 *
 * Returns 0 on VM exit (success), -EIO on VM-entry failure.
 *
 * This is a __naked function: GCC emits NO prologue, NO epilogue, and
 * NO mcount/ftrace instrumentation (notrace is implied by __naked).
 * The entire function body is the asm statement below.
 *
 * Stack layout after all pushes (HOST_RSP points to [RSP+0]):
 *   [RSP+ 0] = return value slot (0 = success, set to -5 on failure)
 *   [RSP+ 8] = state pointer
 *   [RSP+16] = saved host R15
 *   [RSP+24] = saved host R14
 *   [RSP+32] = saved host R13
 *   [RSP+40] = saved host R12
 *   [RSP+48] = saved host RBP
 *   [RSP+56] = saved host RBX
 *   [RSP+64] = return address (from phantom_run_guest's call)
 */
static __naked noinline int
phantom_vmlaunch_trampoline(struct phantom_vmx_cpu_state *state)
{
	/* __naked: only asm statements are allowed here */
	asm (
		/*
		 * On entry: RDI = state pointer (SysV ABI, first argument).
		 * No GCC prologue: RSP points directly at the return address.
		 *
		 * Step 1: Save host callee-saved registers and build frame.
		 */
		"push %%rbx\n\t"
		"push %%rbp\n\t"
		"push %%r12\n\t"
		"push %%r13\n\t"
		"push %%r14\n\t"
		"push %%r15\n\t"
		"push %%rdi\n\t"   /* [RSP+ 8] = state pointer */
		"push $0\n\t"      /* [RSP+ 0] = return value slot */

		/*
		 * Step 2: VMWRITE HOST_RSP = RSP (our frame base).
		 */
		"movq %%rsp, %%rax\n\t"
		"movl $%c[vmcs_host_rsp], %%ecx\n\t"
		"vmwrite %%rax, %%rcx\n\t"

		/*
		 * Step 2b: Refresh HOST_CR3 to the current CR3.
		 *
		 * In a nested KVM environment with KPTI enabled, the kernel
		 * page table CR3 may differ from what was captured at VMCS
		 * configuration time.  Refreshing before each VM entry ensures
		 * the host restores the correct page table on VM exit.
		 * This mirrors what KVM itself does before every VM entry.
		 */
		"movq %%cr3, %%rax\n\t"
		"movl $%c[vmcs_host_cr3], %%ecx\n\t"
		"vmwrite %%rax, %%rcx\n\t"

		/*
		 * Step 3: VMWRITE HOST_RIP = phantom_vm_exit_return.
		 * RIP-relative LEA for position-independent module code.
		 */
		"leaq phantom_vm_exit_return(%%rip), %%rax\n\t"
		"movl $%c[vmcs_host_rip], %%ecx\n\t"
		"vmwrite %%rax, %%rcx\n\t"

		/*
		 * Step 4: Load launched flag into R15 BEFORE touching guest
		 * registers.  movzbq zero-extends the bool byte to 64 bits.
		 * R15 is overwritten with guest_regs.r15 at step 6, after
		 * we've already tested it.
		 */
		"movzbq %c[launched_off](%%rdi), %%r15\n\t"

		/*
		 * Step 5: Load guest GPRs from state->guest_regs.
		 * All loads use RDI (state ptr) as the base register.
		 * RDI itself is loaded last so we can address the struct.
		 */
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

		/*
		 * Step 6: Test launched flag in R15 (sets ZF=1 if zero).
		 * Then overwrite R15 and RDI with guest values.
		 * MOV does NOT change RFLAGS, so the test result survives.
		 */
		"testq %%r15, %%r15\n\t"
		"movq %c[r15_off](%%rdi), %%r15\n\t"
		"movq %c[rdi_off](%%rdi), %%rdi\n\t"

		/*
		 * Step 7: VMLAUNCH (ZF=1, not yet launched) or VMRESUME.
		 * On success: CPU switches to guest.  Does NOT fall through.
		 * On failure: CF=1 or ZF=1.  Falls through to failure path.
		 */
		"jnz  1f\n\t"
		"vmlaunch\n\t"
		"jmp  2f\n\t"
		"1:\n\t"
		"vmresume\n\t"
		"2:\n\t"

		/*
		 * VM-entry failure path.
		 * Retrieve state pointer, record VM_INSTRUCTION_ERROR, ret.
		 */
		"movq 8(%%rsp), %%rdi\n\t"
		"movl $%c[vm_instr_error], %%ecx\n\t"
		"vmread %%rcx, %%rax\n\t"  /* RAX = VM_INSTRUCTION_ERROR */
		"movl %%eax, %c[instr_err_off](%%rdi)\n\t"
		"addq $16, %%rsp\n\t"      /* skip retval + state slots */
		"pop %%r15\n\t"
		"pop %%r14\n\t"
		"pop %%r13\n\t"
		"pop %%r12\n\t"
		"pop %%rbp\n\t"
		"pop %%rbx\n\t"
		"movq $-5, %%rax\n\t"      /* return -EIO */
		ASM_RET

		: /* outputs: none (we ret from asm) */
		: [vmcs_host_rsp]  "i"(VMCS_HOST_RSP),
		  [vmcs_host_rip]  "i"(VMCS_HOST_RIP),
		  [vmcs_host_cr3]  "i"(VMCS_HOST_CR3),
		  [vm_instr_error] "i"(VMCS_RO_VM_INSTR_ERROR),
		  [launched_off]   "i"(offsetof(struct phantom_vmx_cpu_state,
					        launched)),
		  [instr_err_off]  "i"(offsetof(struct phantom_vmx_cpu_state,
					        vm_instr_error)),
		  [rax_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.rax)),
		  [rbx_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.rbx)),
		  [rcx_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.rcx)),
		  [rdx_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.rdx)),
		  [rsi_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.rsi)),
		  [rdi_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.rdi)),
		  [rbp_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.rbp)),
		  [r8_off]         "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.r8)),
		  [r9_off]         "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.r9)),
		  [r10_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.r10)),
		  [r11_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.r11)),
		  [r12_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.r12)),
		  [r13_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.r13)),
		  [r14_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.r14)),
		  [r15_off]        "i"(offsetof(struct phantom_vmx_cpu_state,
					        guest_regs.r15))
		/* no clobbers in a __naked function */
	);
}

/*
 * phantom_vm_exit_return - VM exit landing pad (HOST_RIP target).
 *
 * The CPU jumps here (not calls) on every VM exit, after loading
 * RSP from VMCS HOST_RSP (which equals our saved frame base).
 *
 * Stack state on entry (set up by phantom_vmlaunch_trampoline):
 *   [RSP+ 0] = return value slot (0)
 *   [RSP+ 8] = state pointer
 *   [RSP+16] = saved host R15
 *   [RSP+24] = saved host R14
 *   [RSP+32] = saved host R13
 *   [RSP+40] = saved host R12
 *   [RSP+48] = saved host RBP
 *   [RSP+56] = saved host RBX
 *   [RSP+64] = return address (to phantom_run_guest)
 *
 * All GPRs except RSP hold guest values on entry.
 *
 * This function saves all 15 guest GPRs to state->guest_regs,
 * restores host callee-saved registers, and returns 0 to the caller
 * of phantom_vmlaunch_trampoline (i.e., phantom_run_guest).
 *
 * __naked: no prologue/epilogue.  notrace: no mcount call.
 */
__visible __noreturn __naked
void phantom_vm_exit_return(void)
{
	/*
	 * __naked function body: only asm statements, no C code.
	 *
	 * On entry (CPU jumped here from guest exit):
	 *   RSP = HOST_RSP = our saved frame base
	 *   All GPRs except RSP hold guest values.
	 *
	 * Strategy:
	 *   1. Spill guest RAX to the retval stack slot (frees RAX).
	 *   2. Load state pointer from [RSP+8] into RAX.
	 *   3. Save guest RCX first (frees RCX for scratch use).
	 *   4. Load guest RAX from the stack slot into RCX (reg-to-reg).
	 *   5. Save RCX (== guest RAX) to state->guest_regs.rax.
	 *   6. Save all other guest GPRs directly from their registers.
	 *   7. Restore host callee-saved regs from stack slots.
	 *   8. RAX=0, addq $64 RSP (skips 8 × 8B slots), ret.
	 */
	asm (
		/* Step 1: Spill guest RAX → retval slot [RSP+0] */
		"movq %%rax, (%%rsp)\n\t"

		/* Step 2: RAX = state pointer from [RSP+8] */
		"movq 8(%%rsp), %%rax\n\t"

		/* Step 3: Save guest RCX → state->guest_regs.rcx */
		"movq %%rcx, %c[rcx_off](%%rax)\n\t"

		/* Step 4: RCX = guest RAX (from retval slot) */
		"movq (%%rsp), %%rcx\n\t"

		/* Step 5: Save guest RAX (in RCX) → state->guest_regs.rax */
		"movq %%rcx, %c[rax_off](%%rax)\n\t"

		/* Step 6: Save remaining 13 guest GPRs */
		"movq %%rbx,   %c[rbx_off](%%rax)\n\t"
		"movq %%rdx,   %c[rdx_off](%%rax)\n\t"
		"movq %%rsi,   %c[rsi_off](%%rax)\n\t"
		"movq %%rdi,   %c[rdi_off](%%rax)\n\t"
		"movq %%rbp,   %c[rbp_off](%%rax)\n\t"
		"movq %%r8,    %c[r8_off](%%rax)\n\t"
		"movq %%r9,    %c[r9_off](%%rax)\n\t"
		"movq %%r10,   %c[r10_off](%%rax)\n\t"
		"movq %%r11,   %c[r11_off](%%rax)\n\t"
		"movq %%r12,   %c[r12_off](%%rax)\n\t"
		"movq %%r13,   %c[r13_off](%%rax)\n\t"
		"movq %%r14,   %c[r14_off](%%rax)\n\t"
		"movq %%r15,   %c[r15_off](%%rax)\n\t"

		/*
		 * Step 7: Restore host callee-saved registers.
		 * Trampoline pushed: RBX, RBP, R12, R13, R14, R15, RDI, 0
		 * so from HOST_RSP:
		 *   [RSP+16]=R15, [RSP+24]=R14, [RSP+32]=R13,
		 *   [RSP+40]=R12, [RSP+48]=RBP, [RSP+56]=RBX
		 */
		"movq 16(%%rsp), %%r15\n\t"
		"movq 24(%%rsp), %%r14\n\t"
		"movq 32(%%rsp), %%r13\n\t"
		"movq 40(%%rsp), %%r12\n\t"
		"movq 48(%%rsp), %%rbp\n\t"
		"movq 56(%%rsp), %%rbx\n\t"

		/*
		 * Step 8: Return 0 to phantom_run_guest.
		 * 8 slots × 8 bytes = 64 bytes to skip past our frame.
		 * After addq, RSP points at the return address.
		 */
		"xorq %%rax, %%rax\n\t"
		"addq $64, %%rsp\n\t"
		ASM_RET

		: /* outputs: none (naked, ret from asm) */
		: [rax_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.rax)),
		  [rbx_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.rbx)),
		  [rcx_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.rcx)),
		  [rdx_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.rdx)),
		  [rsi_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.rsi)),
		  [rdi_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.rdi)),
		  [rbp_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.rbp)),
		  [r8_off]  "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.r8)),
		  [r9_off]  "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.r9)),
		  [r10_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.r10)),
		  [r11_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.r11)),
		  [r12_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.r12)),
		  [r13_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.r13)),
		  [r14_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.r14)),
		  [r15_off] "i"(offsetof(struct phantom_vmx_cpu_state,
				          guest_regs.r15))
		/* no clobbers in a __naked function */
	);
}
/*
 * Both the trampoline and the VM exit return function have non-standard
 * stack behaviour — they manipulate RSP directly and the VM exit return
 * is jumped to by the CPU hardware, not called normally.
 * Tell objtool not to validate these functions.
 */
STACK_FRAME_NON_STANDARD(phantom_vmlaunch_trampoline);
STACK_FRAME_NON_STANDARD(phantom_vm_exit_return);

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

	pr_info("phantom: CPU%d: entering guest loop (launched=%d)\n",
		state->cpu, (int)state->launched);

	PHANTOM_TRACE_VM_ENTRY(state->cpu);

	do {
		/*
		 * Refresh volatile host-state VMCS fields before every VM entry.
		 *
		 * HOST_GS_BASE: MSR_GS_BASE holds the kernel per-CPU base for
		 * this CPU while the thread is running.  Refresh defensively,
		 * mirroring KVM's vmx_prepare_switch_to_guest().
		 *
		 * HOST_TR_BASE: The TSS base is a per-CPU constant after boot,
		 * but we refresh it to catch any edge cases (e.g. CPU hotplug).
		 * Note: the TR base bug fix (wrong mask 0xFFFFFFFF00000000 →
		 * correct 0x00000000FFFFFFFF in phantom_get_tr_base) means the
		 * initial VMCS value was wrong (truncated to 32 bits).  This
		 * refresh corrects it on the first VM entry after fix deployment.
		 *
		 * HOST_CR3 is refreshed inside the assembly trampoline.
		 * GS_BASE and TR_BASE are refreshed here in C before IRQs are
		 * disabled, avoiding rdmsr/str sequences in the assembly.
		 */
		{
			u64 gs_base;
			u64 tr_base;

			rdmsrl(MSR_GS_BASE, gs_base);
			phantom_vmcs_write64(VMCS_HOST_GS_BASE, gs_base);

			tr_base = phantom_get_tr_base();
			phantom_vmcs_write64(VMCS_HOST_TR_BASE, tr_base);
		}

		/*
		 * Disable IRQs before VMLAUNCH/VMRESUME.  On VM exit, the CPU
		 * always clears RFLAGS.IF (interrupts remain disabled).  We
		 * must keep IRQs disabled across the entry/exit pair so that
		 * the exit handler sees a consistent state.  IRQs are
		 * re-enabled below, after the trampoline returns.
		 *
		 * Note: the vCPU thread runs with IRQs enabled in between
		 * iterations (during dispatch).  This local_irq_disable applies
		 * only to the VMLAUNCH/VMRESUME boundary itself.
		 */
		local_irq_disable();
		tramp_ret = phantom_vmlaunch_trampoline(state);

		/*
		 * VM exit occurred.  RFLAGS.IF is 0 (interrupts disabled by
		 * the CPU on every VM exit, per Intel SDM §27.5.4).
		 * Re-enable IRQs immediately so the kernel's timer, RCU, and
		 * other subsystems can continue to run.
		 *
		 * This also matches KVM's behaviour: kvm_x86_ops.run() always
		 * runs local_irq_enable() after a VM exit before doing any
		 * further processing.
		 */
		local_irq_enable();

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
		if (iterations == 1)
			pr_info("phantom: CPU%d: first exit reason=%u disp=%d\n",
				state->cpu, state->exit_reason & 0xFFFF,
				disp_ret);
		if (iterations >= MAX_EXIT_ITERATIONS) {
			pr_err("phantom: CPU%d: exceeded max exit iterations "
			       "(last reason=%u)\n",
			       state->cpu, state->exit_reason & 0xFFFF);
			return -ELOOP;
		}

	} while (disp_ret == 0);

	pr_info("phantom: CPU%d: guest loop done iter=%d reason=%u result=0x%llx\n",
		state->cpu, iterations, state->exit_reason & 0xFFFF,
		state->run_result_data);

	return (disp_ret > 0) ? 0 : disp_ret;
}
