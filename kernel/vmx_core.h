// SPDX-License-Identifier: GPL-2.0-only
/*
 * vmx_core.h — VMX bootstrap declarations for phantom.ko
 *
 * Covers: per-CPU VMX state, MSR constants, VMXON/VMXOFF prototypes,
 * VMCS allocation prototypes, and feature-detection declarations.
 */
#ifndef PHANTOM_VMX_CORE_H
#define PHANTOM_VMX_CORE_H

#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/mm_types.h>
#include <asm/msr-index.h>

/* ------------------------------------------------------------------
 * MSR constants — only defined if the running kernel headers omit them
 * (asm/msr-index.h covers most of these from 4.x onwards; keep guards
 *  so we don't clash with the kernel's own definitions).
 * ------------------------------------------------------------------ */

#ifndef MSR_IA32_VMX_BASIC
#define MSR_IA32_VMX_BASIC		0x00000480
#endif
#ifndef MSR_IA32_VMX_PINBASED_CTLS
#define MSR_IA32_VMX_PINBASED_CTLS	0x00000481
#endif
#ifndef MSR_IA32_VMX_PROCBASED_CTLS
#define MSR_IA32_VMX_PROCBASED_CTLS	0x00000482
#endif
#ifndef MSR_IA32_VMX_EXIT_CTLS
#define MSR_IA32_VMX_EXIT_CTLS		0x00000483
#endif
#ifndef MSR_IA32_VMX_ENTRY_CTLS
#define MSR_IA32_VMX_ENTRY_CTLS		0x00000484
#endif
#ifndef MSR_IA32_VMX_CR0_FIXED0
#define MSR_IA32_VMX_CR0_FIXED0		0x00000486
#endif
#ifndef MSR_IA32_VMX_CR0_FIXED1
#define MSR_IA32_VMX_CR0_FIXED1		0x00000487
#endif
#ifndef MSR_IA32_VMX_CR4_FIXED0
#define MSR_IA32_VMX_CR4_FIXED0		0x00000488
#endif
#ifndef MSR_IA32_VMX_CR4_FIXED1
#define MSR_IA32_VMX_CR4_FIXED1		0x00000489
#endif
#ifndef MSR_IA32_VMX_PROCBASED_CTLS2
#define MSR_IA32_VMX_PROCBASED_CTLS2	0x0000048b
#endif
#ifndef MSR_IA32_VMX_EPT_VPID_CAP
#define MSR_IA32_VMX_EPT_VPID_CAP	0x0000048c
#endif
#ifndef MSR_IA32_VMX_TRUE_PINBASED_CTLS
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS	0x0000048d
#endif
#ifndef MSR_IA32_VMX_TRUE_PROCBASED_CTLS
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x0000048e
#endif
#ifndef MSR_IA32_VMX_TRUE_EXIT_CTLS
#define MSR_IA32_VMX_TRUE_EXIT_CTLS	0x0000048f
#endif
#ifndef MSR_IA32_VMX_TRUE_ENTRY_CTLS
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS	0x00000490
#endif

/* ------------------------------------------------------------------
 * EPT/VPID capability bits (MSR_IA32_VMX_EPT_VPID_CAP)
 * ------------------------------------------------------------------ */
#define VMX_EPT_VPID_CAP_4LVL		BIT_ULL(6)   /* 4-level page walk     */
#define VMX_EPT_VPID_CAP_WB		BIT_ULL(14)  /* WB memory type        */
#define VMX_EPT_VPID_CAP_2MB		BIT_ULL(16)  /* 2MB large pages       */
#define VMX_EPT_VPID_CAP_AD		BIT_ULL(21)  /* EPT A/D bits          */

/* Secondary proc-based controls: EPT enable is bit 1 */
#define VMX_SECONDARY_EXEC_ENABLE_EPT	BIT(1)

/* VMX_BASIC bits */
#define VMX_BASIC_REVISION_MASK		0x7fffffffULL
#define VMX_BASIC_TRUE_CTLS		BIT_ULL(55)  /* TRUE controls MSRs present */

/* ------------------------------------------------------------------
 * Per-CPU VMX state
 *
 * One instance per physical CPU designated for fuzzing.  Allocated
 * at module load and kept alive until module unload.
 * ------------------------------------------------------------------ */
struct phantom_vmx_cpu_state {
	struct page	*vmxon_region;	/* 4KB VMXON region, NUMA-local      */
	struct page	*vmcs_region;	/* 4KB VMCS region, NUMA-local       */
	bool		 vmx_active;	/* true after successful VMXON       */
	u64		 saved_cr4;	/* CR4 value before we set VMXE      */
	int		 cpu;		/* physical CPU index                */
	int		 init_err;	/* error code if VMXON/alloc failed  */
};

DECLARE_PER_CPU(struct phantom_vmx_cpu_state, phantom_vmx_state);

/* ------------------------------------------------------------------
 * VMXON region layout (Intel SDM Vol. 3C §24.2)
 *
 * Only the first 4 bytes are software-defined; the rest are reserved
 * for processor use.
 * ------------------------------------------------------------------ */
struct phantom_vmxon_region {
	__le32	revision_id;	/* IA32_VMX_BASIC[30:0], bit31 must be 0 */
	u8	reserved[4092];
} __packed;

/* ------------------------------------------------------------------
 * Feature detection results (populated once at module init)
 * ------------------------------------------------------------------ */
struct phantom_cpu_features {
	bool	vtx;		/* CPUID.1:ECX[5] — VT-x present             */
	bool	ept;		/* Secondary controls EPT bit                 */
	bool	ept_4lvl;	/* EPT VPID CAP: 4-level walk                 */
	bool	ept_wb;		/* EPT VPID CAP: WB memory type               */
	bool	ept_2mb;	/* EPT VPID CAP: 2MB pages                    */
	bool	ept_ad;		/* EPT VPID CAP: A/D bits                     */
	bool	intel_pt;	/* CPUID.7:EBX[25] — Intel PT                 */
	bool	xsave;		/* CPUID.1:ECX[26] — XSAVE/XRSTOR            */
	bool	true_ctls;	/* VMX_BASIC[55]: TRUE ctrl MSRs present      */
	u32	vmx_revision;	/* Revision ID for VMXON/VMCS regions         */
};

/* ------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------ */

/**
 * phantom_vmx_check_cpu_features - Detect and validate CPU VMX capabilities.
 * @feat: Output structure populated on success.
 *
 * Checks VT-x, EPT (4-level, WB, 2MB, A/D), Intel PT, and XSAVE.
 * EPT with 4-level walk and WB memory type are hard requirements.
 * Intel PT and XSAVE are advisory for Phase 1.1 (logged, not fatal).
 *
 * Returns 0 on success, -ENODEV if a hard requirement is missing.
 */
int phantom_vmx_check_cpu_features(struct phantom_cpu_features *feat);

/**
 * phantom_vmxon_all - Execute VMXON on every CPU in cpumask.
 * @cpumask: Set of physical CPUs to enter VMX-root on.
 *
 * Uses smp_call_function_single() for each CPU.  Partial failure
 * triggers rollback: VMXOFF is executed on all previously-entered
 * cores before returning error.
 *
 * Returns 0 on success, negative errno on failure.
 */
int phantom_vmxon_all(const struct cpumask *cpumask);

/**
 * phantom_vmxoff_all - Execute VMXOFF on every active VMX-root CPU.
 * @cpumask: Set of physical CPUs to exit VMX-root on.
 *
 * Safe to call on CPUs where VMXON was never attempted or failed.
 * Restores CR4.VMXE to the saved value.
 */
void phantom_vmxoff_all(const struct cpumask *cpumask);

/**
 * phantom_vmcs_alloc_all - Allocate and initialise VMCS on each CPU.
 * @cpumask: Target CPU set.
 *
 * Allocates one 4KB VMCS region per CPU (NUMA-local), sets revision ID,
 * executes VMCLEAR and VMPTRLD to make the VMCS current on each core.
 *
 * Must be called after phantom_vmxon_all() succeeds.
 * Returns 0 on success, negative errno on failure.
 */
int phantom_vmcs_alloc_all(const struct cpumask *cpumask);

/**
 * phantom_vmcs_free_all - Free VMCS regions and execute VMCLEAR.
 * @cpumask: Target CPU set.
 */
void phantom_vmcs_free_all(const struct cpumask *cpumask);

#endif /* PHANTOM_VMX_CORE_H */
