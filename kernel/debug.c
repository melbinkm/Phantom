// SPDX-License-Identifier: GPL-2.0-only
/*
 * debug.c — VMCS dump, VMCS field validator, and debug subsystem
 *
 * All hot-path events use trace_printk() (guarded by PHANTOM_DEBUG).
 * The VMCS dump and validator are slow-path tools called only on
 * unexpected VM exits or at VMLAUNCH time in debug builds.
 *
 * The dump uses trace_printk to avoid lock contention on the printk
 * ring buffer.  Structured output format is machine-parseable by
 * tools/vmcs-dump/.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <asm/msr.h>
#include <asm/io.h>

#include "phantom.h"
#include "vmx_core.h"
#include "ept.h"
#include "debug.h"

/* ------------------------------------------------------------------
 * Full VMCS dump
 *
 * Reads all significant VMCS fields and emits them via trace_printk.
 * Called on any unexpected VM exit.  Must only be called from VMX-root
 * context with a current VMCS loaded (after VMPTRLD).
 * ------------------------------------------------------------------ */

/**
 * phantom_dump_vmcs - Dump current VMCS fields to the trace ring buffer.
 * @inst_id:     Instance identifier (for log correlation).
 * @cpu:         Physical CPU index.
 * @exit_reason: VM-exit reason (raw VMCS field value).
 * @iteration:   Fuzzing iteration counter at time of exit.
 *
 * Uses trace_printk — never printk.  Safe from interrupt context.
 */
void phantom_dump_vmcs(int inst_id, int cpu, u32 exit_reason, u64 iteration)
{
	u64 guest_rip, guest_rsp, guest_rflags;
	u64 guest_cr0, guest_cr3, guest_cr4;
	u64 exit_qual, guest_phys;
	u32 vm_instr_err;
	u32 intr_info;
	u64 eptp;

	trace_printk("PHANTOM VMCS DUMP [inst=%d cpu=%d exit_reason=0x%x "
		     "iter=%llu]\n",
		     inst_id, cpu, exit_reason, iteration);

	/* Guest execution state */
	guest_rip    = phantom_vmcs_read64(VMCS_GUEST_RIP);
	guest_rsp    = phantom_vmcs_read64(VMCS_GUEST_RSP);
	guest_rflags = phantom_vmcs_read64(VMCS_GUEST_RFLAGS);
	guest_cr0    = phantom_vmcs_read64(VMCS_GUEST_CR0);
	guest_cr3    = phantom_vmcs_read64(VMCS_GUEST_CR3);
	guest_cr4    = phantom_vmcs_read64(VMCS_GUEST_CR4);

	trace_printk("  GUEST_RIP=0x%llx RSP=0x%llx RFLAGS=0x%llx\n",
		     guest_rip, guest_rsp, guest_rflags);
	trace_printk("  GUEST_CR0=0x%llx CR3=0x%llx CR4=0x%llx\n",
		     guest_cr0, guest_cr3, guest_cr4);

	/* Exit information */
	exit_qual    = phantom_vmcs_read64(VMCS_RO_EXIT_QUAL);
	vm_instr_err = phantom_vmcs_read32(VMCS_RO_VM_INSTR_ERROR);
	intr_info    = phantom_vmcs_read32(VMCS_RO_EXIT_INTR_INFO);

	trace_printk("  EXIT_QUAL=0x%llx VM_INSTR_ERROR=%u INTR_INFO=0x%x\n",
		     exit_qual, vm_instr_err, intr_info);

	/* Guest physical address (valid for EPT violations) */
	guest_phys = phantom_vmcs_read64(VMCS_RO_GUEST_PHYS_ADDR);
	trace_printk("  GUEST_PHYS_ADDR=0x%llx\n", guest_phys);

	/* EPT pointer */
	eptp = phantom_vmcs_read64(VMCS_CTRL_EPT_POINTER);
	trace_printk("  EPT_POINTER=0x%llx\n", eptp);

	/* CS */
	{
		u16 sel;
		u64 base;
		u32 limit, ar;

		sel   = phantom_vmcs_read16(VMCS_GUEST_CS_SELECTOR);
		base  = phantom_vmcs_read64(VMCS_GUEST_CS_BASE);
		limit = phantom_vmcs_read32(VMCS_GUEST_CS_LIMIT);
		ar    = phantom_vmcs_read32(VMCS_GUEST_CS_AR);
		trace_printk("  GUEST_CS: sel=0x%x base=0x%llx "
			     "limit=0x%x ar=0x%x\n",
			     sel, base, limit, ar);
	}

	/* SS */
	{
		u16 sel;
		u64 base;
		u32 limit, ar;

		sel   = phantom_vmcs_read16(VMCS_GUEST_SS_SELECTOR);
		base  = phantom_vmcs_read64(VMCS_GUEST_SS_BASE);
		limit = phantom_vmcs_read32(VMCS_GUEST_SS_LIMIT);
		ar    = phantom_vmcs_read32(VMCS_GUEST_SS_AR);
		trace_printk("  GUEST_SS: sel=0x%x base=0x%llx "
			     "limit=0x%x ar=0x%x\n",
			     sel, base, limit, ar);
	}

	/* DS */
	{
		u16 sel;
		u64 base;
		u32 limit, ar;

		sel   = phantom_vmcs_read16(VMCS_GUEST_DS_SELECTOR);
		base  = phantom_vmcs_read64(VMCS_GUEST_DS_BASE);
		limit = phantom_vmcs_read32(VMCS_GUEST_DS_LIMIT);
		ar    = phantom_vmcs_read32(VMCS_GUEST_DS_AR);
		trace_printk("  GUEST_DS: sel=0x%x base=0x%llx "
			     "limit=0x%x ar=0x%x\n",
			     sel, base, limit, ar);
	}

	/* ES */
	{
		u16 sel;
		u64 base;
		u32 limit, ar;

		sel   = phantom_vmcs_read16(VMCS_GUEST_ES_SELECTOR);
		base  = phantom_vmcs_read64(VMCS_GUEST_ES_BASE);
		limit = phantom_vmcs_read32(VMCS_GUEST_ES_LIMIT);
		ar    = phantom_vmcs_read32(VMCS_GUEST_ES_AR);
		trace_printk("  GUEST_ES: sel=0x%x base=0x%llx "
			     "limit=0x%x ar=0x%x\n",
			     sel, base, limit, ar);
	}

	/* FS */
	{
		u16 sel;
		u64 base;
		u32 limit, ar;

		sel   = phantom_vmcs_read16(VMCS_GUEST_FS_SELECTOR);
		base  = phantom_vmcs_read64(VMCS_GUEST_FS_BASE);
		limit = phantom_vmcs_read32(VMCS_GUEST_FS_LIMIT);
		ar    = phantom_vmcs_read32(VMCS_GUEST_FS_AR);
		trace_printk("  GUEST_FS: sel=0x%x base=0x%llx "
			     "limit=0x%x ar=0x%x\n",
			     sel, base, limit, ar);
	}

	/* GS */
	{
		u16 sel;
		u64 base;
		u32 limit, ar;

		sel   = phantom_vmcs_read16(VMCS_GUEST_GS_SELECTOR);
		base  = phantom_vmcs_read64(VMCS_GUEST_GS_BASE);
		limit = phantom_vmcs_read32(VMCS_GUEST_GS_LIMIT);
		ar    = phantom_vmcs_read32(VMCS_GUEST_GS_AR);
		trace_printk("  GUEST_GS: sel=0x%x base=0x%llx "
			     "limit=0x%x ar=0x%x\n",
			     sel, base, limit, ar);
	}

	/* TR */
	{
		u16 sel;
		u64 base;
		u32 limit, ar;

		sel   = phantom_vmcs_read16(VMCS_GUEST_TR_SELECTOR);
		base  = phantom_vmcs_read64(VMCS_GUEST_TR_BASE);
		limit = phantom_vmcs_read32(VMCS_GUEST_TR_LIMIT);
		ar    = phantom_vmcs_read32(VMCS_GUEST_TR_AR);
		trace_printk("  GUEST_TR: sel=0x%x base=0x%llx "
			     "limit=0x%x ar=0x%x\n",
			     sel, base, limit, ar);
	}

	/* LDTR */
	{
		u16 sel;
		u64 base;
		u32 limit, ar;

		sel   = phantom_vmcs_read16(VMCS_GUEST_LDTR_SELECTOR);
		base  = phantom_vmcs_read64(VMCS_GUEST_LDTR_BASE);
		limit = phantom_vmcs_read32(VMCS_GUEST_LDTR_LIMIT);
		ar    = phantom_vmcs_read32(VMCS_GUEST_LDTR_AR);
		trace_printk("  GUEST_LDTR: sel=0x%x base=0x%llx "
			     "limit=0x%x ar=0x%x\n",
			     sel, base, limit, ar);
	}

	/* GDTR / IDTR */
	{
		u64 gdtr_base = phantom_vmcs_read64(VMCS_GUEST_GDTR_BASE);
		u32 gdtr_lim  = phantom_vmcs_read32(VMCS_GUEST_GDTR_LIMIT);
		u64 idtr_base = phantom_vmcs_read64(VMCS_GUEST_IDTR_BASE);
		u32 idtr_lim  = phantom_vmcs_read32(VMCS_GUEST_IDTR_LIMIT);

		trace_printk("  GUEST_GDTR: base=0x%llx limit=0x%x\n",
			     gdtr_base, gdtr_lim);
		trace_printk("  GUEST_IDTR: base=0x%llx limit=0x%x\n",
			     idtr_base, idtr_lim);
	}

	/* EFER and interrupt state */
	{
		u64 efer  = phantom_vmcs_read64(VMCS_GUEST_IA32_EFER);
		u32 intr  = phantom_vmcs_read32(VMCS_GUEST_INTR_STATE);
		u32 activ = phantom_vmcs_read32(VMCS_GUEST_ACTIVITY_STATE);

		trace_printk("  GUEST_EFER=0x%llx INTR_STATE=0x%x "
			     "ACTIVITY=0x%x\n",
			     efer, intr, activ);
	}

	trace_printk("PHANTOM VMCS DUMP END\n");
}

/* ------------------------------------------------------------------
 * VMCS field validator (compiled only in PHANTOM_DEBUG builds)
 *
 * Validates guest-state VMCS fields against Intel SDM §26.3 before
 * every VMLAUNCH/VMRESUME.  Catches most invalid-state panics during
 * development.
 * ------------------------------------------------------------------ */

#ifdef PHANTOM_DEBUG

/**
 * phantom_validate_vmcs - Validate VMCS guest state before VM entry.
 *
 * Checks:
 *   1. CR0 fixed bits (Intel SDM §26.3.1.1)
 *   2. CR4 fixed bits
 *   3. CS access rights: not unusable, L=1 for 64-bit mode
 *   4. IA-32e mode consistency: PG/PAE/LME/LMA all set
 *   5. VMCS link pointer == 0xFFFFFFFFFFFFFFFF
 *   6. Activity state == 0 (active)
 *
 * Returns 0 if all checks pass, -EINVAL on any violation (with
 * pr_err describing the failure so the developer can fix it).
 *
 * Called only in PHANTOM_DEBUG builds — compiled out in production.
 */
int phantom_validate_vmcs(void)
{
	u64 cr0_fixed0, cr0_fixed1;
	u64 cr4_fixed0, cr4_fixed1;
	u64 cr0, cr4;
	u32 ar_cs;
	u64 vmcs_link;
	u32 activity;
	u64 efer;

	rdmsrl(MSR_IA32_VMX_CR0_FIXED0, cr0_fixed0);
	rdmsrl(MSR_IA32_VMX_CR0_FIXED1, cr4_fixed1);  /* reuse var */
	rdmsrl(MSR_IA32_VMX_CR4_FIXED0, cr4_fixed0);
	rdmsrl(MSR_IA32_VMX_CR4_FIXED1, cr4_fixed1);

	/* Re-read CR0/CR4 fixed1 properly */
	rdmsrl(MSR_IA32_VMX_CR0_FIXED1, cr0_fixed1);

	cr0  = phantom_vmcs_read64(VMCS_GUEST_CR0);
	cr4  = phantom_vmcs_read64(VMCS_GUEST_CR4);

	/* Check 1: CR0 fixed bits */
	if ((cr0 & cr0_fixed0) != cr0_fixed0) {
		pr_err("phantom: VMCS validator: CR0=0x%llx missing "
		       "required bits from fixed0=0x%llx\n",
		       cr0, cr0_fixed0);
		return -EINVAL;
	}
	if (cr0 & ~cr0_fixed1) {
		pr_err("phantom: VMCS validator: CR0=0x%llx has bits "
		       "not allowed by fixed1=0x%llx\n",
		       cr0, cr0_fixed1);
		return -EINVAL;
	}

	/* Check 2: CR4 fixed bits */
	if ((cr4 & cr4_fixed0) != cr4_fixed0) {
		pr_err("phantom: VMCS validator: CR4=0x%llx missing "
		       "required bits from fixed0=0x%llx\n",
		       cr4, cr4_fixed0);
		return -EINVAL;
	}
	if (cr4 & ~cr4_fixed1) {
		pr_err("phantom: VMCS validator: CR4=0x%llx has bits "
		       "not allowed by fixed1=0x%llx\n",
		       cr4, cr4_fixed1);
		return -EINVAL;
	}

	/* Check 3: CS access rights */
	ar_cs = phantom_vmcs_read32(VMCS_GUEST_CS_AR);
	if (ar_cs & VMX_SEGMENT_AR_UNUSABLE) {
		pr_err("phantom: VMCS validator: CS marked unusable "
		       "(ar=0x%x)\n", ar_cs);
		return -EINVAL;
	}
	/* L bit = bit 13 in the access-rights byte */
	if (!(ar_cs & BIT(13))) {
		pr_err("phantom: VMCS validator: CS not 64-bit (L=0) "
		       "ar=0x%x\n", ar_cs);
		return -EINVAL;
	}

	/* Check 4: IA-32e mode consistency */
	efer = phantom_vmcs_read64(VMCS_GUEST_IA32_EFER);
	if (!(cr0 & X86_CR0_PG)) {
		pr_err("phantom: VMCS validator: CR0.PG=0 but IA-32e "
		       "mode required\n");
		return -EINVAL;
	}
	if (!(cr4 & X86_CR4_PAE)) {
		pr_err("phantom: VMCS validator: CR4.PAE=0 but IA-32e "
		       "mode required\n");
		return -EINVAL;
	}
	if (!(efer & EFER_LME)) {
		pr_err("phantom: VMCS validator: EFER.LME=0 but IA-32e "
		       "mode required\n");
		return -EINVAL;
	}
	if (!(efer & EFER_LMA)) {
		pr_err("phantom: VMCS validator: EFER.LMA=0 but IA-32e "
		       "mode required\n");
		return -EINVAL;
	}

	/* Check 5: VMCS link pointer */
	vmcs_link = phantom_vmcs_read64(VMCS_CTRL_VMCS_LINK_PTR);
	if (vmcs_link != 0xFFFFFFFFFFFFFFFFULL) {
		pr_err("phantom: VMCS validator: link pointer=0x%llx "
		       "(must be 0xffffffffffffffff)\n", vmcs_link);
		return -EINVAL;
	}

	/* Check 6: Activity state == 0 (active) */
	activity = phantom_vmcs_read32(VMCS_GUEST_ACTIVITY_STATE);
	if (activity != 0) {
		pr_err("phantom: VMCS validator: activity state=%u "
		       "(must be 0 for active)\n", activity);
		return -EINVAL;
	}

	trace_printk("phantom: VMCS validator: all checks passed\n");
	return 0;
}

#endif /* PHANTOM_DEBUG */

/* ------------------------------------------------------------------
 * Debug subsystem init/exit
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------
 * EPT walker / dumper
 *
 * Traverses the full 4-level EPT and emits each mapped region via
 * trace_printk.  Slow-path only — must not be called from a VM-exit
 * handler or any hot-path context.
 * ------------------------------------------------------------------ */

/*
 * Memory type names for EPT leaf PTEs.
 */
static const char *ept_memtype_name(u64 pte)
{
	switch ((pte >> 3) & 7) {
	case 0: return "UC";
	case 1: return "WC";
	case 4: return "WT";
	case 5: return "WP";
	case 6: return "WB";
	default: return "??";
	}
}

/*
 * Permission string from leaf PTE bits [2:0].
 */
static void ept_perm_str(u64 pte, char out[4])
{
	out[0] = (pte & EPT_PTE_READ)  ? 'R' : '-';
	out[1] = (pte & EPT_PTE_WRITE) ? 'W' : '-';
	out[2] = (pte & EPT_PTE_EXEC)  ? 'X' : '-';
	out[3] = '\0';
}

/**
 * phantom_walk_ept - Walk the 4-level EPT and emit mappings via trace_printk.
 * @ept: EPT state to walk.
 *
 * Traverses PML4 → PDPT → PD → PT and for each present leaf PTE emits
 * a trace_printk line:
 *   "EPT_MAP GPA=0x%012llx HPA=0x%012llx perm=%s memtype=%s"
 *
 * Absent (all-zero) PTEs are counted and printed in summary.
 * Large-page PD entries (PS=1) are noted but not expanded.
 */
void phantom_walk_ept(struct phantom_ept_state *ept)
{
	u64 *pml4, *pdpt, *pd, *pt;
	u64 pml4e, pdpte, pde, pte_val;
	unsigned int i, j, k, l;
	unsigned long mapped_count = 0;
	unsigned long absent_count = 0;

	if (!ept || !ept->pml4) {
		trace_printk("phantom: EPT walker: ept state not allocated\n");
		return;
	}

	trace_printk("PHANTOM EPT WALK START eptp=0x%llx\n", ept->eptp);

	pml4 = (u64 *)page_address(ept->pml4);

	for (i = 0; i < 512; i++) {
		pml4e = pml4[i];
		if (!(pml4e & EPT_PTE_READ))
			continue;

		pdpt = (u64 *)phys_to_virt(pml4e & EPT_PTE_HPA_MASK);

		for (j = 0; j < 512; j++) {
			pdpte = pdpt[j];
			if (!(pdpte & EPT_PTE_READ))
				continue;

			/* 1GB large page (PS=1 in PDPT entry) */
			if (pdpte & EPT_PTE_PS) {
				u64 gpa = ((u64)i << 39) | ((u64)j << 30);
				u64 hpa = pdpte & EPT_PTE_HPA_MASK;
				char perm[4];

				ept_perm_str(pdpte, perm);
				trace_printk("EPT_MAP GPA=0x%012llx "
					     "HPA=0x%012llx perm=%s "
					     "memtype=%s size=1GB\n",
					     gpa, hpa, perm,
					     ept_memtype_name(pdpte));
				mapped_count++;
				continue;
			}

			pd = (u64 *)phys_to_virt(pdpte & EPT_PTE_HPA_MASK);

			for (k = 0; k < 512; k++) {
				pde = pd[k];
				if (!(pde & EPT_PTE_READ)) {
					absent_count++;
					continue;
				}

				/* 2MB large page (PS=1 in PD entry) */
				if (pde & EPT_PTE_PS) {
					u64 gpa = ((u64)i << 39) |
						  ((u64)j << 30) |
						  ((u64)k << 21);
					u64 hpa = pde & EPT_PTE_HPA_MASK;
					char perm[4];

					ept_perm_str(pde, perm);
					trace_printk("EPT_MAP GPA=0x%012llx "
						     "HPA=0x%012llx perm=%s "
						     "memtype=%s size=2MB\n",
						     gpa, hpa, perm,
						     ept_memtype_name(pde));
					mapped_count++;
					continue;
				}

				pt = (u64 *)phys_to_virt(pde &
							 EPT_PTE_HPA_MASK);

				for (l = 0; l < 512; l++) {
					pte_val = pt[l];
					if (!(pte_val & EPT_PTE_READ)) {
						absent_count++;
						continue;
					}

					{
						u64 gpa = ((u64)i << 39) |
							  ((u64)j << 30) |
							  ((u64)k << 21) |
							  ((u64)l << 12);
						u64 hpa = pte_val &
							  EPT_PTE_HPA_MASK;
						char perm[4];
						const struct phantom_gpa_region
							*rgn;
						const char *rtype;

						ept_perm_str(pte_val, perm);
						rgn = phantom_ept_classify_gpa(
							gpa);
						switch (rgn->type) {
						case PHANTOM_GPA_RAM:
							rtype = "RAM";
							break;
						case PHANTOM_GPA_MMIO:
							rtype = "MMIO";
							break;
						default:
							rtype = "RSV";
							break;
						}

						trace_printk(
						    "EPT_MAP GPA=0x%012llx "
						    "HPA=0x%012llx perm=%s "
						    "memtype=%s type=%s\n",
						    gpa, hpa, perm,
						    ept_memtype_name(pte_val),
						    rtype);
						mapped_count++;
					}
				}
			}
		}
	}

	trace_printk("PHANTOM EPT WALK END mapped=%lu absent=%lu\n",
		     mapped_count, absent_count);
}

/**
 * phantom_debug_dump_ept - Dump EPT for a given VMX CPU state.
 * @state: Per-CPU VMX state (must have pages_allocated set).
 *
 * Returns 0 on success, -EINVAL if pages not allocated.
 */
int phantom_debug_dump_ept(struct phantom_vmx_cpu_state *state)
{
	if (!state || !state->pages_allocated) {
		pr_err("phantom: dump_ept: pages not allocated\n");
		return -EINVAL;
	}

	phantom_walk_ept(&state->ept);
	return 0;
}

/* ------------------------------------------------------------------
 * Debug subsystem init/exit
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
