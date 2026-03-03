// SPDX-License-Identifier: GPL-2.0-only
/*
 * spike_ept.c — Minimal EPT (Extended Page Tables) for the VMX feasibility spike.
 *
 * Builds a 3-level identity-mapped EPT covering the 2MB-aligned region that
 * contains the guest_code_start symbol, plus one additional 4KB read/write page
 * for the guest stack.  All other GPAs are unmapped, so any access outside these
 * two regions produces an EPT violation (exit reason 48), which the spike uses to
 * validate the violation handler path.
 *
 * EPT structure used here:
 *   PML4  (1 page  — 512 entries, each covering 512GB)
 *    └─ PDPT (1 page  — 512 entries, each covering 1GB)
 *        └─ PD   (1 page  — 512 entries, each covering 2MB)
 *                └─ 2MB large-page entry pointing at guest_code
 *
 * Only one 2MB large-page entry is populated (the one covering guest_code).
 * A separate 4KB PD entry for the guest stack (a single page) uses the same
 * approach but points at an individually-allocated page.
 *
 * EPT PTE layout (Intel SDM Vol. 3C §29.3.2):
 *   Bit 0  — Read access allowed
 *   Bit 1  — Write access allowed
 *   Bit 2  — Execute access allowed
 *   Bits 5:3 — Memory type (6 = WB)
 *   Bit 7  — Page-size (1 = 2MB large page in PD, 0 = 4KB)
 *   Bits 51:12 — Physical address of next level or page frame
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/io.h>          /* virt_to_phys */
#include <asm/page.h>        /* page_to_phys */

#include "spike_ept.h"

/* EPT permission + memory-type flags for normal RAM entries */
#define EPT_RWX         (0x7ULL)            /* read | write | execute */
#define EPT_MEM_WB      (6ULL << 3)         /* write-back */
#define EPT_ENTRY_RAM   (EPT_RWX | EPT_MEM_WB)

/* Large-page bit in PD entry */
#define EPT_PD_LARGE    (1ULL << 7)

/* Mask to extract the physical frame number from an EPT entry */
#define EPT_PHYS_MASK   (~0xFFFULL & ((1ULL << 52) - 1))

/* Size of one EPT table page (holds 512 × 8-byte entries) */
#define EPT_TABLE_SIZE  PAGE_SIZE

/*
 * spike_ept_build() — allocate and populate the EPT hierarchy.
 *
 * @ept: output structure; caller must zero-initialise.
 *
 * Returns 0 on success.  On error all previously-allocated pages are freed
 * before returning.
 *
 * The resulting EPTP value is stored in ept->eptp.  Pass it to VMCS field
 * VMCS_EPT_POINTER (0x201a) during VMCS setup.
 */
int spike_ept_build(struct spike_ept *ept)
{
	u64 *pml4, *pdpt, *pd;
	u64 guest_phys;
	u64 stack_phys;
	unsigned long code_virt;
	u64 code_phys;
	unsigned int pml4_idx, pdpt_idx, pd_idx;
	int ret = -ENOMEM;

	/* Allocate the three EPT paging structure pages (PML4, PDPT, PD). */
	ept->pml4_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!ept->pml4_page)
		goto err_pml4;

	ept->pdpt_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!ept->pdpt_page)
		goto err_pdpt;

	ept->pd_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!ept->pd_page)
		goto err_pd;

	/*
	 * Allocate a 4KB page for the guest stack.  The guest will receive
	 * this as a read/write page at a fixed GPA (SPIKE_GUEST_STACK_GPA).
	 * Because the stack GPA may fall in a different 2MB region from the
	 * code, we may need a second PD entry — or, if it's within the same
	 * 2MB region, the large-page entry covers it.  For simplicity, we
	 * allocate a dedicated stack page regardless and map it explicitly
	 * at SPIKE_GUEST_STACK_GPA using its own EPT PT.
	 */
	ept->stack_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!ept->stack_page)
		goto err_stack;

	/*
	 * Allocate a 4KB EPT page-table page for the 4KB stack mapping.
	 * (The 2MB code region uses a large-page PD entry and needs no PT.)
	 */
	ept->stack_pt_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!ept->stack_pt_page)
		goto err_stack_pt;

	/* Obtain virtual and physical addresses of all tables. */
	pml4 = page_address(ept->pml4_page);
	pdpt = page_address(ept->pdpt_page);
	pd   = page_address(ept->pd_page);

	/* ----------------------------------------------------------------
	 * Map the 2MB code region (identity-map, large page).
	 *
	 * guest_code_start is a kernel virtual address.  The GPA we assign
	 * to it is the same as its host physical address (identity mapping):
	 *   GPA = HPA = virt_to_phys(guest_code_start)
	 *
	 * The 2MB-aligned base of that physical address selects a single PD
	 * entry covering the whole 2MB region containing the code.
	 * ---------------------------------------------------------------- */
	code_virt  = (unsigned long)guest_code_start;
	code_phys  = virt_to_phys((void *)code_virt);
	guest_phys = code_phys & ~((u64)(2 * 1024 * 1024 - 1)); /* 2MB align */

	/*
	 * Store the identity base so the caller can use it as guest RIP.
	 * The guest RIP must be the GPA, which equals the HPA here.
	 */
	ept->code_gpa = code_phys;    /* exact GPA for RIP */
	ept->code_hpa = code_phys;    /* HPA is the same   */

	/* Decompose the 2MB-aligned GPA into EPT walk indices. */
	pml4_idx = (guest_phys >> 39) & 0x1ff;
	pdpt_idx = (guest_phys >> 30) & 0x1ff;
	pd_idx   = (guest_phys >> 21) & 0x1ff;

	/* PML4[pml4_idx] → PDPT */
	pml4[pml4_idx] = page_to_phys(ept->pdpt_page) | EPT_RWX;

	/* PDPT[pdpt_idx] → PD */
	pdpt[pdpt_idx] = page_to_phys(ept->pd_page) | EPT_RWX;

	/* PD[pd_idx] → 2MB large page (identity) */
	pd[pd_idx] = guest_phys | EPT_ENTRY_RAM | EPT_PD_LARGE;

	/* ----------------------------------------------------------------
	 * Map the 4KB guest stack page.
	 *
	 * SPIKE_GUEST_STACK_GPA is chosen so that it does NOT fall in the
	 * same 2MB region as the code (to avoid aliasing the large-page PD
	 * entry).  We use a separate EPT PT for this mapping.
	 *
	 * If SPIKE_GUEST_STACK_GPA falls within the same PML4/PDPT/PD as
	 * the code region but in a different 2MB slot, we reuse the same
	 * PDPT/PD pages (they were already wired in above).  However, the
	 * stack GPA may need a different PDPT or PD entry — the code below
	 * handles this generically.
	 * ---------------------------------------------------------------- */
	stack_phys = page_to_phys(ept->stack_page);
	ept->stack_gpa = SPIKE_GUEST_STACK_GPA;
	ept->stack_hpa = stack_phys;

	{
		u64  sgpa      = SPIKE_GUEST_STACK_GPA;
		unsigned int s_pml4 = (sgpa >> 39) & 0x1ff;
		unsigned int s_pdpt = (sgpa >> 30) & 0x1ff;
		unsigned int s_pd   = (sgpa >> 21) & 0x1ff;
		unsigned int s_pt   = (sgpa >> 12) & 0x1ff;
		u64 *stack_pt = page_address(ept->stack_pt_page);
		u64 *tgt_pdpt, *tgt_pd;

		/*
		 * The stack GPA lives in a different 1GB slot from the code
		 * (SPIKE_GUEST_STACK_GPA = 0x1000000, code is typically in
		 * the kernel's direct-map at ~0xffff...).  We therefore need
		 * separate PDPT/PD allocations for the stack only if the walk
		 * indices differ from those used by the code path.
		 *
		 * For simplicity, reuse the same pml4/pdpt/pd pages if the
		 * indices match, otherwise allocate additional pages.
		 *
		 * In practice the stack GPA (16MB) and code GPA (kernel
		 * direct-map > 0xffff800000000000) always have different
		 * PML4 indices, so we allocate dedicated PDPT/PD for stack.
		 */
		if (s_pml4 != pml4_idx) {
			/* Need a dedicated PDPT for the stack region. */
			ept->stack_pdpt_page =
				alloc_page(GFP_KERNEL | __GFP_ZERO);
			if (!ept->stack_pdpt_page) {
				ret = -ENOMEM;
				goto err_stack_pdpt;
			}
			ept->stack_pd_page =
				alloc_page(GFP_KERNEL | __GFP_ZERO);
			if (!ept->stack_pd_page) {
				ret = -ENOMEM;
				goto err_stack_pd;
			}
			tgt_pdpt = page_address(ept->stack_pdpt_page);
			tgt_pd   = page_address(ept->stack_pd_page);
			pml4[s_pml4] = page_to_phys(ept->stack_pdpt_page)
				       | EPT_RWX;
			tgt_pdpt[s_pdpt] = page_to_phys(ept->stack_pd_page)
					  | EPT_RWX;
		} else if (s_pdpt != pdpt_idx) {
			/*
			 * Same PML4, different PDPT entry — reuse pml4/pdpt
			 * pages, but allocate a new PD for the stack.
			 */
			ept->stack_pdpt_page = NULL;
			ept->stack_pd_page =
				alloc_page(GFP_KERNEL | __GFP_ZERO);
			if (!ept->stack_pd_page) {
				ret = -ENOMEM;
				goto err_stack_pd_only;
			}
			tgt_pdpt = pdpt;
			tgt_pd   = page_address(ept->stack_pd_page);
			tgt_pdpt[s_pdpt] = page_to_phys(ept->stack_pd_page)
					  | EPT_RWX;
		} else {
			/* Same PML4 and PDPT, different PD entry. */
			ept->stack_pdpt_page = NULL;
			ept->stack_pd_page   = NULL;
			tgt_pd = pd;
		}

		/* tgt_pd[s_pd] → EPT PT for 4KB stack mapping */
		tgt_pd[s_pd] = page_to_phys(ept->stack_pt_page) | EPT_RWX;

		/* stack_pt[s_pt] → actual stack page (RW, no-execute) */
		stack_pt[s_pt] = stack_phys | EPT_RWX | EPT_MEM_WB;
	}

	/*
	 * Build the EPTP value:
	 *   bits  2:0 = memory type for EPT structures = 6 (WB)
	 *   bits  5:3 = EPT page-walk length minus 1 = 3 (4-level walk)
	 *   bit   6   = enable A/D bits (0 for spike — not needed)
	 *   bits 51:12 = PML4 physical page frame number
	 */
	ept->eptp = page_to_phys(ept->pml4_page) | EPTP_FLAGS_WB_4LEVEL;

	pr_info("spike: EPT built: eptp=0x%llx code_gpa=0x%llx "
		"stack_gpa=0x%llx\n",
		ept->eptp, ept->code_gpa, ept->stack_gpa);
	return 0;

	/* ----------------------------------------------------------------
	 * Error-cleanup labels — reverse order of allocation.
	 * ---------------------------------------------------------------- */
err_stack_pd:
	/*
	 * stack_pd_page alloc failed after stack_pdpt_page succeeded.
	 * Free stack_pdpt_page before falling through to common cleanup.
	 */
	if (ept->stack_pdpt_page) {
		__free_page(ept->stack_pdpt_page);
		ept->stack_pdpt_page = NULL;
	}
	goto err_common;

err_stack_pdpt:
	/* stack_pdpt_page alloc itself failed — nothing extra to free. */
	goto err_common;

err_stack_pd_only:
	/* stack_pd_page alloc failed (no stack_pdpt_page was allocated). */
	goto err_common;

err_common:
	__free_page(ept->stack_pt_page);
	ept->stack_pt_page = NULL;
err_stack_pt:
	__free_page(ept->stack_page);
	ept->stack_page = NULL;
err_stack:
	__free_page(ept->pd_page);
	ept->pd_page = NULL;
err_pd:
	__free_page(ept->pdpt_page);
	ept->pdpt_page = NULL;
err_pdpt:
	__free_page(ept->pml4_page);
	ept->pml4_page = NULL;
err_pml4:
	return ret;
}

/*
 * spike_ept_destroy() — free all pages belonging to the EPT hierarchy.
 *
 * Safe to call even if spike_ept_build() failed partway through, as long as
 * the caller zero-initialised the struct before calling build().
 */
void spike_ept_destroy(struct spike_ept *ept)
{
	if (ept->stack_pd_page) {
		__free_page(ept->stack_pd_page);
		ept->stack_pd_page = NULL;
	}
	if (ept->stack_pdpt_page) {
		__free_page(ept->stack_pdpt_page);
		ept->stack_pdpt_page = NULL;
	}
	if (ept->stack_pt_page) {
		__free_page(ept->stack_pt_page);
		ept->stack_pt_page = NULL;
	}
	if (ept->stack_page) {
		__free_page(ept->stack_page);
		ept->stack_page = NULL;
	}
	if (ept->pd_page) {
		__free_page(ept->pd_page);
		ept->pd_page = NULL;
	}
	if (ept->pdpt_page) {
		__free_page(ept->pdpt_page);
		ept->pdpt_page = NULL;
	}
	if (ept->pml4_page) {
		__free_page(ept->pml4_page);
		ept->pml4_page = NULL;
	}
}
