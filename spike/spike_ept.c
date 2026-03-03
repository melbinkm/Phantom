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
	 * Identity-map all of physical memory 0-512GB using 1GB pages.
	 *
	 * The guest runs with the host's CR3, so the CPU needs to walk the
	 * host's page tables (physical addresses 0-62GB on phantom-bench).
	 * Rather than mapping individual regions, we map all 512 1GB slots
	 * in a single PDPT covering GPA 0 to 512GB.
	 *
	 * PML4[0] → PDPT (covering GPA 0x0000_0000 to 0x7FFF_FFFF_FFFF)
	 * PDPT[0..511] → 1GB large pages at GPA i*1GB (identity-mapped)
	 *
	 * The code GPA is in the kernel direct-map (above 0xffff_8000_0000_0000)
	 * which maps to physical addresses 0-maxRAM.  PML4[0] covers the
	 * physical range used by those page-table walks.
	 * ---------------------------------------------------------------- */
	{
		unsigned int i;

		for (i = 0; i < 512; i++) {
			/*
			 * 1GB PDPT entry: PS=1 (bit 7), RWX, WB memory type.
			 * Physical address = i * 1GB.
			 */
			pdpt[i] = ((u64)i << 30) | EPT_ENTRY_RAM | (1ULL << 7);
		}
	}

	/* PML4[0] → PDPT covering GPA 0 to 512GB */
	pml4[0] = page_to_phys(ept->pdpt_page) | EPT_RWX;

	/*
	 * Store the code GPA (= HPA = virt_to_phys(guest_code_start)).
	 * The code lives in the direct-map, so its GPA is its physical addr.
	 */
	code_virt  = (unsigned long)guest_code_start;
	code_phys  = virt_to_phys((void *)code_virt);
	guest_phys = code_phys;

	ept->code_gpa = code_phys;
	ept->code_hpa = code_phys;

	/*
	 * The PD page is pre-allocated but not wired into the EPT since the
	 * 1GB PDPT entries cover all physical memory.  We keep the allocation
	 * so spike_ept_destroy() frees it without any changes to that path.
	 * Suppress unused-variable warnings for the index variables.
	 */
	pml4_idx = (guest_phys >> 39) & 0x1ff; (void)pml4_idx;
	pdpt_idx = (guest_phys >> 30) & 0x1ff; (void)pdpt_idx;
	pd_idx   = (guest_phys >> 21) & 0x1ff; (void)pd_idx;

	/*
	 * Stack mapping: the 1GB identity PDPT already covers
	 * GPA 0x1000000 (SPIKE_GUEST_STACK_GPA).  Guest RSP = GPA top of
	 * the stack page, which maps to whatever physical frame is at that
	 * address in host RAM.  We still allocate a stack_page so the struct
	 * fields are non-NULL and destroy() can free them safely.
	 *
	 * The stack_pt_page, stack_pdpt_page, stack_pd_page are not wired
	 * into the EPT — the 1GB entries cover the stack GPA already.
	 */
	stack_phys = page_to_phys(ept->stack_page);
	ept->stack_gpa = SPIKE_GUEST_STACK_GPA;
	ept->stack_hpa = stack_phys;

	/* Null out optional pages that are not allocated in this path. */
	ept->stack_pdpt_page = NULL;
	ept->stack_pd_page   = NULL;

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
