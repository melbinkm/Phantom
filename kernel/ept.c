// SPDX-License-Identifier: GPL-2.0-only
/*
 * ept.c — EPT 4-level page table construction and GPA classification
 *
 * Implements:
 *   - Static GPA region table with RAM / MMIO / reserved classification
 *   - phantom_ept_alloc: NUMA-local page allocation with goto-cleanup
 *   - phantom_ept_build: populate all 4 EPT levels, return EPTP
 *   - phantom_ept_teardown: free all pages
 *   - phantom_ept_lookup_pte: 4-level walk returning leaf PTE pointer
 *   - phantom_ept_get_ram_page: index into backing pages array
 *   - phantom_ept_get_pd_entry: walk to PD level, return PD entry ptr
 *   - phantom_invept_single_context: single-context INVEPT helper
 *
 * EPT layout for task 1.5 (mixed 2MB + 4KB):
 *   First 8MB  (GPA 0x000000–0x7FFFFF): 4 × 2MB large pages (PS=1)
 *   Second 8MB (GPA 0x800000–0xFFFFFF): 4KB pages (4 PT pages × 512)
 *   All other GPA ranges: absent (not-present, all-zero PTE)
 *
 * Critical correctness rules:
 *   - Non-leaf entries MUST have RWX bits set (else EPT misconfig #49)
 *   - 2MB leaf: EPT_PTE_READ | EPT_PTE_EXEC | EPT_PTE_MEMTYPE_WB |
 *     EPT_PTE_PS | 2MB-aligned HPA  (WRITE cleared for CoW snapshot)
 *   - 4KB leaf RAM entries: EPT_PTE_READ | EPT_PTE_EXEC |
 *     EPT_PTE_MEMTYPE_WB | HPA  (WRITE cleared for CoW snapshot)
 *   - Absent entries: all-zero (no bits set)
 *   - EPTP: PML4_phys | EPTP_MEMTYPE_WB | EPTP_PAGEWALK_4 (no A/D)
 *
 * INVEPT rules:
 *   - 2MB→4KB split: INVEPT required (stale 2MB translations)
 *   - 4KB RO→RW CoW fault: NO INVEPT (EPT violation invalidated GPA)
 *   - Snapshot restore: one batched INVEPT after all PTE resets
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/cpu.h>
#include <linux/numa.h>
#include <linux/topology.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <asm/special_insns.h>
#include <asm/processor-flags.h>

#include "ept.h"
#include "debug.h"

/* ------------------------------------------------------------------
 * GPA region classification table
 *
 * Covers all interesting GPA ranges in order.  Any GPA not matching
 * a RAM or MMIO entry falls through to the final "all others" entry
 * which is RESERVED / absent.
 *
 * Ordering: sorted by gpa_start for clarity (not used for binary search
 * because the table is tiny — linear scan is fine for slow-path use).
 * ------------------------------------------------------------------ */

static const struct phantom_gpa_region phantom_gpa_regions[] = {
	/* 0x00000000–0x00FFFFFF: 16MB guest RAM */
	{
		.gpa_start = 0x00000000ULL,
		.gpa_end   = 0x01000000ULL,
		.type      = PHANTOM_GPA_RAM,
		.ept_flags = EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_EXEC |
			     EPT_PTE_MEMTYPE_WB,
	},
	/* 0x01000000–0xFEB_FFFFF: reserved (absent) */
	{
		.gpa_start = 0x01000000ULL,
		.gpa_end   = 0xFEB00000ULL,
		.type      = PHANTOM_GPA_RESERVED,
		.ept_flags = 0,
	},
	/* 0xFEC00000–0xFEC00FFF: IOAPIC MMIO */
	{
		.gpa_start = 0xFEC00000ULL,
		.gpa_end   = 0xFEC01000ULL,
		.type      = PHANTOM_GPA_MMIO,
		.ept_flags = 0,
	},
	/* 0xFEC01000–0xFED0_03FF: reserved */
	{
		.gpa_start = 0xFEC01000ULL,
		.gpa_end   = 0xFED00000ULL,
		.type      = PHANTOM_GPA_RESERVED,
		.ept_flags = 0,
	},
	/* 0xFED00000–0xFED00400: HPET MMIO */
	{
		.gpa_start = 0xFED00000ULL,
		.gpa_end   = 0xFED00400ULL,
		.type      = PHANTOM_GPA_MMIO,
		.ept_flags = 0,
	},
	/* 0xFED00400–0xFEE00000: reserved */
	{
		.gpa_start = 0xFED00400ULL,
		.gpa_end   = 0xFEE00000ULL,
		.type      = PHANTOM_GPA_RESERVED,
		.ept_flags = 0,
	},
	/* 0xFEE00000–0xFEE01000: LAPIC MMIO */
	{
		.gpa_start = 0xFEE00000ULL,
		.gpa_end   = 0xFEE01000ULL,
		.type      = PHANTOM_GPA_MMIO,
		.ept_flags = 0,
	},
	/* 0xFEE01000–0xFFFFFFFFFFFFFFFF: reserved */
	{
		.gpa_start = 0xFEE01000ULL,
		.gpa_end   = 0xFFFFFFFFFFFFFFFFULL,
		.type      = PHANTOM_GPA_RESERVED,
		.ept_flags = 0,
	},
};

/* Sentinel entry: matches any GPA not covered above */
static const struct phantom_gpa_region phantom_gpa_reserved_sentinel = {
	.gpa_start = 0,
	.gpa_end   = 0xFFFFFFFFFFFFFFFFULL,
	.type      = PHANTOM_GPA_RESERVED,
	.ept_flags = 0,
};

/**
 * phantom_ept_classify_gpa - Classify a GPA into RAM / MMIO / reserved.
 * @gpa: Guest physical address to classify.
 *
 * Linear scan of the static region table.  For the small table used in
 * task 1.3 this is fine; replace with an interval tree for larger maps.
 *
 * Returns a pointer to the matching region descriptor. Never NULL.
 */
const struct phantom_gpa_region *phantom_ept_classify_gpa(u64 gpa)
{
	int i;
	int nr = ARRAY_SIZE(phantom_gpa_regions);

	for (i = 0; i < nr; i++) {
		if (gpa >= phantom_gpa_regions[i].gpa_start &&
		    gpa <  phantom_gpa_regions[i].gpa_end)
			return &phantom_gpa_regions[i];
	}

	return &phantom_gpa_reserved_sentinel;
}
EXPORT_SYMBOL_GPL(phantom_ept_classify_gpa);

/* ------------------------------------------------------------------
 * GPA-to-page-index helper
 *
 * Maps a RAM GPA to its index in ept->ram_pages[].
 * Caller is responsible for ensuring gpa is within RAM range.
 * ------------------------------------------------------------------ */
static inline unsigned int gpa_to_ram_idx(u64 gpa)
{
	return (unsigned int)((gpa - PHANTOM_EPT_RAM_BASE) >> PAGE_SHIFT);
}

/* ------------------------------------------------------------------
 * phantom_ept_alloc - NUMA-local allocation of all EPT + RAM pages
 * ------------------------------------------------------------------ */

/**
 * phantom_ept_alloc - Allocate all EPT pages for one vCPU instance.
 * @ept: EPT state to populate (must be zeroed by caller).
 * @cpu: Physical CPU index (for NUMA-local allocation).
 *
 * Allocates in order:
 *   1. EPT PML4 (1 page, zeroed)
 *   2. EPT PDPT (1 page, zeroed)
 *   3. EPT PD   (1 page, zeroed)
 *   4. EPT PT pages (PHANTOM_EPT_NR_PT_PAGES pages, zeroed)
 *      — only for the 4KB region (second 8MB, PD entries 4–7)
 *      — the 2MB region (PD entries 0–3) uses large-page entries, no PT
 *   5. RAM backing pages (PHANTOM_EPT_RAM_PAGES pages, zeroed)
 *
 * Returns 0 on success, negative errno on failure.
 * goto-cleanup ensures no leaks on partial failure.
 */
int phantom_ept_alloc(struct phantom_ept_state *ept, int cpu)
{
	int node = cpu_to_node(cpu);
	int i, ret;

	if (ept->ready)
		return 0;

	/* 1. PML4 */
	ept->pml4 = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
	if (!ept->pml4) { ret = -ENOMEM; goto err_pml4; }

	/* 2. PDPT */
	ept->pdpt = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
	if (!ept->pdpt) { ret = -ENOMEM; goto err_pdpt; }

	/* 3. PD */
	ept->pd = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
	if (!ept->pd) { ret = -ENOMEM; goto err_pd; }

	/*
	 * 4. PT pages — only for the 4KB region (second 8MB).
	 *
	 * PHANTOM_EPT_NR_PT_PAGES = 4, corresponding to PD entries 4–7.
	 * The first 8MB (PD entries 0–3) uses 2MB large-page PD entries
	 * with PS=1 and no PT page needed.
	 */
	for (i = 0; i < PHANTOM_EPT_NR_PT_PAGES; i++) {
		ept->pt[i] = alloc_pages_node(node,
					      GFP_KERNEL | __GFP_ZERO, 0);
		if (!ept->pt[i]) {
			ret = -ENOMEM;
			goto err_pt;
		}
	}

	/*
	 * 5. Allocate the ram_pages pointer array on the heap.
	 *
	 * Embedding 4096 struct page* pointers directly in the struct would
	 * make it ~33KB, exceeding the percpu data limit.  Use kvmalloc_array
	 * so the array lives on the heap, not in per-CPU static storage.
	 */
	ept->ram_pages = kvmalloc_array(PHANTOM_EPT_RAM_PAGES,
					sizeof(struct page *),
					GFP_KERNEL | __GFP_ZERO);
	if (!ept->ram_pages) {
		ret = -ENOMEM;
		goto err_ram_array;
	}

	/*
	 * 6a. Allocate the 2MB region backing pages as order-9 physically
	 *     contiguous blocks.
	 *
	 * We need physically contiguous 2MB blocks so that the 2MB large-page
	 * EPT entry (PS=1) maps a correctly-aligned, contiguous HPA range.
	 * Individual 4KB alloc_pages_node() calls produce pages that are
	 * 4KB-aligned but typically not 2MB-aligned or physically contiguous.
	 *
	 * alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 9) allocates
	 * 2^9 = 512 contiguous pages = 2MB, aligned to 2MB boundary.
	 *
	 * ram_pages[block_i * 512 + sub_i] = nth_page(block, sub_i)
	 * for each of the PHANTOM_EPT_NR_2MB_ENTRIES blocks.
	 */
	for (i = 0; i < PHANTOM_EPT_NR_2MB_ENTRIES; i++) {
		struct page *blk;
		unsigned int sub;

		blk = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 9);
		if (!blk) {
			ret = -ENOMEM;
			goto err_ram_2mb;
		}
		ept->ram_2mb_blocks[i] = blk;

		/* Populate ram_pages[] with individual sub-page pointers */
		for (sub = 0; sub < 512; sub++) {
			unsigned int idx = (unsigned int)i * 512 + sub;

			ept->ram_pages[idx] = nth_page(blk, sub);
		}
	}

	/*
	 * 6b. Allocate the 4KB region backing pages individually.
	 *
	 * Indices PHANTOM_EPT_2MB_REGION_PAGES .. PHANTOM_EPT_RAM_PAGES-1
	 * correspond to GPA 0x800000–0xFFFFFF (second 8MB).
	 */
	for (i = PHANTOM_EPT_2MB_REGION_PAGES; i < PHANTOM_EPT_RAM_PAGES;
	     i++) {
		ept->ram_pages[i] = alloc_pages_node(node,
						     GFP_KERNEL | __GFP_ZERO,
						     0);
		if (!ept->ram_pages[i]) {
			ret = -ENOMEM;
			goto err_ram_4kb;
		}
	}

	return 0;

err_ram_4kb:
	for (i = i - 1; (int)i >= (int)PHANTOM_EPT_2MB_REGION_PAGES; i--) {
		__free_page(ept->ram_pages[i]);
		ept->ram_pages[i] = NULL;
	}
	i = PHANTOM_EPT_NR_2MB_ENTRIES;
err_ram_2mb:
	for (i = i - 1; (int)i >= 0; i--) {
		if (ept->ram_2mb_blocks[i]) {
			__free_pages(ept->ram_2mb_blocks[i], 9);
			ept->ram_2mb_blocks[i] = NULL;
		}
	}
	kvfree(ept->ram_pages);
	ept->ram_pages = NULL;
err_ram_array:
	i = PHANTOM_EPT_NR_PT_PAGES;
err_pt:
	for (i = i - 1; i >= 0; i--) {
		__free_page(ept->pt[i]);
		ept->pt[i] = NULL;
	}
	__free_page(ept->pd);
	ept->pd = NULL;
err_pd:
	__free_page(ept->pdpt);
	ept->pdpt = NULL;
err_pdpt:
	__free_page(ept->pml4);
	ept->pml4 = NULL;
err_pml4:
	return ret;
}
EXPORT_SYMBOL_GPL(phantom_ept_alloc);

/* ------------------------------------------------------------------
 * phantom_ept_build - Populate EPT page table entries (mixed layout)
 *
 * GPA bit decomposition for 4-level EPT:
 *   [47:39] → PML4 index
 *   [38:30] → PDPT index
 *   [29:21] → PD index
 *   [20:12] → PT index  (4KB only)
 *   [11: 0] → page offset
 *
 * For 16MB RAM (GPAs 0x00000000–0x00FFFFFF):
 *   PML4 index = 0         (GPA[47:39] = 0)
 *   PDPT index = 0         (GPA[38:30] = 0)
 *   PD   index = 0–7       (GPA[29:21] = 0..7 for 8 × 2MB)
 *
 * Task 1.5 mixed layout:
 *   PD index 0–3: 2MB large-page entries (PS=1, RW+WB initially)
 *     HPA = page_to_phys(ept->ram_2mb_blocks[i]) — 2MB-aligned
 *     phantom_ept_mark_all_ro() clears WRITE bit before first VMLAUNCH
 *   PD index 4–7: 4KB page entries pointing to PT pages
 * ------------------------------------------------------------------ */

/**
 * phantom_ept_build - Populate all EPT levels and return the EPTP value.
 * @ept: EPT state with pages already allocated by phantom_ept_alloc().
 *
 * Populates:
 *   - PML4[0] → PDPT (RWX non-leaf)
 *   - PDPT[0] → PD   (RWX non-leaf)
 *   - PD[0..3]: 2MB large-page entries (PS=1, RE+WB, WRITE cleared for CoW)
 *   - PD[4..7]: pointer to PT pages (RWX non-leaf)
 *   - PT[i][j]: 4KB leaf entries (RWX+WB for second 8MB region)
 *
 * The 2MB large-page entries are RO (WRITE=0) so CoW logic works via
 * phantom_split_2mb_page() on the first write fault.
 *
 * Returns the EPTP value, also stored in ept->eptp.
 */
u64 phantom_ept_build(struct phantom_ept_state *ept)
{
	u64 *pml4, *pdpt, *pd, *pt;
	u64 eptp;
	int pd_idx, pt_idx;

	pml4 = (u64 *)page_address(ept->pml4);
	pdpt = (u64 *)page_address(ept->pdpt);
	pd   = (u64 *)page_address(ept->pd);

	/* Zero the structure pages (they may have been rebuilt) */
	memset(pml4, 0, PAGE_SIZE);
	memset(pdpt, 0, PAGE_SIZE);
	memset(pd,   0, PAGE_SIZE);

	/*
	 * PML4[0] → PDPT
	 * Non-leaf entry: RWX bits MUST be set.  Missing R bit = EPT misconfig.
	 */
	pml4[0] = page_to_phys(ept->pdpt) | EPT_PERM_RWX;

	/* PDPT[0] → PD */
	pdpt[0] = page_to_phys(ept->pd) | EPT_PERM_RWX;

	/*
	 * PD entries 0–3: 2MB large-page entries (first 8MB, PS=1).
	 *
	 * Each 2MB region is backed by a physically contiguous order-9 block
	 * (ram_2mb_blocks[i]).  page_to_phys() of the first page of the block
	 * gives the 2MB-aligned HPA, since alloc_pages(order=9) guarantees
	 * 2^9 × 4KB = 2MB alignment.
	 *
	 * Permissions: READ | WRITE | EXEC | WB | PS
	 * phantom_ept_mark_all_ro() will clear WRITE before first VMLAUNCH.
	 */
	for (pd_idx = 0; pd_idx < PHANTOM_EPT_NR_2MB_ENTRIES; pd_idx++) {
		u64 hpa_2mb = page_to_phys(ept->ram_2mb_blocks[pd_idx]);

		pd[pd_idx] = hpa_2mb | EPT_PTE_READ | EPT_PTE_WRITE |
			     EPT_PTE_EXEC | EPT_PTE_MEMTYPE_WB | EPT_PTE_PS;
	}

	/*
	 * PD entries 4–7: non-leaf entries pointing to PT pages (4KB region).
	 *
	 * pt[i] corresponds to PD entry (PHANTOM_EPT_4KB_PD_START + i).
	 */
	for (pd_idx = 0; pd_idx < PHANTOM_EPT_NR_PT_PAGES; pd_idx++) {
		int pde_idx = PHANTOM_EPT_4KB_PD_START + pd_idx;

		memset(page_address(ept->pt[pd_idx]), 0, PAGE_SIZE);
		pd[pde_idx] = page_to_phys(ept->pt[pd_idx]) | EPT_PERM_RWX;
	}

	/*
	 * PT entries for 4KB region (PD entries 4–7):
	 * Map each 4KB RAM page in the second 8MB (GPA 0x800000–0xFFFFFF).
	 *
	 * RAM page index for the second 8MB region starts at:
	 *   PHANTOM_EPT_2MB_REGION_PAGES = PHANTOM_EPT_NR_2MB_ENTRIES * 512
	 */
	for (pd_idx = 0; pd_idx < PHANTOM_EPT_NR_PT_PAGES; pd_idx++) {
		pt = (u64 *)page_address(ept->pt[pd_idx]);

		for (pt_idx = 0; pt_idx < 512; pt_idx++) {
			unsigned int ram_idx = PHANTOM_EPT_2MB_REGION_PAGES +
					       (unsigned int)pd_idx * 512 +
					       (unsigned int)pt_idx;
			u64 hpa;

			if (ram_idx >= PHANTOM_EPT_RAM_PAGES)
				break;

			hpa = page_to_phys(ept->ram_pages[ram_idx]);

			/*
			 * Leaf entry: RWX + WB memory type + HPA.
			 * For CoW this becomes RO at snapshot time via
			 * phantom_ept_mark_all_ro().
			 */
			pt[pt_idx] = hpa | EPT_PTE_READ | EPT_PTE_WRITE |
				     EPT_PTE_EXEC | EPT_PTE_MEMTYPE_WB;
		}
	}

	/* EPTP: PML4 phys | WB caching | 4-level walk (no A/D bits) */
	eptp = page_to_phys(ept->pml4) | EPTP_MEMTYPE_WB | EPTP_PAGEWALK_4;
	ept->eptp = eptp;

	return eptp;
}
EXPORT_SYMBOL_GPL(phantom_ept_build);

/* ------------------------------------------------------------------
 * phantom_ept_teardown - Free all EPT + RAM pages
 * ------------------------------------------------------------------ */

/**
 * phantom_ept_teardown - Free all pages allocated by phantom_ept_alloc.
 * @ept: EPT state to tear down.
 *
 * NULL-safe: skips any page pointer that is NULL (handles partial alloc).
 *
 * Frees: ram_pages array + individual ram_pages, PT pages (4KB region),
 * PD, PDPT, PML4.
 * Does NOT free split-list PT pages — those are owned by phantom_split_list
 * and freed via phantom_split_list_free().
 */
void phantom_ept_teardown(struct phantom_ept_state *ept)
{
	int i;

	if (ept->ram_pages) {
		/*
		 * Free 4KB region pages individually
		 * (indices PHANTOM_EPT_2MB_REGION_PAGES..PHANTOM_EPT_RAM_PAGES-1).
		 * The 2MB region pages (indices 0..PHANTOM_EPT_2MB_REGION_PAGES-1)
		 * are sub-pages of order-9 blocks and must NOT be individually freed.
		 */
		for (i = PHANTOM_EPT_RAM_PAGES - 1;
		     i >= (int)PHANTOM_EPT_2MB_REGION_PAGES; i--) {
			if (ept->ram_pages[i]) {
				__free_page(ept->ram_pages[i]);
				ept->ram_pages[i] = NULL;
			}
		}

		/* NULL out 2MB region pointers (owned by ram_2mb_blocks) */
		for (i = 0; i < (int)PHANTOM_EPT_2MB_REGION_PAGES; i++)
			ept->ram_pages[i] = NULL;

		kvfree(ept->ram_pages);
		ept->ram_pages = NULL;
	}

	/*
	 * Free the order-9 (2MB) contiguous blocks for the first 8MB.
	 * Each block covers 512 × 4KB = 2MB.
	 */
	for (i = PHANTOM_EPT_NR_2MB_ENTRIES - 1; i >= 0; i--) {
		if (ept->ram_2mb_blocks[i]) {
			__free_pages(ept->ram_2mb_blocks[i], 9);
			ept->ram_2mb_blocks[i] = NULL;
		}
	}

	/*
	 * Free only the PHANTOM_EPT_NR_PT_PAGES PT pages for the 4KB region.
	 * The split-list PT pages (from 2MB splits) are managed separately
	 * by phantom_split_list_free().
	 */
	for (i = PHANTOM_EPT_NR_PT_PAGES - 1; i >= 0; i--) {
		if (ept->pt[i]) {
			__free_page(ept->pt[i]);
			ept->pt[i] = NULL;
		}
	}

	if (ept->pd) {
		__free_page(ept->pd);
		ept->pd = NULL;
	}

	if (ept->pdpt) {
		__free_page(ept->pdpt);
		ept->pdpt = NULL;
	}

	if (ept->pml4) {
		__free_page(ept->pml4);
		ept->pml4 = NULL;
	}

	ept->eptp  = 0;
	ept->ready = false;
}
EXPORT_SYMBOL_GPL(phantom_ept_teardown);

/* ------------------------------------------------------------------
 * phantom_ept_lookup_pte - 4-level EPT walk
 * ------------------------------------------------------------------ */

/**
 * phantom_ept_lookup_pte - Walk the 4-level EPT for a given GPA.
 * @ept: EPT state.
 * @gpa: Guest physical address to look up.
 *
 * Walks: PML4 → PDPT → PD → PT.
 * Handles both 2MB large-page entries (PS=1 in PD) and 4KB entries.
 *
 * For 2MB large-page entries (first 8MB, before any split):
 *   Returns NULL — the PDE itself is not a 4KB leaf PTE.
 *   Use phantom_ept_get_pd_entry() instead to get the PD entry pointer.
 *
 * For 4KB entries (second 8MB or after a 2MB split):
 *   Returns a pointer to the leaf PT entry.
 *
 * Returns NULL if the GPA is outside the EPT structure.
 */
u64 *phantom_ept_lookup_pte(struct phantom_ept_state *ept, u64 gpa)
{
	unsigned int pml4_idx, pdpt_idx, pd_idx, pt_idx;
	u64 *pml4, *pdpt, *pd, *pt;
	u64 entry;

	pml4_idx = (gpa >> 39) & 0x1FF;
	pdpt_idx = (gpa >> 30) & 0x1FF;
	pd_idx   = (gpa >> 21) & 0x1FF;
	pt_idx   = (gpa >> 12) & 0x1FF;

	pml4 = (u64 *)page_address(ept->pml4);
	entry = pml4[pml4_idx];
	if (!(entry & EPT_PTE_READ))
		return NULL;

	pdpt = (u64 *)phys_to_virt(entry & EPT_PTE_HPA_MASK);
	entry = pdpt[pdpt_idx];
	if (!(entry & EPT_PTE_READ))
		return NULL;

	pd = (u64 *)phys_to_virt(entry & EPT_PTE_HPA_MASK);
	entry = pd[pd_idx];
	if (!(entry & EPT_PTE_READ))
		return NULL;

	/*
	 * 2MB large page (PS=1 in PD entry): this GPA is covered by a
	 * large-page mapping, not a 4KB PT.  Caller should use
	 * phantom_ept_get_pd_entry() to get the PDE pointer directly.
	 * Return NULL so callers know this is not a 4KB PTE.
	 */
	if (entry & EPT_PTE_PS)
		return NULL;

	pt = (u64 *)phys_to_virt(entry & EPT_PTE_HPA_MASK);
	return &pt[pt_idx];
}
EXPORT_SYMBOL_GPL(phantom_ept_lookup_pte);

/* ------------------------------------------------------------------
 * phantom_ept_get_ram_page - Return backing struct page for a RAM GPA
 * ------------------------------------------------------------------ */

/**
 * phantom_ept_get_ram_page - Get the backing struct page for a RAM GPA.
 * @ept: EPT state.
 * @gpa: Guest physical address (must be within 0–16MB RAM range).
 *
 * Returns the struct page pointer, or NULL if GPA is out of RAM range.
 */
struct page *phantom_ept_get_ram_page(struct phantom_ept_state *ept, u64 gpa)
{
	unsigned int idx;

	if (gpa < PHANTOM_EPT_RAM_BASE ||
	    gpa >= PHANTOM_EPT_RAM_END)
		return NULL;

	idx = gpa_to_ram_idx(gpa);
	if (idx >= PHANTOM_EPT_RAM_PAGES)
		return NULL;

	return ept->ram_pages[idx];
}
EXPORT_SYMBOL_GPL(phantom_ept_get_ram_page);

/* ------------------------------------------------------------------
 * phantom_ept_mark_all_ro - Write-protect all RAM leaf PTEs
 * ------------------------------------------------------------------ */

/**
 * phantom_ept_mark_all_ro - Clear EPT_PTE_WRITE on all 16MB RAM PTEs.
 * @ept: EPT state with pages already built by phantom_ept_build().
 *
 * Task 1.5: handles BOTH regions:
 *
 * 1. 2MB large-page region (PD entries 0–3, first 8MB):
 *    Clears EPT_PTE_WRITE from each 2MB PD entry that has PS=1 and READ.
 *
 * 2. 4KB region (PT pages for PD entries 4–7, second 8MB):
 *    Iterates all PT pages and clears EPT_PTE_WRITE from each present leaf.
 *
 * After this call:
 *   - All guest writes to RAM trigger EPT violation (exit 48).
 *   - phantom_cow_fault() handles 4KB violations directly.
 *   - phantom_cow_fault() calls phantom_split_2mb_page() for 2MB faults.
 *   - Execute and read access still function normally.
 *
 * Called before the first VMLAUNCH (snapshot point).
 * Must NOT be called while the guest is running (not re-entrant).
 */
void phantom_ept_mark_all_ro(struct phantom_ept_state *ept)
{
	u64 *pd;
	int pd_idx, pt_idx;

	if (!ept || !ept->ready)
		return;

	pd = (u64 *)page_address(ept->pd);

	/*
	 * Step 1: Clear WRITE from 2MB large-page PD entries (first 8MB).
	 *
	 * These entries have PS=1 (EPT_PTE_PS).  After clearing WRITE,
	 * any guest write to this 2MB region triggers EPT violation with
	 * exit qualification showing the GPA is readable but not writable.
	 * phantom_cow_fault() will detect PS=1 in the PDE and call
	 * phantom_split_2mb_page() to split into 512 × 4KB RO entries.
	 */
	for (pd_idx = 0; pd_idx < PHANTOM_EPT_NR_2MB_ENTRIES; pd_idx++) {
		if ((pd[pd_idx] & EPT_PTE_READ) &&
		    (pd[pd_idx] & EPT_PTE_PS))
			pd[pd_idx] &= ~EPT_PTE_WRITE;
	}

	/*
	 * Step 2: Clear WRITE from 4KB PT entries (second 8MB).
	 *
	 * pt[i] corresponds to PD entry (PHANTOM_EPT_4KB_PD_START + i).
	 */
	for (pd_idx = 0; pd_idx < PHANTOM_EPT_NR_PT_PAGES; pd_idx++) {
		u64 *pt;

		if (!ept->pt[pd_idx])
			continue;

		pt = (u64 *)page_address(ept->pt[pd_idx]);

		for (pt_idx = 0; pt_idx < 512; pt_idx++) {
			if (pt[pt_idx] & EPT_PTE_READ)
				pt[pt_idx] &= ~EPT_PTE_WRITE;
		}
	}
}
EXPORT_SYMBOL_GPL(phantom_ept_mark_all_ro);

/* ------------------------------------------------------------------
 * phantom_ept_get_pd_entry - Walk to PD level and return PDE pointer
 * ------------------------------------------------------------------ */

/**
 * phantom_ept_get_pd_entry - Return pointer to the PD entry for a GPA.
 * @ept: EPT state.
 * @gpa: Guest physical address.
 *
 * Walks PML4 → PDPT → PD and returns a pointer to the PD entry
 * (the entry at PD[GPA[29:21]]).  The caller can inspect or modify the
 * entry directly (e.g., to check PS=1 for 2MB large-page detection or
 * to replace a 2MB entry with a 4KB-level PT pointer during splitting).
 *
 * Returns NULL if PML4 or PDPT entries are absent (no EPT coverage).
 * Hot-path safe: no allocation, no sleeping.
 */
u64 *phantom_ept_get_pd_entry(struct phantom_ept_state *ept, u64 gpa)
{
	unsigned int pml4_idx = (gpa >> 39) & 0x1FF;
	unsigned int pdpt_idx = (gpa >> 30) & 0x1FF;
	unsigned int pd_idx   = (gpa >> 21) & 0x1FF;
	u64 *pml4, *pdpt, *pd;
	u64 entry;

	pml4 = (u64 *)page_address(ept->pml4);
	entry = pml4[pml4_idx];
	if (!(entry & EPT_PTE_READ))
		return NULL;

	pdpt = (u64 *)phys_to_virt(entry & EPT_PTE_HPA_MASK);
	entry = pdpt[pdpt_idx];
	if (!(entry & EPT_PTE_READ))
		return NULL;

	pd = (u64 *)phys_to_virt(entry & EPT_PTE_HPA_MASK);
	return &pd[pd_idx];
}
EXPORT_SYMBOL_GPL(phantom_ept_get_pd_entry);

/* ------------------------------------------------------------------
 * phantom_invept_single_context - single-context INVEPT
 * ------------------------------------------------------------------ */

/*
 * INVEPT descriptor: 16 bytes as required by Intel SDM Vol. 3C §30.3.
 */
struct phantom_invept_desc {
	u64 eptp;
	u64 rsvd;
} __packed;

/**
 * phantom_invept_single_context - Invalidate EPT translations for @eptp.
 * @eptp: EPT pointer value identifying the context to invalidate.
 *
 * Issues INVEPT type 1 (single-context) which invalidates all cached
 * EPT translations associated with this EPTP value.
 *
 * Required after 2MB→4KB structural splits:
 *   The processor may have cached the 2MB translation for non-faulting
 *   GPAs within the same 2MB range.  INVEPT invalidates those stale
 *   cached translations so subsequent accesses use the new 4KB PTEs.
 *
 * NOT required after 4KB RO→RW CoW faults:
 *   The EPT violation itself invalidates the cached translation for the
 *   faulting GPA (Intel SDM §28.3.3.1).
 *
 * Emits trace_printk under PHANTOM_DEBUG.
 * Reports pr_err if INVEPT returns CF=1 (hardware error, should never
 * happen with a valid EPTP and supported INVEPT type).
 */
void phantom_invept_single_context(u64 eptp)
{
	struct phantom_invept_desc desc = { .eptp = eptp, .rsvd = 0 };
	u64 rflags;

	asm volatile(
		"invept %1, %2\n\t"
		"pushfq\n\t"
		"popq %0"
		: "=r"(rflags)
		: "m"(desc), "r"((u64)1)  /* type 1 = single-context */
		: "cc", "memory");

	if (rflags & X86_EFLAGS_CF)
		pr_err("phantom: INVEPT single-context failed "
		       "(CF=1, eptp=0x%llx)\n", eptp);

#ifdef PHANTOM_DEBUG
	trace_printk("PHANTOM INVEPT type=1 eptp=0x%llx\n", eptp);
#endif
}
EXPORT_SYMBOL_GPL(phantom_invept_single_context);
