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
 *
 * EPT layout for task 1.3:
 *   RAM: GPA 0x00000000–0x00FFFFFF (16MB), 4KB pages, RWX + WB
 *   All other GPA ranges: absent (not-present, all-zero PTE)
 *
 * Critical correctness rules:
 *   - Non-leaf entries MUST have RWX bits set (else EPT misconfig #49)
 *   - Leaf RAM entries: EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_EXEC |
 *     EPT_PTE_MEMTYPE_WB | HPA
 *   - Absent entries: all-zero (no bits set)
 *   - EPTP: PML4_phys | EPTP_MEMTYPE_WB | EPTP_PAGEWALK_4 (no A/D)
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

#include "ept.h"

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

	/* 4. PT pages */
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

	/* 6. Allocate the RAM backing pages */
	for (i = 0; i < PHANTOM_EPT_RAM_PAGES; i++) {
		ept->ram_pages[i] = alloc_pages_node(node,
						     GFP_KERNEL | __GFP_ZERO,
						     0);
		if (!ept->ram_pages[i]) {
			ret = -ENOMEM;
			goto err_ram;
		}
	}

	return 0;

err_ram:
	for (i = i - 1; i >= 0; i--) {
		__free_page(ept->ram_pages[i]);
		ept->ram_pages[i] = NULL;
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
 * phantom_ept_build - Populate EPT page table entries
 *
 * GPA bit decomposition for 4-level EPT:
 *   [47:39] → PML4 index
 *   [38:30] → PDPT index
 *   [29:21] → PD index
 *   [20:12] → PT index
 *   [11: 0] → page offset
 *
 * For 16MB RAM (GPAs 0x00000000–0x00FFFFFF):
 *   PML4 index = 0         (GPA[47:39] = 0)
 *   PDPT index = 0         (GPA[38:30] = 0)
 *   PD   index = 0–7       (GPA[29:21] = 0..7 for 8 × 2MB)
 *   PT   index = 0–511     (GPA[20:12] within each 2MB range)
 * ------------------------------------------------------------------ */

/**
 * phantom_ept_build - Populate all EPT levels and return the EPTP value.
 * @ept: EPT state with pages already allocated by phantom_ept_alloc().
 *
 * Populates:
 *   - PML4[0] → PDPT (RWX non-leaf)
 *   - PDPT[0] → PD   (RWX non-leaf)
 *   - PD[0..7] → PT[i] (RWX non-leaf, 4KB granularity)
 *   - PT[i][j] → RAM page (RWX + WB leaf, if within 16MB)
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
	 *
	 * Non-leaf entry: RWX bits MUST be set.  Missing R bit = EPT misconfig.
	 */
	pml4[0] = page_to_phys(ept->pdpt) | EPT_PERM_RWX;

	/*
	 * PDPT[0] → PD
	 */
	pdpt[0] = page_to_phys(ept->pd) | EPT_PERM_RWX;

	/*
	 * PD[0..7] → PT[0..7]  (8 × 2MB = 16MB RAM)
	 *
	 * Each PD entry covers a 2MB range.  Bit 7 (PS) is NOT set —
	 * we use 4KB pages for full GPA-to-HPA granularity.
	 */
	for (pd_idx = 0; pd_idx < PHANTOM_EPT_NR_PD_ENTRIES; pd_idx++) {
		memset(page_address(ept->pt[pd_idx]), 0, PAGE_SIZE);
		pd[pd_idx] = page_to_phys(ept->pt[pd_idx]) | EPT_PERM_RWX;
	}

	/*
	 * PT entries: map each 4KB RAM page.
	 *
	 * GPA index: pd_idx selects which 2MB region (PT page),
	 * pt_idx selects the 4KB page within that region.
	 *
	 * RAM page index = pd_idx * 512 + pt_idx
	 * (since PAGE_SIZE = 4096 = 1 << 12)
	 */
	for (pd_idx = 0; pd_idx < PHANTOM_EPT_NR_PD_ENTRIES; pd_idx++) {
		pt = (u64 *)page_address(ept->pt[pd_idx]);

		for (pt_idx = 0; pt_idx < 512; pt_idx++) {
			unsigned int ram_idx = pd_idx * 512 + pt_idx;
			u64 hpa;

			if (ram_idx >= PHANTOM_EPT_RAM_PAGES)
				break;

			hpa = page_to_phys(ept->ram_pages[ram_idx]);

			/*
			 * Leaf entry: RWX + WB memory type + HPA.
			 *
			 * For CoW this will eventually become RO (clear W bit)
			 * at snapshot time.  For task 1.3 all pages are RWX.
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
 */
void phantom_ept_teardown(struct phantom_ept_state *ept)
{
	int i;

	if (ept->ram_pages) {
		for (i = PHANTOM_EPT_RAM_PAGES - 1; i >= 0; i--) {
			if (ept->ram_pages[i]) {
				__free_page(ept->ram_pages[i]);
				ept->ram_pages[i] = NULL;
			}
		}
		kvfree(ept->ram_pages);
		ept->ram_pages = NULL;
	}

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
 * Only valid for 4KB leaf entries (large-page entries not used here).
 *
 * Returns a pointer to the leaf PT entry, or NULL if the GPA is outside
 * the EPT structure (e.g., GPA >= 16MB which has no PT page).
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

	/* Large page (PS bit set in PD entry) — not used in task 1.3 */
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
