// SPDX-License-Identifier: GPL-2.0-only
/*
 * ept.h — EPT page table structures, GPA classification, and API
 *
 * Covers the full 4-level EPT for a 16MB flat RAM identity map,
 * GPA range classification (RAM / MMIO / reserved), and the EPTP
 * computation.  EPT A/D bits are disabled for task 1.3.
 *
 * Non-leaf EPT entries (PML4, PDPT, PD→PT) MUST have RWX bits set.
 * Leaf entries are either all-zero (absent) or have at least R bit set.
 */
#ifndef PHANTOM_EPT_H
#define PHANTOM_EPT_H

#include <linux/types.h>
#include <linux/mm_types.h>

/* ------------------------------------------------------------------
 * EPT PTE bit layout (Intel SDM Vol. 3C §28.2.2)
 * ------------------------------------------------------------------ */
#define EPT_PTE_READ		(1ULL << 0)	/* Read permission        */
#define EPT_PTE_WRITE		(1ULL << 1)	/* Write permission       */
#define EPT_PTE_EXEC		(1ULL << 2)	/* Execute permission     */
#define EPT_PTE_MEMTYPE_MASK	(0x7ULL << 3)	/* Memory type bits [5:3] */
#define EPT_PTE_MEMTYPE_UC	(0ULL << 3)	/* Uncacheable            */
#define EPT_PTE_MEMTYPE_WB	(6ULL << 3)	/* Write-Back             */
#define EPT_PTE_PS		(1ULL << 7)	/* Large page (2MB in PD) */
#define EPT_PTE_ACCESSED	(1ULL << 8)	/* A bit (EPT A/D)        */
#define EPT_PTE_DIRTY		(1ULL << 9)	/* D bit (EPT A/D)        */

/* Bits [51:12] of a leaf PTE hold the HPA (page-aligned) */
#define EPT_PTE_HPA_MASK	(~0xFFFULL & ((1ULL << 52) - 1))

/* EPTP (EPT Pointer) format — no A/D bits for task 1.3 */
#define EPTP_MEMTYPE_WB		(6ULL << 0)	/* WB for EPT structures  */
#define EPTP_PAGEWALK_4		(3ULL << 3)	/* 4-level EPT walk       */

/* Permissions shorthand for non-leaf entries */
#define EPT_PERM_RWX		(EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_EXEC)

/* ------------------------------------------------------------------
 * Guest RAM layout for task 1.3
 *
 * 16MB flat RAM: GPA 0x00000000–0x00FFFFFF
 *   1 PML4 entry (index 0)
 *   1 PDPT entry (index 0)
 *   1 PD    (8 entries, indices 0–7 → 8 × 2MB = 16MB)
 *   8 PT    pages (512 entries each → 8 × 512 × 4KB = 16MB)
 *   4096 backing RAM pages (16MB total)
 *
 * GPA 0x01000000 and above → absent (no EPT entry).
 * ------------------------------------------------------------------ */
#define PHANTOM_EPT_RAM_BASE		0x00000000ULL
#define PHANTOM_EPT_RAM_SIZE_MB		16
#define PHANTOM_EPT_RAM_PAGES		(PHANTOM_EPT_RAM_SIZE_MB * 256)
#define PHANTOM_EPT_RAM_END		\
	(PHANTOM_EPT_RAM_BASE + (PHANTOM_EPT_RAM_SIZE_MB << 20))

/* Number of PT pages needed: 16MB / 2MB_per_PD_entry = 8 */
#define PHANTOM_EPT_NR_PD_ENTRIES	8
#define PHANTOM_EPT_NR_PT_PAGES		PHANTOM_EPT_NR_PD_ENTRIES

/* Guest page layout (GPAs that must be backed by specific pages) */
#define GUEST_CODE_GPA			0x00010000ULL
#define GUEST_STACK_GPA			0x00011000ULL
#define GUEST_DATA_GPA			0x00012000ULL
#define GUEST_PML4_GPA			0x00013000ULL
#define GUEST_PDPT_GPA			0x00014000ULL
#define GUEST_PD_GPA			0x00015000ULL

/*
 * Data pages for R/W test: 10 pages at 0x30000–0x39000.
 * All within the first 2MB → covered by PT page 0.
 */
#define GUEST_RWTEST_GPA_BASE		0x00030000ULL
#define GUEST_RWTEST_NR_PAGES		10

/*
 * Absent-GPA test target: first GPA outside RAM map.
 * This triggers an EPT violation when the guest accesses it.
 */
#define GUEST_ABSENT_GPA		0x01000000ULL

/* ------------------------------------------------------------------
 * GPA type classification
 * ------------------------------------------------------------------ */
enum phantom_gpa_type {
	PHANTOM_GPA_RAM		= 0,	/* CoW-eligible, WB memory type */
	PHANTOM_GPA_MMIO	= 1,	/* Trap-and-emulate, no CoW     */
	PHANTOM_GPA_RESERVED	= 2,	/* EPT-absent, any access→abort */
};

/*
 * struct phantom_gpa_region - describes a GPA range and its treatment.
 * @gpa_start:  First GPA in this region (inclusive).
 * @gpa_end:    First GPA beyond this region (exclusive).
 * @type:       RAM / MMIO / RESERVED.
 * @ept_flags:  EPT leaf permission + memtype bits (0 = absent).
 */
struct phantom_gpa_region {
	u64			 gpa_start;
	u64			 gpa_end;
	enum phantom_gpa_type	 type;
	u64			 ept_flags;	/* leaf PTE bits (no HPA) */
};

/* ------------------------------------------------------------------
 * struct phantom_ept_state - all EPT resources for one vCPU instance.
 *
 * Allocated by phantom_ept_alloc(), populated by phantom_ept_build(),
 * freed by phantom_ept_teardown().
 *
 * Layout of page arrays:
 *   pml4:          1 page  (EPT PML4)
 *   pdpt:          1 page  (EPT PDPT)
 *   pd:            1 page  (EPT PD, 8 active entries)
 *   pt[0..7]:      8 pages (EPT PT pages, one per 2MB range)
 *   ram_pages:     heap pointer → PHANTOM_EPT_RAM_PAGES page pointers
 *
 * ram_pages is heap-allocated (kvmalloc) because embedding 4096 pointers
 * directly in the struct would exceed the kernel percpu data size limit
 * (DEFINE_PER_CPU with >32KB static data fails at module load time).
 *
 * eptp is set by phantom_ept_build() and passed to VMCS_CTRL_EPT_POINTER.
 * ------------------------------------------------------------------ */
struct phantom_ept_state {
	/* EPT structure pages */
	struct page		*pml4;
	struct page		*pdpt;
	struct page		*pd;
	struct page		*pt[PHANTOM_EPT_NR_PT_PAGES];

	/*
	 * Backing RAM pages: heap-allocated array of PHANTOM_EPT_RAM_PAGES
	 * struct page pointers.  Index = GPA >> PAGE_SHIFT.
	 * Allocated by kvmalloc_array in phantom_ept_alloc().
	 * Freed in phantom_ept_teardown().
	 */
	struct page		**ram_pages;

	/* Computed EPTP value (set by phantom_ept_build) */
	u64			 eptp;

	/* True once alloc + build succeeded */
	bool			 ready;
};

/* ------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------ */

/**
 * phantom_ept_classify_gpa - Classify a GPA into RAM / MMIO / reserved.
 * @gpa: Guest physical address to classify.
 *
 * Returns a pointer to the matching static region descriptor.
 * Never returns NULL.
 */
const struct phantom_gpa_region *phantom_ept_classify_gpa(u64 gpa);

/**
 * phantom_ept_alloc - Allocate all EPT pages for one vCPU instance.
 * @ept: EPT state to populate.
 * @cpu: Physical CPU index (for NUMA-local allocation).
 *
 * Allocates: 1 PML4 + 1 PDPT + 1 PD + 8 PT pages +
 *            4096 backing RAM pages.
 *
 * MUST be called from process context (GFP_KERNEL OK).
 * Idempotent once ept->ready is set.
 *
 * Returns 0 on success, negative errno on failure (goto-cleanup).
 */
int phantom_ept_alloc(struct phantom_ept_state *ept, int cpu);

/**
 * phantom_ept_build - Populate EPT page tables from allocated pages.
 * @ept: EPT state with pages already allocated.
 *
 * Sets ept->eptp to the correct EPTP value.
 * Must be called after phantom_ept_alloc().
 *
 * Returns the EPTP value (also stored in ept->eptp).
 */
u64 phantom_ept_build(struct phantom_ept_state *ept);

/**
 * phantom_ept_teardown - Free all pages allocated by phantom_ept_alloc.
 * @ept: EPT state to tear down.
 *
 * Safe to call even if alloc partially failed (NULL pages skipped).
 */
void phantom_ept_teardown(struct phantom_ept_state *ept);

/**
 * phantom_ept_lookup_pte - Walk the 4-level EPT and return the leaf PTE.
 * @ept: EPT state.
 * @gpa: Guest physical address to look up.
 *
 * Returns a pointer to the leaf 4KB EPT PTE, or NULL if the GPA is
 * not covered by the EPT structure (i.e., absent range).
 */
u64 *phantom_ept_lookup_pte(struct phantom_ept_state *ept, u64 gpa);

/**
 * phantom_ept_get_ram_page - Return the backing struct page for a RAM GPA.
 * @ept: EPT state.
 * @gpa: Guest physical address (must be within RAM range).
 *
 * Returns the struct page pointer, or NULL if out of range.
 */
struct page *phantom_ept_get_ram_page(struct phantom_ept_state *ept,
				      u64 gpa);

#endif /* PHANTOM_EPT_H */
