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
 *
 * Task 1.5: Mixed 2MB+4KB EPT layout:
 *   First 8MB  (GPA 0x000000–0x7FFFFF): 4 × 2MB large-page PD entries
 *   Second 8MB (GPA 0x800000–0xFFFFFF): 4KB pages (4 PT pages × 512 entries)
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
 * Guest RAM layout for task 1.5 (mixed 2MB + 4KB EPT)
 *
 * 16MB flat RAM: GPA 0x00000000–0x00FFFFFF
 *   1 PML4 entry (index 0)
 *   1 PDPT entry (index 0)
 *   1 PD    (8 entries, indices 0–7 → 8 × 2MB = 16MB)
 *
 *   First 8MB (PD entries 0–3): 2MB large pages (PS=1, no PT needed)
 *   Second 8MB (PD entries 4–7): 4KB pages (4 PT pages × 512 entries)
 *
 *   4096 backing RAM pages (16MB total)
 *
 * GPA 0x01000000 and above → absent (no EPT entry).
 * ------------------------------------------------------------------ */
#define PHANTOM_EPT_RAM_BASE		0x00000000ULL
#define PHANTOM_EPT_RAM_SIZE_MB		16
#define PHANTOM_EPT_RAM_PAGES		(PHANTOM_EPT_RAM_SIZE_MB * 256)
#define PHANTOM_EPT_RAM_END		\
	(PHANTOM_EPT_RAM_BASE + (PHANTOM_EPT_RAM_SIZE_MB << 20))

/* Total PD entries covering RAM (8 × 2MB = 16MB) */
#define PHANTOM_EPT_NR_PD_ENTRIES	8

/*
 * Task 1.5 mixed layout:
 *   2MB region: PD entries 0–3 (GPA 0x000000–0x7FFFFF), no PT needed
 *   4KB region: PD entries 4–7 (GPA 0x800000–0xFFFFFF), 4 PT pages
 */
#define PHANTOM_EPT_NR_2MB_ENTRIES	4	/* large-page PD entries */
#define PHANTOM_EPT_NR_PT_PAGES		4	/* 4KB-level PT pages    */
/* First PD index using 4KB pages (second half) */
#define PHANTOM_EPT_4KB_PD_START	PHANTOM_EPT_NR_2MB_ENTRIES

/* Size of the 2MB-mapped region in bytes */
#define PHANTOM_EPT_2MB_REGION_SIZE	\
	((u64)PHANTOM_EPT_NR_2MB_ENTRIES << 21)

/* Number of 4KB pages in the 2MB-mapped region */
#define PHANTOM_EPT_2MB_REGION_PAGES	\
	(PHANTOM_EPT_NR_2MB_ENTRIES * 512U)

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
 * Task 1.5 mixed layout:
 *   pml4:          1 page  (EPT PML4)
 *   pdpt:          1 page  (EPT PDPT)
 *   pd:            1 page  (EPT PD, 8 active entries)
 *   pt[0..3]:      4 pages (EPT PT pages for PD entries 4–7, 4KB region)
 *                          (pt[0..3] correspond to PD entries 4–7)
 *   ram_pages:     heap pointer → PHANTOM_EPT_RAM_PAGES page pointers
 *
 * PD entries 0–3 map via 2MB large pages (PS=1, no PT page needed).
 * PD entries 4–7 map via PT pages pt[0..3] at 4KB granularity.
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
	/*
	 * pt[0..PHANTOM_EPT_NR_PT_PAGES-1]: PT pages for 4KB region only.
	 * pt[i] corresponds to PD entry (PHANTOM_EPT_4KB_PD_START + i).
	 */
	struct page		*pt[PHANTOM_EPT_NR_PT_PAGES];

	/*
	 * ram_2mb_blocks[]: order-9 (2MB = 512 × 4KB) physically contiguous
	 * page blocks for the 2MB large-page region (first 8MB).
	 *
	 * ram_2mb_blocks[i] is the first struct page of the i-th 2MB block.
	 * Each block covers 512 consecutive 4KB pages.
	 * HPA of block i = page_to_phys(ram_2mb_blocks[i]).
	 *
	 * Stored separately so phantom_ept_teardown() can free them with
	 * __free_pages(block, 9) rather than 512 × __free_page().
	 *
	 * ram_pages[0..PHANTOM_EPT_2MB_REGION_PAGES-1] are derived from
	 * these blocks (each page in the block is individually tracked).
	 */
	struct page		*ram_2mb_blocks[PHANTOM_EPT_NR_2MB_ENTRIES];

	/*
	 * Backing RAM pages: heap-allocated array of PHANTOM_EPT_RAM_PAGES
	 * struct page pointers.  Index = GPA >> PAGE_SHIFT.
	 *
	 * For the 2MB region (indices 0..PHANTOM_EPT_2MB_REGION_PAGES-1):
	 *   ram_pages[i] = nth_page(ram_2mb_blocks[i/512], i % 512)
	 *   These are sub-pages of order-9 blocks — do NOT free individually.
	 *
	 * For the 4KB region (indices PHANTOM_EPT_2MB_REGION_PAGES..4095):
	 *   ram_pages[i] = individually allocated pages — free with __free_page.
	 *
	 * Allocated by kvmalloc_array in phantom_ept_alloc().
	 * Freed in phantom_ept_teardown().
	 */
	struct page		**ram_pages;

	/*
	 * null_guard_pt: PT page used to install the null-guard mapping.
	 *
	 * phantom_ept_install_null_guard() splits PD[0] (the 2MB large page
	 * covering GPAs 0x000000–0x1FFFFF) into 512 × 4KB PTEs and marks
	 * PT[0] = 0 (absent) so any access to GPA 0x000–0xFFF triggers an
	 * EPT violation → PHANTOM_RESULT_CRASH.
	 *
	 * NULL until phantom_ept_install_null_guard() is called.
	 * Freed by phantom_ept_teardown().
	 */
	struct page		*null_guard_pt;

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
 * Allocates: 1 PML4 + 1 PDPT + 1 PD +
 *            PHANTOM_EPT_NR_PT_PAGES PT pages (for 4KB region) +
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

/**
 * phantom_ept_mark_all_ro - Mark all RAM EPT leaf PTEs read-only.
 * @ept: EPT state (must have been built by phantom_ept_build).
 *
 * For the 4KB region: walks all PT entries and clears EPT_PTE_WRITE.
 * For the 2MB region: walks all 2MB large-page PD entries and clears
 * EPT_PTE_WRITE (checking PS bit to identify large-page entries).
 *
 * This simulates the snapshot moment: after this call, any guest write
 * to a RAM GPA triggers an EPT violation (exit reason 48) which is
 * handled by phantom_cow_fault() to create a private copy.
 *
 * Called from vmx_core.c after phantom_ept_build() and before the
 * first VMLAUNCH.  Must be called from process context.
 */
void phantom_ept_mark_all_ro(struct phantom_ept_state *ept);

/**
 * phantom_ept_install_null_guard - Mark GPA 0x000–0xFFF as EPT absent.
 * @ept: EPT state (must have been built by phantom_ept_build).
 *
 * Splits PD[0] (the first 2MB large-page entry) into 512 × 4KB PTEs
 * via a newly allocated PT page.  PT[0] is set to 0 (absent — no R/W/X
 * bits) so any access to GPA 0x000–0xFFF causes an EPT violation with
 * "GPA not readable" qualification.  The vmx_core.c EPT violation handler
 * detects this as a non-CoW fault and sets PHANTOM_RESULT_CRASH.
 *
 * PT[1..511] map their corresponding 4KB sub-pages of ram_2mb_blocks[0]
 * as read-only (WRITE cleared so CoW still works for these pages).
 *
 * MUST be called after phantom_ept_build() and before the first VMLAUNCH,
 * from process context (GFP_KERNEL allowed).
 *
 * Returns 0 on success, -ENOMEM if PT page allocation fails.
 */
int phantom_ept_install_null_guard(struct phantom_ept_state *ept);

/**
 * phantom_ept_get_pd_entry - Walk PML4→PDPT→PD and return PD entry pointer.
 * @ept: EPT state.
 * @gpa: Guest physical address (any GPA within the 16MB RAM range).
 *
 * Returns a pointer to the PD entry for the 2MB region containing @gpa,
 * or NULL if the GPA is not covered by the EPT structure.
 *
 * Hot-path safe: no allocation, no sleeping.
 * The returned pointer is directly writeable (used by split logic).
 */
u64 *phantom_ept_get_pd_entry(struct phantom_ept_state *ept, u64 gpa);

/**
 * phantom_invept_single_context - Issue single-context INVEPT for @eptp.
 * @eptp: EPTP value identifying the EPT context to invalidate.
 *
 * Required after 2MB→4KB structural splits (stale 2MB translations may
 * exist for non-faulting GPAs in the same 2MB range).
 *
 * NOT required after 4KB RO→RW CoW faults (the EPT violation itself
 * invalidated the faulting GPA's cached translation — Intel SDM §28.3.3.1).
 *
 * Uses trace_printk (under PHANTOM_DEBUG) to log INVEPT events.
 * Reports via pr_err if INVEPT returns CF=1 (hardware error).
 */
void phantom_invept_single_context(u64 eptp);

#endif /* PHANTOM_EPT_H */
