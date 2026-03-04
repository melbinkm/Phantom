// SPDX-License-Identifier: GPL-2.0-only
/*
 * ept_cow.c — CoW page pool, dirty list, split list, and EPT fault handler
 *
 * Implements the Copy-on-Write snapshot engine for phantom.ko:
 *
 *   phantom_cow_pool_init/destroy — pre-allocate private pages (NUMA-local)
 *   phantom_cow_pool_alloc/free   — lock-free LIFO allocation
 *   phantom_split_list_free       — free split-list PT pages
 *   phantom_cow_fault             — EPT violation handler (hot path)
 *   phantom_cow_abort_iteration   — restore snapshot state at end-of-iter
 *
 * INVEPT rules enforced here (Intel SDM §28.3.3.1):
 *   - phantom_cow_fault (4KB):     NO INVEPT (permission-only change,
 *                                   EPT violation itself invalidated GPA)
 *   - phantom_split_2mb_page:      YES, single-context INVEPT required
 *                                   (structural change — stale 2MB cached
 *                                    translations for non-faulting GPAs)
 *   - phantom_cow_abort_iteration: YES, one batched INVEPT (single-context)
 *                                   after ALL PTEs are reset
 *
 * Hot-path discipline (phantom_cow_fault, phantom_split_2mb_page):
 *   - No printk, no pr_*, no trace_printk outside PHANTOM_DEBUG
 *   - No kmalloc(GFP_KERNEL), no schedule(), no mutex_lock()
 *   - Split PT page uses GFP_ATOMIC (VM exit context, no sleeping)
 *   - All other resources pre-allocated at pool init time
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
#include <linux/atomic.h>
#include <asm/io.h>

#include "phantom.h"
#include "ept.h"
#include "ept_cow.h"
#include "vmx_core.h"
#include "debug.h"
#include "memory.h"

/*
 * No local INVEPT wrapper needed: phantom_invept_single_context() in ept.c
 * is the authoritative single-context INVEPT implementation, with tracing
 * and error reporting.  Use it for both split and abort-iteration paths.
 */

/* ------------------------------------------------------------------
 * phantom_cow_pool_init — NUMA-local page pool allocation
 * ------------------------------------------------------------------ */

/**
 * phantom_cow_pool_init - Allocate and initialise the CoW page pool.
 * @pool:     Pool to initialise (must be zeroed by caller).
 * @cpu:      Physical CPU index (for NUMA-local allocation).
 * @capacity: Number of 4KB pages to pre-allocate.
 *
 * Returns 0 on success, -ENOMEM on allocation failure.
 * Uses goto-cleanup for safe partial-failure rollback.
 */
int phantom_cow_pool_init(struct phantom_cow_pool *pool, int cpu, u32 capacity)
{
	int node = cpu_to_node(cpu);
	u32 i;
	int ret;

	if (!capacity)
		return -EINVAL;

	pool->node     = node;
	pool->capacity = capacity;

	/*
	 * Check memory limit before allocating.
	 * Each page = PAGE_SIZE bytes.  Total = capacity * PAGE_SIZE.
	 */
	ret = phantom_memory_reserve((u64)capacity * PAGE_SIZE);
	if (ret) {
		pr_err("phantom: cow_pool: memory limit exceeded "
		       "(capacity=%u pages, %luMB)\n",
		       capacity,
		       (unsigned long)((u64)capacity * PAGE_SIZE >> 20));
		return ret;
	}

	/* Allocate the page pointer array on the heap */
	pool->pages = kvmalloc_array(capacity, sizeof(struct page *),
				     GFP_KERNEL | __GFP_ZERO);
	if (!pool->pages) {
		ret = -ENOMEM;
		goto err_pages_array;
	}

	/* Allocate each page NUMA-locally */
	for (i = 0; i < capacity; i++) {
		pool->pages[i] = alloc_pages_node(node, GFP_KERNEL, 0);
		if (!pool->pages[i]) {
			pr_err("phantom: cow_pool: failed to alloc page %u "
			       "of %u (node %d)\n", i, capacity, node);
			ret = -ENOMEM;
			goto err_pages;
		}
	}

	/*
	 * Initialise the lock-free LIFO head.
	 *
	 * head = capacity: all pages[0..capacity-1] are available.
	 *
	 * Alloc protocol: `idx = atomic_dec_return(&head)` → idx is the
	 * NEW head value (old head minus one).  Return pages[idx].
	 *   - First alloc: head becomes capacity-1, returns pages[capacity-1].
	 *   - Pool empty when idx < 0.
	 *
	 * Free protocol: `idx = atomic_inc_return(&head)` → idx is the
	 * NEW head value (old head plus one).  Write page to pages[idx-1].
	 *   - Writes to the slot that was just made available by the increment.
	 *
	 * This scheme avoids the off-by-one that occurs when head starts at
	 * capacity-1: in that case alloc skips pages[capacity-1] and free
	 * overwrites the original slot at pages[capacity-1], causing a leak
	 * and eventual double-free in phantom_cow_pool_destroy.
	 */
	atomic_set(&pool->head, (int)capacity);

	pr_info("phantom: cow_pool: initialised %u pages (%luMB) "
		"on node %d\n",
		capacity,
		(unsigned long)((u64)capacity * PAGE_SIZE >> 20),
		node);
	return 0;

err_pages:
	for (i = i - 1; (int)i >= 0; i--) {
		__free_page(pool->pages[i]);
		pool->pages[i] = NULL;
	}
	kvfree(pool->pages);
	pool->pages = NULL;
err_pages_array:
	phantom_memory_release((u64)capacity * PAGE_SIZE);
	return ret;
}
EXPORT_SYMBOL_GPL(phantom_cow_pool_init);

/**
 * phantom_cow_pool_destroy - Free all pages and release the pool.
 * @pool: Pool to destroy (NULL-safe, handles partial init).
 */
void phantom_cow_pool_destroy(struct phantom_cow_pool *pool)
{
	u32 i;

	if (!pool || !pool->pages)
		return;

	for (i = 0; i < pool->capacity; i++) {
		if (pool->pages[i]) {
			__free_page(pool->pages[i]);
			pool->pages[i] = NULL;
		}
	}

	phantom_memory_release((u64)pool->capacity * PAGE_SIZE);

	kvfree(pool->pages);
	pool->pages    = NULL;
	pool->capacity = 0;
	atomic_set(&pool->head, -1);
}
EXPORT_SYMBOL_GPL(phantom_cow_pool_destroy);

/* ------------------------------------------------------------------
 * Lock-free LIFO allocation / free
 * ------------------------------------------------------------------ */

/**
 * phantom_cow_pool_alloc - Allocate one page from the pool.
 * @pool: Initialised pool.
 *
 * Lock-free LIFO.  Hot-path: no sleeping, no dynamic allocation.
 * Returns NULL if pool is exhausted.
 */
struct page *phantom_cow_pool_alloc(struct phantom_cow_pool *pool)
{
	int idx;

	idx = atomic_dec_return(&pool->head);
	if (idx < 0) {
		/*
		 * Pool exhausted.  Restore head so subsequent allocs
		 * see the correct (still-zero) count.
		 */
		atomic_inc(&pool->head);
		return NULL;
	}

	return pool->pages[idx];
}
EXPORT_SYMBOL_GPL(phantom_cow_pool_alloc);

/**
 * phantom_cow_pool_free - Return one page to the pool.
 * @pool: Initialised pool.
 * @page: Page previously allocated from this pool.
 *
 * Lock-free.  Hot-path compatible (called from abort_iteration).
 *
 * Protocol: atomic_inc_return returns the NEW head value (old+1).
 * The correct slot to write is pages[new_head - 1] — the slot that
 * was just exposed by the increment.  Writing to pages[new_head]
 * would be off by one and overwrite the next-to-be-allocated slot.
 */
void phantom_cow_pool_free(struct phantom_cow_pool *pool, struct page *page)
{
	int idx;

	idx = atomic_inc_return(&pool->head);
	pool->pages[idx - 1] = page;
}
EXPORT_SYMBOL_GPL(phantom_cow_pool_free);

/* ------------------------------------------------------------------
 * phantom_split_list_free - free all PT pages in split list
 * ------------------------------------------------------------------ */

/**
 * phantom_split_list_free - Free all PT pages in the split list.
 * @sl: Split list to release.
 *
 * Frees each split-allocated PT page and resets count to 0.
 * Called from phantom_vmcs_teardown() on module unload to avoid leaks.
 * Also called from phantom_cow_abort_iteration() after restoring 2MB PDEs.
 *
 * NOT hot-path: called once per iteration end (abort) or once on unload.
 */
void phantom_split_list_free(struct phantom_split_list *sl)
{
	u32 i;

	if (!sl || !sl->count)
		return;

	for (i = 0; i < sl->count; i++) {
		if (sl->entries[i].pt_page) {
			__free_page(sl->entries[i].pt_page);
			sl->entries[i].pt_page = NULL;
		}
	}
	sl->count = 0;
}
EXPORT_SYMBOL_GPL(phantom_split_list_free);

/* ------------------------------------------------------------------
 * phantom_split_2mb_page — split 2MB PD entry into 512 × 4KB PTEs
 *
 * Called from phantom_cow_fault() when a write fault hits a 2MB PD
 * entry (PS=1).  Allocates a new 4KB PT page, populates it with 512
 * RO PTEs pointing to the individual ram_pages, replaces the 2MB PDE
 * with a pointer to the new PT, issues INVEPT, then performs the 4KB
 * CoW for the faulting GPA.
 *
 * Hot-path: called from VM exit handler.
 *   - Uses GFP_ATOMIC for PT page allocation (no sleeping)
 *   - No printk outside PHANTOM_DEBUG
 *   - No mutex_lock()
 * ------------------------------------------------------------------ */

/*
 * split_list_add - record a split entry in the per-state split list.
 *
 * Must be called only from phantom_split_2mb_page (hot path).
 * On overflow: drop the PT page (pr_warn_ratelimited) — this should
 * never happen with PHANTOM_SPLIT_LIST_MAX = 64 and 4 × 2MB regions.
 */
static void split_list_add(struct phantom_split_list *sl,
			   u64 gpa_2mb, struct page *pt_page)
{
	if (sl->count >= PHANTOM_SPLIT_LIST_MAX) {
		/*
		 * Should not happen: 64-entry limit with only 4 × 2MB
		 * regions.  Leak-free: free the page we can't track.
		 */
		pr_warn_ratelimited("phantom: split_list overflow "
				    "(max=%u)\n", PHANTOM_SPLIT_LIST_MAX);
		__free_page(pt_page);
		return;
	}
	sl->entries[sl->count].gpa_2mb  = gpa_2mb;
	sl->entries[sl->count].pt_page  = pt_page;
	sl->count++;
}

/*
 * phantom_cow_4kb_page - perform 4KB CoW for a single faulting GPA.
 *
 * Shared implementation used by both phantom_cow_fault (direct 4KB case)
 * and phantom_split_2mb_page (after splitting).  Caller guarantees the
 * GPA is already covered by a 4KB PTE (no PS=1 in PDE).
 *
 * Returns 0 on success, negative on error (CRASH result set in state).
 * Hot-path: no sleeping, no kmalloc.
 */
static int phantom_cow_4kb_page(struct phantom_vmx_cpu_state *state, u64 gpa)
{
	struct page *priv_page;
	u64 *pte_ptr;
	u64 orig_pte;
	u64 orig_hpa;
	u64 priv_hpa;

	/* Allocate a private page from the pre-allocated pool */
	priv_page = phantom_cow_pool_alloc(&state->cow_pool);
	if (!priv_page) {
		state->run_result = PHANTOM_RESULT_CRASH;
		return -ENOMEM;
	}

	/* Walk EPT to find the leaf 4KB PTE */
	pte_ptr = phantom_ept_lookup_pte(&state->ept, gpa);
	if (!pte_ptr) {
		phantom_cow_pool_free(&state->cow_pool, priv_page);
		state->run_result = PHANTOM_RESULT_CRASH;
		return -EFAULT;
	}

	orig_pte = *pte_ptr;
	orig_hpa = orig_pte & EPT_PTE_HPA_MASK;
	priv_hpa = page_to_phys(priv_page);

	/* Copy original page content to private page */
	memcpy(page_address(priv_page), phys_to_virt(orig_hpa), PAGE_SIZE);

	/* Update EPT PTE: private page with full RWX + WB */
	*pte_ptr = priv_hpa | EPT_PTE_READ | EPT_PTE_WRITE |
		   EPT_PTE_EXEC | EPT_PTE_MEMTYPE_WB;

	/*
	 * Append to dirty list.
	 *
	 * Overflow check: if dirty_count >= dirty_max, increment overflow
	 * counter and signal abort.
	 */
	if (state->dirty_count >= state->dirty_max) {
		state->dirty_overflow_count++;
		phantom_cow_pool_free(&state->cow_pool, priv_page);
		/* Undo the PTE update */
		*pte_ptr = orig_pte;
		state->run_result = PHANTOM_RESULT_CRASH;
		return -ENOSPC;
	}

	{
		struct phantom_dirty_entry *de =
			&state->dirty_list[state->dirty_count];

		de->gpa      = gpa & ~(u64)(PAGE_SIZE - 1);
		de->orig_hpa = orig_hpa;
		de->priv_hpa = priv_hpa;
		de->iter_num = state->cow_iteration;
		state->dirty_count++;
	}

	PHANTOM_TRACE_COW(gpa, priv_hpa);

	/*
	 * NO INVEPT: permission-only change on the faulting PTE.
	 * Intel SDM §28.3.3.1: the EPT violation itself invalidated
	 * the cached translation for the faulting GPA.
	 */
	return 0;
}

/*
 * phantom_split_2mb_page - split a 2MB PD entry into 512 × 4KB PTEs.
 * @state: Per-CPU VMX state.
 * @gpa:   Faulting GPA (within the 2MB region to split).
 *
 * Algorithm:
 *   1. Get pointer to the 2MB PD entry for @gpa.
 *   2. Extract the 2MB-aligned HPA and memory type.
 *   3. Allocate a new 4KB PT page (GFP_ATOMIC — in VM exit context).
 *   4. Populate 512 × 4KB PTEs, each pointing to ram_pages[N] (RO).
 *   5. Replace the 2MB PDE with a non-leaf pointer to the new PT.
 *   6. Track in split list for cleanup at iteration end.
 *   7. Issue INVEPT (structural change — stale 2MB translations).
 *   8. Perform the 4KB CoW for the faulting GPA.
 *
 * Returns 0 on success, negative errno on error.
 * Hot-path: no sleeping, GFP_ATOMIC allocation only.
 */
static int phantom_split_2mb_page(struct phantom_vmx_cpu_state *state,
				  u64 gpa)
{
	u64 *pd_entry;
	u64  orig_pde;
	u64  orig_memtype;
	u64  gpa_2mb_base;
	struct page *pt_page;
	u64 *pt;
	unsigned int i;
	unsigned int first_ram_idx;
	int ret;

	/* Step 1: Get the 2MB PD entry pointer */
	pd_entry = phantom_ept_get_pd_entry(&state->ept, gpa);
	if (!pd_entry) {
		state->run_result = PHANTOM_RESULT_CRASH;
		return -EFAULT;
	}

	orig_pde   = *pd_entry;
	orig_memtype = orig_pde & (7ULL << 3);   /* bits [5:3] */
	gpa_2mb_base = gpa & ~((1ULL << 21) - 1ULL);

	/*
	 * Sanity: must be a large-page entry (PS=1) to split.
	 * If this is already a non-leaf pointer (PS=0), phantom_cow_fault()
	 * should have taken the 4KB path.  Guard defensively.
	 */
	if (!(orig_pde & EPT_PTE_PS)) {
		state->run_result = PHANTOM_RESULT_CRASH;
		return -EINVAL;
	}

	/* Step 2: Allocate a new 4KB PT page (GFP_ATOMIC — VM exit context) */
	pt_page = alloc_page(GFP_ATOMIC | __GFP_ZERO);
	if (!pt_page) {
		state->run_result = PHANTOM_RESULT_CRASH;
		return -ENOMEM;
	}
	pt = (u64 *)page_address(pt_page);

	/*
	 * Step 3: Populate 512 × 4KB RO PTEs.
	 *
	 * Each PTE points to the corresponding individual ram_page.
	 * The 2MB GPA base corresponds to ram_pages starting at index:
	 *   first_ram_idx = (gpa_2mb_base >> PAGE_SHIFT) - PHANTOM_EPT_RAM_BASE >> PAGE_SHIFT
	 *                 = gpa_2mb_base >> PAGE_SHIFT
	 *   (since PHANTOM_EPT_RAM_BASE = 0)
	 *
	 * All 512 PTEs are RO (WRITE=0) so CoW logic fires on writes.
	 */
	first_ram_idx = (unsigned int)(gpa_2mb_base >> PAGE_SHIFT);

	for (i = 0; i < 512; i++) {
		unsigned int ram_idx = first_ram_idx + i;
		u64 hpa;

		if (ram_idx >= PHANTOM_EPT_RAM_PAGES) {
			/* Should not happen within 16MB RAM range */
			break;
		}

		hpa = page_to_phys(state->ept.ram_pages[ram_idx]);
		pt[i] = hpa | EPT_PTE_READ | EPT_PTE_EXEC | orig_memtype;
		/* WRITE intentionally omitted — RO for CoW */
	}

	/* Step 4: Replace 2MB PDE with pointer to new PT (clear PS bit) */
	*pd_entry = page_to_phys(pt_page) | EPT_PERM_RWX;

	/* Step 5: Track in split list for cleanup at iteration end */
	split_list_add(&state->split_list, gpa_2mb_base, pt_page);

#ifdef PHANTOM_DEBUG
	trace_printk("PHANTOM SPLIT_2MB gpa_base=0x%llx new_pt=0x%llx "
		     "first_ram_idx=%u\n",
		     gpa_2mb_base, (u64)page_to_phys(pt_page), first_ram_idx);
#endif

	/*
	 * Step 6: INVEPT required — stale 2MB translations for non-faulting
	 * GPAs in the same 2MB range must be invalidated.
	 * Intel SDM §28.3.3.1: structural EPT change.
	 */
	phantom_invept_single_context(state->ept.eptp);

	/*
	 * Step 7: Perform the actual 4KB CoW fault for the faulting GPA.
	 * After the split, phantom_ept_lookup_pte() will return the new
	 * 4KB PTE.
	 */
	ret = phantom_cow_4kb_page(state, gpa);
	return ret;
}

/* ------------------------------------------------------------------
 * phantom_cow_fault — EPT violation handler (hot path)
 *
 * Called from VMX exit dispatch when exit_reason=48 and the
 * EPT violation qualification indicates a write access to a
 * read-only RAM page (the snapshot condition).
 *
 * Returns 0 → caller does VMRESUME (NO INVEPT for 4KB case).
 * Returns negative → caller stops execution.
 * ------------------------------------------------------------------ */

/**
 * phantom_cow_fault - Handle write fault on read-only snapshot page.
 * @state: Per-CPU VMX state.
 * @gpa:   Faulting GPA from VMCS GUEST_PHYS_ADDR field.
 *
 * Task 1.5: detects 2MB large-page faults (PS=1 in PDE) and delegates
 * to phantom_split_2mb_page() before performing the 4KB CoW.
 *
 * Hot-path: NO printk, NO sleeping, NO GFP_KERNEL allocation.
 * Uses trace_printk under PHANTOM_DEBUG only.
 *
 * Returns 0 on success (caller VMRESUMEs).
 * Returns negative errno on error (caller stops execution).
 */
int phantom_cow_fault(struct phantom_vmx_cpu_state *state, u64 gpa)
{
	const struct phantom_gpa_region *rgn;
	u64 *pd_entry;

	/* Step 1: Classify GPA — only RAM pages are CoW-eligible */
	rgn = phantom_ept_classify_gpa(gpa);
	if (rgn->type != PHANTOM_GPA_RAM) {
		/*
		 * MMIO or reserved GPA write — this is a guest error.
		 * Set CRASH result so the ioctl caller sees the abort.
		 * NO printk here (hot path) — caller logs via VMCS dump.
		 */
		state->run_result = PHANTOM_RESULT_CRASH;
		return -EINVAL;
	}

	/*
	 * Step 2: Check if the fault hit a 2MB large-page PD entry.
	 *
	 * phantom_ept_get_pd_entry() returns the PD entry pointer.
	 * If PS=1, the GPA is covered by a 2MB large page — split it first.
	 * If PS=0 (already a 4KB-level PT pointer), fall through to 4KB CoW.
	 *
	 * The split path handles INVEPT and the subsequent 4KB CoW promotion.
	 */
	pd_entry = phantom_ept_get_pd_entry(&state->ept, gpa);
	if (pd_entry && (*pd_entry & EPT_PTE_PS)) {
		/* 2MB large page — split into 512 × 4KB, then CoW */
		return phantom_split_2mb_page(state, gpa);
	}

	/*
	 * Step 3: 4KB CoW fault (either in 4KB region or after a split).
	 * Delegate to the shared 4KB CoW helper.
	 * NO INVEPT: permission-only change on the faulting PTE.
	 */
	return phantom_cow_4kb_page(state, gpa);
}
EXPORT_SYMBOL_GPL(phantom_cow_fault);

/* ------------------------------------------------------------------
 * phantom_cow_abort_iteration — restore snapshot, issue INVEPT
 * ------------------------------------------------------------------ */

/**
 * phantom_cow_abort_iteration - Reset all dirty pages to snapshot state.
 * @state: Per-CPU VMX state.
 *
 * Called at end-of-iteration.  Not a hot-path (once per iteration).
 *
 * For each dirty list entry:
 *   - Reset EPT PTE to orig_hpa | READ | EXEC | WB (write-protected).
 *   - Return private page to pool.
 *
 * For each split list entry (2MB→4KB splits done this iteration):
 *   - Restore the 2MB PDE with orig 2MB HPA | READ | EXEC | WB | PS.
 *   - Free the split PT page.
 *
 * Then: reset dirty_count = 0, split_list.count = 0, issue one batched
 * INVEPT (single-context) after ALL changes.
 */
void phantom_cow_abort_iteration(struct phantom_vmx_cpu_state *state)
{
	u32 i;

	if (!state->dirty_list || !state->dirty_count)
		goto restore_splits;

	for (i = 0; i < state->dirty_count; i++) {
		struct phantom_dirty_entry *de = &state->dirty_list[i];
		u64 *pte_ptr;

		pte_ptr = phantom_ept_lookup_pte(&state->ept, de->gpa);
		if (pte_ptr) {
			/*
			 * Restore PTE to original HPA with RO permissions.
			 * EXEC is kept so the guest can still execute pages
			 * that are in the snapshot.
			 */
			*pte_ptr = de->orig_hpa | EPT_PTE_READ |
				   EPT_PTE_EXEC | EPT_PTE_MEMTYPE_WB;
		}

		/*
		 * Return private page to pool.
		 * page_to_phys → struct page lookup via pfn.
		 */
		{
			struct page *pg = pfn_to_page(
				de->priv_hpa >> PAGE_SHIFT);
			phantom_cow_pool_free(&state->cow_pool, pg);
		}
	}

	PHANTOM_TRACE_SNAPSHOT(state->cpu, state->dirty_count);
	state->dirty_count = 0;

restore_splits:
	/*
	 * Restore 2MB PD entries for any regions that were split this iter.
	 *
	 * For each split entry, we need to:
	 *   1. Rewrite the PDE with a 2MB large-page entry pointing to the
	 *      original 2MB-aligned HPA of the first backing page, RO+WB+PS.
	 *   2. Free the split PT page.
	 *
	 * The original 2MB HPA: since phantom_ept_build() set the PDE HPA
	 * from the first ram_page in the 2MB region, and we know the
	 * gpa_2mb_base, we can recover the HPA from ept.ram_pages[].
	 *
	 * ram_pages index of first page in region = gpa_2mb_base >> PAGE_SHIFT
	 * (since PHANTOM_EPT_RAM_BASE = 0)
	 */
	for (i = 0; i < state->split_list.count; i++) {
		struct phantom_split_entry *se = &state->split_list.entries[i];
		u64 *pd_entry;
		unsigned int block_idx;
		u64 hpa_2mb;

		pd_entry = phantom_ept_get_pd_entry(&state->ept, se->gpa_2mb);
		if (!pd_entry)
			goto free_split_page;

		/*
		 * Recover the 2MB HPA from ram_2mb_blocks[].
		 *
		 * block_idx = which 2MB region this GPA falls in.
		 * gpa_2mb >> 21 gives the PD index = block index.
		 */
		block_idx = (unsigned int)(se->gpa_2mb >> 21);
		if (block_idx >= PHANTOM_EPT_NR_2MB_ENTRIES)
			goto free_split_page;

		hpa_2mb = page_to_phys(state->ept.ram_2mb_blocks[block_idx]);

		/*
		 * Restore 2MB PDE: READ | EXEC | WB | PS (WRITE cleared —
		 * snapshot is RO, ready for next iteration's CoW faults).
		 */
		*pd_entry = hpa_2mb | EPT_PTE_READ | EPT_PTE_EXEC |
			    EPT_PTE_MEMTYPE_WB | EPT_PTE_PS;

free_split_page:
		if (se->pt_page) {
			__free_page(se->pt_page);
			se->pt_page = NULL;
		}
	}
	state->split_list.count = 0;

	/*
	 * Issue one batched INVEPT (single-context) after ALL PTE resets and
	 * 2MB PDE restorations.
	 *
	 * Required by Intel SDM §28.3.3.1:
	 *   - RW→RO resets (dirty list restore) are structural changes
	 *   - 4KB PT→2MB large-page PDE swaps (split restore) are structural
	 * Both require INVEPT before next VMRESUME.
	 */
	if (state->ept.eptp)
		phantom_invept_single_context(state->ept.eptp);
}
EXPORT_SYMBOL_GPL(phantom_cow_abort_iteration);
