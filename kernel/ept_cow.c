// SPDX-License-Identifier: GPL-2.0-only
/*
 * ept_cow.c — CoW page pool, dirty list, and EPT fault handler
 *
 * Implements the Copy-on-Write snapshot engine for phantom.ko:
 *
 *   phantom_cow_pool_init/destroy — pre-allocate private pages (NUMA-local)
 *   phantom_cow_pool_alloc/free   — lock-free LIFO allocation
 *   phantom_cow_fault             — EPT violation handler (hot path)
 *   phantom_cow_abort_iteration   — restore snapshot state at end-of-iter
 *
 * INVEPT rules enforced here (Intel SDM §28.3.3.1):
 *   - phantom_cow_fault:          NO INVEPT (permission-only change,
 *                                  EPT violation itself invalidated GPA)
 *   - phantom_cow_abort_iteration: YES, one batched INVEPT (single-context)
 *                                  after ALL PTEs are reset
 *
 * Hot-path discipline (phantom_cow_fault):
 *   - No printk, no pr_*, no trace_printk outside PHANTOM_DEBUG
 *   - No kmalloc(GFP_KERNEL), no schedule(), no mutex_lock()
 *   - All resources pre-allocated at pool init time
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

/* ------------------------------------------------------------------
 * INVEPT helper (single-context, type 1)
 *
 * Used only in phantom_cow_abort_iteration (slow path — once per iter).
 * NOT in phantom_cow_fault (permission-only change — no INVEPT needed).
 * ------------------------------------------------------------------ */

struct phantom_cow_invept_desc {
	u64 eptp;
	u64 rsvd;
} __packed;

static inline void cow_invept_single(u64 eptp)
{
	struct phantom_cow_invept_desc desc = { .eptp = eptp, .rsvd = 0 };

	asm volatile("invept %0, %1"
		     :: "m"(desc), "r"((u64)1)   /* type 1 = single-context */
		     : "cc", "memory");
}

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
 * phantom_cow_fault — EPT violation handler (hot path)
 *
 * Called from VMX exit dispatch when exit_reason=48 and the
 * EPT violation qualification indicates a write access to a
 * read-only RAM page (the snapshot condition).
 *
 * Returns 0 → caller does VMRESUME (NO INVEPT).
 * Returns negative → caller stops execution.
 * ------------------------------------------------------------------ */

/**
 * phantom_cow_fault - Handle write fault on read-only snapshot page.
 * @state: Per-CPU VMX state.
 * @gpa:   Faulting GPA from VMCS GUEST_PHYS_ADDR field.
 *
 * Hot-path: NO printk, NO sleeping, NO kmalloc.
 * Uses trace_printk under PHANTOM_DEBUG only.
 */
int phantom_cow_fault(struct phantom_vmx_cpu_state *state, u64 gpa)
{
	const struct phantom_gpa_region *rgn;
	struct page *priv_page;
	u64 *pte_ptr;
	u64 orig_pte;
	u64 orig_hpa;
	u64 priv_hpa;

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

	/* Step 2: Allocate a private page from the pre-allocated pool */
	priv_page = phantom_cow_pool_alloc(&state->cow_pool);
	if (!priv_page) {
		/*
		 * Pool exhausted.  Abort iteration — snapshot will be
		 * restored by the ioctl handler after we return.
		 */
		state->run_result = PHANTOM_RESULT_CRASH;
		return -ENOMEM;
	}

	/* Step 3: Walk EPT to find the leaf PTE for this GPA */
	pte_ptr = phantom_ept_lookup_pte(&state->ept, gpa);
	if (!pte_ptr) {
		/*
		 * PTE not found — GPA is in the RAM region but has no EPT
		 * mapping.  This should not happen if the EPT is correctly
		 * built; treat as a fatal error.
		 */
		phantom_cow_pool_free(&state->cow_pool, priv_page);
		state->run_result = PHANTOM_RESULT_CRASH;
		return -EFAULT;
	}

	orig_pte = *pte_ptr;
	orig_hpa = orig_pte & EPT_PTE_HPA_MASK;
	priv_hpa = page_to_phys(priv_page);

	/* Step 4: Copy original page content to private page */
	memcpy(page_address(priv_page), phys_to_virt(orig_hpa), PAGE_SIZE);

	/* Step 5: Update EPT PTE — private page with full RWX + WB */
	*pte_ptr = priv_hpa | EPT_PTE_READ | EPT_PTE_WRITE |
		   EPT_PTE_EXEC | EPT_PTE_MEMTYPE_WB;

	/*
	 * Step 6: Append to dirty list.
	 *
	 * Check capacity first.  dirty_max == cow_pool.capacity so they
	 * are always consistent.  If the dirty list is full but the pool
	 * still has pages, we have a logic error — guard it.
	 */
	if (state->dirty_count < state->dirty_max) {
		struct phantom_dirty_entry *de =
			&state->dirty_list[state->dirty_count];

		de->gpa      = gpa & ~(u64)(PAGE_SIZE - 1);
		de->orig_hpa = orig_hpa;
		de->priv_hpa = priv_hpa;
		de->iter_num = state->cow_iteration;
		state->dirty_count++;
	}
	/* else: silent — pool ran out at same time as dirty list */

	PHANTOM_TRACE_COW(gpa, priv_hpa);

	/*
	 * Step 7: Return 0 — caller does VMRESUME.
	 * NO INVEPT: permission-only change on the faulting PTE.
	 * Intel SDM §28.3.3.1: the EPT violation itself invalidated
	 * the cached translation for the faulting GPA.
	 */
	return 0;
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
 * For each dirty entry:
 *   - Reset EPT PTE to orig_hpa | READ | EXEC | WB (write-protected).
 *   - Return private page to pool.
 * Then: reset dirty_count, issue one batched INVEPT (single-context).
 */
void phantom_cow_abort_iteration(struct phantom_vmx_cpu_state *state)
{
	u32 i;

	if (!state->dirty_list || !state->dirty_count)
		goto do_invept;

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

do_invept:
	/*
	 * Issue one batched INVEPT (single-context) after ALL PTE resets.
	 * Required by Intel SDM §28.3.3.1: structural EPT changes (all
	 * RW→RO resets) must be followed by INVEPT before next VMRESUME.
	 *
	 * We use single-context INVEPT (type 1) to avoid cross-core TLB
	 * invalidation overhead of all-context INVEPT (type 2).
	 */
	if (state->ept.eptp)
		cow_invept_single(state->ept.eptp);
}
EXPORT_SYMBOL_GPL(phantom_cow_abort_iteration);
