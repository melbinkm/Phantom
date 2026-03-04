// SPDX-License-Identifier: GPL-2.0-only
/*
 * ept_cow.h — CoW page pool, dirty list, and fault handler declarations
 *
 * The CoW engine supports snapshot-based fuzzing iterations:
 *   1. At snapshot time, all RAM EPT entries are marked read-only.
 *   2. When the guest writes to a page, an EPT violation (exit 48) fires.
 *   3. phantom_cow_fault() allocates a private page, copies the original,
 *      updates the EPT PTE to RW, and records the entry in the dirty list.
 *   4. At end-of-iteration, phantom_cow_abort_iteration() resets all dirty
 *      PTEs to the original HPA (RO), returns pages to pool, issues INVEPT.
 *
 * INVEPT rules (Intel SDM §28.3.3.1):
 *   - 4KB RO→RW CoW fault:          NO INVEPT (EPT violation invalidated GPA)
 *   - snapshot restore (abort_iter): YES, one batched INVEPT (single-context)
 *
 * Hot-path discipline: phantom_cow_fault() MUST NOT call printk, kmalloc,
 * schedule(), or mutex_lock().  All resources are pre-allocated at pool init.
 */
#ifndef PHANTOM_EPT_COW_H
#define PHANTOM_EPT_COW_H

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/atomic.h>

/* ------------------------------------------------------------------
 * Dirty list entry: one entry per CoW-promoted page per iteration.
 * ------------------------------------------------------------------ */
struct phantom_dirty_entry {
	u64	gpa;		/* faulting guest physical address        */
	u64	orig_hpa;	/* original host physical page address    */
	u64	priv_hpa;	/* private copy host physical address     */
	u32	iter_num;	/* fuzzing iteration when fault occurred  */
};

/* ------------------------------------------------------------------
 * CoW page pool: lock-free LIFO pre-allocated private pages.
 *
 * head: atomic index into pages[].  alloc decrements, free increments.
 * capacity: total pages in pool.
 * node: NUMA node for allocation (cpu_to_node(cpu)).
 *
 * Lock-free LIFO protocol:
 *   alloc: idx = atomic_dec_return(&pool->head)
 *          if idx < 0 → restore head, return NULL (pool exhausted)
 *   free:  pages[atomic_inc_return(&pool->head)] = page
 *          (valid because we only free pages that were allocated)
 * ------------------------------------------------------------------ */
struct phantom_cow_pool {
	struct page	**pages;	/* pre-allocated page pointers  */
	atomic_t	  head;		/* lock-free LIFO head index    */
	u32		  capacity;	/* total pages in pool          */
	int		  node;		/* NUMA node                    */
};

/* Default pool capacity (number of 4KB pages).
 * 4096 pages = 16MB — covers ~50-page dirty sets with large headroom.
 */
#define PHANTOM_COW_POOL_DEFAULT_CAPACITY	4096U

/* ------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------ */
struct phantom_vmx_cpu_state;

/* ------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------ */

/**
 * phantom_cow_pool_init - Allocate and initialise the CoW page pool.
 * @pool:     Pool to initialise.
 * @cpu:      Physical CPU (for NUMA-local allocation).
 * @capacity: Number of pages to pre-allocate.
 *
 * Allocates capacity pages via alloc_pages_node(cpu_to_node(cpu), ...)
 * Must be called from process context (GFP_KERNEL).
 * Returns 0 on success, negative errno on failure (goto-cleanup safe).
 */
int phantom_cow_pool_init(struct phantom_cow_pool *pool, int cpu,
			  u32 capacity);

/**
 * phantom_cow_pool_destroy - Free all pages and release the pool.
 * @pool: Pool to destroy.
 *
 * NULL-safe: safe to call if init partially failed.
 */
void phantom_cow_pool_destroy(struct phantom_cow_pool *pool);

/**
 * phantom_cow_pool_alloc - Allocate one page from the pool (hot path).
 * @pool: Initialised pool.
 *
 * Lock-free.  Returns NULL if pool is exhausted.
 * Called from VM exit handler — NO sleeping, NO dynamic allocation.
 */
struct page *phantom_cow_pool_alloc(struct phantom_cow_pool *pool);

/**
 * phantom_cow_pool_free - Return one page to the pool (hot path).
 * @pool: Initialised pool.
 * @page: Page to return (must have been allocated from this pool).
 *
 * Lock-free.  Called from abort_iteration — NO sleeping.
 */
void phantom_cow_pool_free(struct phantom_cow_pool *pool, struct page *page);

/**
 * phantom_cow_fault - Handle EPT violation on a read-only RAM page.
 * @state: Per-CPU VMX state.
 * @gpa:   Faulting guest physical address (from VMCS GUEST_PHYS_ADDR).
 *
 * Algorithm:
 *   1. Classify GPA — if not RAM, set run_result=CRASH, return -EINVAL.
 *   2. Alloc private page from pool — if NULL, set run_result=ABORT.
 *   3. Walk EPT to get orig PTE + orig_hpa.
 *   4. memcpy original page → private page.
 *   5. Update EPT PTE: priv_hpa | RWX | WB.
 *   6. Append to dirty list (check dirty_count < dirty_max).
 *   7. Return 0 — caller does VMRESUME, NO INVEPT.
 *
 * Hot-path: no printk, no sleeping, no kmalloc.
 * Returns 0 on success (caller VMRESUMEs), negative errno on error.
 */
int phantom_cow_fault(struct phantom_vmx_cpu_state *state, u64 gpa);

/**
 * phantom_cow_abort_iteration - Reset all dirty pages to snapshot state.
 * @state: Per-CPU VMX state.
 *
 * For each dirty list entry:
 *   - Reset EPT PTE to orig_hpa | READ | EXEC | WB (write-protected).
 *   - Return private page to pool.
 * Then: dirty_count = 0, issue one batched INVEPT (single-context).
 *
 * Called at end of each fuzzing iteration.  NOT a hot-path (called once
 * per iteration, not per fault).  May use pr_err for error reporting.
 */
void phantom_cow_abort_iteration(struct phantom_vmx_cpu_state *state);

#endif /* PHANTOM_EPT_COW_H */
