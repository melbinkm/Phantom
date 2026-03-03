# Task 1.4: First CoW Fault + Page Pool

> **Phase:** VMX Bootstrap + Basic EPT | **Week(s):** 6 | **Depends on:** [Task 1.3](task-1.3-basic-rw-ept.md)

## Objective

Implement the first CoW fault handler and pre-allocated page pool. Guest writes to read-only RAM pages should allocate private copies, populate the dirty list, and resume execution — no INVEPT on 4KB permission-only changes.

## What to Build

- Mark all guest EPT pages read-only (snapshot prototype — just the permission change, no VMCS save yet)
- CoW page pool: pre-allocate pool at module init (configurable, default Class A: 4096 pages, Class B: 16384 pages), allocated via `alloc_pages_node(node, GFP_KERNEL, 0)` for NUMA-local allocation (see Section 7), lock-free per-CPU free list for fast allocation, pool exhaustion → abort current iteration gracefully (not host panic)
- CoW fault handler (basic): on write to read-only RAM EPT page — (1) allocate private page from pool, (2) `memcpy` original page → private page, (3) update EPT entry to point to private page with RW and WB memory type, (4) append to dirty list, (5) resume guest — do NOT issue INVEPT here (per Section 2.3 INVEPT batching); reject CoW on MMIO pages (log error, abort iteration)
- Dirty list inspector (`debug.c`): debug ioctl returning current dirty list (GPA, original HPA, private HPA, iteration number)

## Implementation Guidance

### CoW Algorithm (Complete)

```c
static int phantom_cow_fault(struct phantom_instance *inst, u64 gpa)
{
    struct page *private_page;
    u64 orig_hpa, private_hpa;
    u64 *ept_pte;

    /* Step 1: Classify GPA — reject MMIO */
    if (classify_gpa(inst, gpa) != GPA_TYPE_RAM) {
        pr_err("phantom: CoW on non-RAM GPA 0x%llx — aborting\n", gpa);
        inst->run_result = PHANTOM_RESULT_CRASH;
        return -EINVAL;
    }

    /* Step 2: Allocate private page from pool (lock-free per-CPU list) */
    private_page = phantom_pool_alloc(inst);
    if (!private_page) {
        /* Pool exhaustion — abort iteration gracefully */
        inst->run_result_error = PHANTOM_ERROR_POOL_EXHAUSTED;
        phantom_abort_iteration(inst);  /* Walk dirty list, return pages to pool */
        return -ENOMEM;
    }

    /* Step 3: memcpy original → private */
    ept_pte = phantom_ept_walk(inst, gpa, 4 /*4KB level*/);
    orig_hpa = *ept_pte & ~0xFFF & EPT_PTE_HPA_MASK;
    memcpy(page_address(private_page), phys_to_virt(orig_hpa), PAGE_SIZE);
    private_hpa = page_to_phys(private_page);

    /* Step 4: Update EPT entry → private page with RW + WB */
    *ept_pte = private_hpa | EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_EXEC
                           | EPT_PTE_MEMTYPE_WB;

    /* Step 5: Append to dirty list */
    if (inst->dirty_count >= inst->dirty_max) {
        inst->debugfs_dirty_overflow++;
        phantom_abort_iteration(inst);
        return -ENOSPC;  /* Returns PHANTOM_ERROR_DIRTY_OVERFLOW */
    }
    inst->dirty_list[inst->dirty_count++] = (struct dirty_entry){
        .gpa      = gpa,
        .orig_hpa = orig_hpa,
        .priv_hpa = private_hpa,
        .iter_num = inst->iteration,
    };

    /*
     * Step 6: NO INVEPT here.
     * Per §2.3 INVEPT batching: 4KB RO→RW is a permission-only change.
     * The EPT violation itself invalidated the faulting GPA's cached
     * translation (Intel SDM §28.3.3.1). Just update the PTE and VMRESUME.
     */
    return 0;  /* Caller does VMRESUME */
}
```

### INVEPT Batching Rules (Critical)

**SDM guarantee (§28.3.3.1):** An EPT violation invalidates cached translations for the *faulting* GPA only.

| Operation | INVEPT Required? | Why |
|-----------|-----------------|-----|
| 4KB RO→RW CoW fault | **NO** | EPT violation invalidated faulting GPA; permission-only change |
| 2MB→4KB structural split | **YES** | Non-faulting GPAs in same 2MB range may have stale cached 2MB translations |
| Snapshot restore (end of iteration) | **YES (one, batched)** | Single INVEPT after all dirty-list entries reset |

### CoW Page Pool Implementation

```c
/* Pool sizing formulas */
/* Class A: 50 pages × 4KB = 200KB minimum; default 16MB (4096 pages) */
/* Class B: 2000 pages × 4KB = 8MB minimum; default 64MB (16384 pages) */

struct phantom_pool {
    struct page **pages;    /* Array of pre-allocated page pointers    */
    atomic_t     head;      /* Lock-free LIFO head index               */
    u32          capacity;  /* Total pages in pool                     */
    u32          numa_node; /* NUMA node for allocation                */
};

static struct page *phantom_pool_alloc(struct phantom_instance *inst)
{
    struct phantom_pool *pool = &inst->cow_pool;
    int idx = atomic_dec_return(&pool->head);
    if (idx < 0) {
        atomic_inc(&pool->head);  /* Restore */
        return NULL;              /* Pool exhausted */
    }
    return pool->pages[idx];
}

static void phantom_pool_free(struct phantom_pool *pool, struct page *page)
{
    int idx = atomic_inc_return(&pool->head) - 1;
    pool->pages[idx] = page;
}
```

### Pool Sizing and NUMA Allocation

From §4.3 and §7:

```c
static int phantom_pool_init(struct phantom_instance *inst, int cpu, u32 capacity)
{
    int node = cpu_to_node(cpu);  /* NUMA-local allocation */

    inst->cow_pool.pages = kvmalloc_array(capacity, sizeof(struct page *),
                                           GFP_KERNEL);
    for (u32 i = 0; i < capacity; i++) {
        inst->cow_pool.pages[i] = alloc_pages_node(node, GFP_KERNEL, 0);
        if (!inst->cow_pool.pages[i]) {
            phantom_pool_destroy(inst, i);
            return -ENOMEM;
        }
    }
    atomic_set(&inst->cow_pool.head, capacity);
    inst->cow_pool.capacity = capacity;
    inst->cow_pool.numa_node = node;
    return 0;
}
```

### Pool Exhaustion → Graceful Abort

On pool exhaustion, perform cleanup without host panic:

```c
static void phantom_abort_iteration(struct phantom_instance *inst)
{
    /* Walk dirty list — reset EPT mappings, return private pages to pool */
    for (u32 i = 0; i < inst->dirty_count; i++) {
        struct dirty_entry *e = &inst->dirty_list[i];
        u64 *pte = phantom_ept_walk(inst, e->gpa, 4);
        /* Reset to original HPA, read-only */
        *pte = e->orig_hpa | EPT_PTE_READ | EPT_PTE_EXEC | EPT_PTE_MEMTYPE_WB;
        phantom_pool_free(&inst->cow_pool, phys_to_page(e->priv_hpa));
    }
    inst->dirty_count = 0;
    /* Single INVEPT after all EPT updates complete */
    phantom_invept_single_context(inst->eptp);
}
```

### Memory Accounting

From §6.8 — all allocations tracked via atomic counter:

```c
/* Global allocation tracker */
atomic64_t phantom_allocated_bytes;

/* On every allocation: */
atomic64_add(size, &phantom_allocated_bytes);

/* On new instance creation — enforce max_memory_mb */
if (atomic64_read(&phantom_allocated_bytes) + new_size > max_memory_mb * 1024 * 1024) {
    pr_err("phantom: memory limit exceeded\n");
    return -ENOMEM;
}
```

### Dirty List Inspector (debug.c)

Debug ioctl `PHANTOM_DEBUG_DUMP_DIRTY_LIST`:
- Returns current dirty list contents: GPA, original HPA, private HPA, iteration number
- Available mid-iteration (for debugging runaway dirty sets) and post-iteration
- Output to debugfs file `/sys/kernel/debug/phantom/instance_N/dirty_list`

## Key Data Structures

```c
/* Dirty list entry */
struct dirty_entry {
    u64  gpa;       /* Guest physical address of CoW'd page            */
    u64  orig_hpa;  /* Original host physical address (read-only)      */
    u64  priv_hpa;  /* Private host physical address (read-write copy) */
    u64  iter_num;  /* Iteration number when this page was CoW'd       */
};

/* Per-instance state */
struct phantom_instance {
    struct phantom_pool  cow_pool;       /* Pre-allocated private pages  */
    struct dirty_entry  *dirty_list;     /* Per-iteration dirty tracking */
    u32                  dirty_count;    /* Current dirty entry count    */
    u32                  dirty_max;      /* Max entries (default 4096)   */
    u64                  debugfs_dirty_overflow; /* Overflow counter     */
    u64                  iteration;      /* Current iteration number     */
    /* ... */
};

/* Per-instance memory formula (Class B example) from §4.3:
 * guest_mem: 256MB  (alloc_pages_node)
 * cow_pool:   64MB  (16384 × 4KB pages, alloc_pages_node)
 * topa:       16MB  (2 × 8MB double-buffer)
 * ept_tables:  2MB  (~512 page tables for 256MB guest)
 * vmcs:        4KB
 * xsave_area:  4KB
 * Total:    ~338MB per Class B instance
 * 16 cores: ~5.4GB — plan for 8GB reserved on 64GB machine
 */
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/ept_cow.c` | CoW fault handler, page pool, dirty list management |
| `kernel/ept.c` | EPT permission changes (RO marking), INVEPT batching |
| `kernel/debug.c` | `PHANTOM_DEBUG_DUMP_DIRTY_LIST` ioctl |
| `kernel/memory.c` | Global memory accounting, max_memory_mb enforcement |

## Reference Sections

- §2.3: CoW algorithm full — complete snapshot/fault/restore flow, INVEPT batching rules
- §4.3: Pool sizing formulas — Class A 4096 pages (16MB), Class B 16384 pages (64MB), per-instance formula
- §6.8: Memory accounting — atomic counter, `__GFP_ACCOUNT` flag, debugfs exposure
- §7: NUMA allocation strategy — `alloc_pages_node(cpu_to_node(cpu))`, 40–80ns remote penalty
- §5.5 Appendix A §3: Resource errors — pool exhaustion recovery, dirty list overflow handling
- §5.6 Appendix B §3: Dirty list inspector — debugfs format, mid-iteration availability

## Tests to Run

- Guest writes to 20 pages produce exactly 20 dirty list entries (pass = dirty list count matches write count, all GPAs present)
- Private pages contain the correct written data (pass = private page contents match guest-written values)
- MMIO CoW attempt is rejected with a logged error and iteration aborted (pass = no private page allocated for MMIO GPA, abort confirmed)
- Pool exhaustion: 5-page pool with a 10-write guest aborts gracefully without host panic (pass = `PHANTOM_ERROR_POOL_EXHAUSTED` returned, no kernel oops)

## Deliverables

First CoW fault handled correctly; dirty list populated; private pages contain correct data.

## Exit Criteria

**Phase 1a exit criteria:** module loads/unloads cleanly on all designated cores; guest executes trivial code and communicates via VMCALL; basic R/W EPT with correct MMIO/RAM/reserved classification; CoW fault handler allocates private pages and tracks dirty list; serial console and kdump verified working before any EPT CoW code.
