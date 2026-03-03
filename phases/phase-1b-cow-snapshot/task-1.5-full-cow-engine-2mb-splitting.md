# Task 1.5: Full CoW Engine with 2MB Splitting

> **Phase:** CoW Engine + Snapshot/Restore | **Week(s):** 7–8 | **Depends on:** [Task 1.4](../phase-1a-vmx-bootstrap/task-1.4-first-cow-fault-page-pool.md)

## Objective

Extend the basic CoW handler to correctly handle 2MB EPT large-page entries by splitting them into 512 × 4KB PTEs on first CoW fault, issuing INVEPT only on structural changes, and maintaining a per-instance split-page list.

## What to Build

- 2MB page splitting: when a CoW fault hits a 2MB EPT entry, split to 512 × 4KB EPT PTEs; only the faulting 4KB page gets a private copy; issue single-context INVEPT before VMRESUME after any 2MB→4KB split (stale cached 2MB translations for non-faulting GPAs in the same range must be invalidated, per INVEPT batching strategy in §2.3); track split pages in per-instance split-page list for potential re-coalescing
- Dirty list: per-instance fixed-size array (max 4096 entries initially, configurable); each entry: guest physical address, pointer to private page, pointer to original EPT entry, iteration number; overflow → abort iteration, log warning, expose overflow count via debugfs

## Implementation Guidance

### 2MB Splitting: 4-Step Procedure

When a CoW fault occurs on a GPA covered by a 2MB EPT large-page entry:

```c
static int phantom_split_2mb_page(struct phantom_instance *inst, u64 gpa)
{
    u64 *pd_entry = phantom_ept_walk(inst, gpa, 2 /* PD level */);
    u64  large_hpa = *pd_entry & ~((1ULL << 21) - 1);  /* 2MB-aligned HPA */
    u64  orig_memtype = *pd_entry & EPT_PTE_MEMTYPE;
    struct page *pt_page;
    u64 *pt;

    /* Step 1: Allocate 4KB-level EPT PT */
    pt_page = alloc_page(GFP_ATOMIC | __GFP_ZERO);
    if (!pt_page) return -ENOMEM;
    pt = page_address(pt_page);

    /* Step 2: Populate 512 × 4KB PTEs by splitting the 2MB mapping */
    for (int i = 0; i < 512; i++) {
        u64 hpa_4k = large_hpa + (u64)i * PAGE_SIZE;
        pt[i] = hpa_4k | EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_EXEC
                        | orig_memtype;
        /* All 512 pages start read-only if this is a snapshot-protected range */
        if (inst->snapshot_taken)
            pt[i] &= ~EPT_PTE_WRITE;
    }

    /* Step 3: Insert new 4KB-level PT into EPT PD (clear PS bit, set PT HPA) */
    *pd_entry = page_to_phys(pt_page) | EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_EXEC;
    /* PS (large page) bit is now clear — points to next-level PT instead */

    /* Step 4: Track in split-page list for potential re-coalescing */
    phantom_split_list_add(inst, gpa & ~((1ULL << 21) - 1), pt_page);

    /*
     * INVEPT IS REQUIRED here before VMRESUME.
     * Non-faulting GPAs in the same 2MB range may have stale cached
     * 2MB translations pointing to the old large-page frame.
     * Issue single-context INVEPT (type 1) after completing the split.
     */
    phantom_invept_single_context(inst->eptp);

    /* Now handle the actual CoW fault for the faulting 4KB page */
    return phantom_cow_4kb_page(inst, gpa);
}
```

### INVEPT Batching Rules (Definitive Reference)

| Operation | INVEPT Required? | Rationale |
|-----------|-----------------|-----------|
| 4KB RO→RW CoW fault (permission-only) | **NO** | EPT violation invalidated faulting GPA per SDM §28.3.3.1 |
| 2MB→4KB structural split | **YES (before VMRESUME)** | Non-faulting GPAs in 2MB range may have stale 2MB cached translations |
| Snapshot restore (end of iteration) | **YES (single, batched)** | All dirty-list EPT updates batched; one INVEPT after all |

**Formal invariant:** Every EPT structural change (page-table level insertion or removal) requires INVEPT before the next VMRESUME. Permission-only changes to the faulting PTE do not require INVEPT.

**Alternative considered and rejected:** `INVVPID` type 3 (all-context) — rejected due to cross-core overhead. Single-context INVEPT (type 1) is sufficient because Phantom uses per-instance EPT pointers and cores are not sharing EPT structures.

### Dirty List Structure

```c
/* Per-instance dirty list entry */
struct dirty_entry {
    u64  gpa;          /* Guest physical address of CoW'd page           */
    u64  orig_hpa;     /* Original HPA (the snapshot page)              */
    u64  priv_hpa;     /* Private HPA (the CoW copy)                    */
    u64  iter_num;     /* Iteration number                              */
};

/* Dirty list config */
#define DIRTY_LIST_DEFAULT_MAX  4096   /* Initial max; configurable          */

struct phantom_dirty_list {
    struct dirty_entry *entries;
    u32                 count;       /* Current entries                   */
    u32                 max;         /* Configured maximum                */
    u64                 overflow_count; /* Exposed via debugfs            */
};
```

### Dirty List Overflow → Graceful Abort

```c
static int phantom_dirty_list_append(struct phantom_instance *inst,
                                      u64 gpa, u64 orig_hpa, u64 priv_hpa)
{
    if (inst->dirty.count >= inst->dirty.max) {
        inst->dirty.overflow_count++;
        pr_warn_ratelimited("phantom: dirty list overflow at iter %llu\n",
                            inst->iteration);
        phantom_abort_iteration(inst);  /* Clean up, return pages to pool */
        return -ENOSPC;                 /* Returns PHANTOM_ERROR_DIRTY_OVERFLOW */
    }
    inst->dirty.entries[inst->dirty.count++] = (struct dirty_entry){
        .gpa      = gpa,
        .orig_hpa = orig_hpa,
        .priv_hpa = priv_hpa,
        .iter_num = inst->iteration,
    };
    return 0;
}
```

## Key Data Structures

```c
/* Split-page tracking */
struct split_page_entry {
    u64          gpa_2mb_aligned;   /* Start GPA of the split 2MB region */
    struct page *pt_page;            /* The 4KB EPT PT page we allocated  */
};

struct phantom_split_list {
    struct split_page_entry *entries;
    u32                      count;
    u32                      max;
};
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/ept_cow.c` | 2MB splitting procedure, split-page list management |
| `kernel/ept.c` | INVEPT batching logic, structural change tracking |
| `kernel/debug.c` | Dirty list overflow counter exposed via debugfs |

## Reference Sections

- §2.3: 2MB splitting 4-step procedure — detailed algorithm with PT allocation and PD entry update
- §2.3: INVEPT batching rules — SDM §28.3.3.1 guarantee, when INVEPT is/is not required

## Tests to Run

- CoW fault on a 2MB EPT entry produces exactly 512 PTEs in the page table, with only 1 private page allocated (pass = EPT walker confirms 512 4KB entries, dirty list has 1 entry)
- INVEPT is logged after the structural 2MB→4KB split (pass = trace log shows INVEPT event before VMRESUME)
- 200+ CoW faults across both 4KB and 2MB pages in a mixed workload complete without memory corruption (pass = all private page contents correct)
- Dirty list overflow: reduce max entries to force overflow, verify iteration aborts gracefully and debugfs counter increments (pass = no host panic, counter incremented by 1)
- 100 snapshot/restore iterations with 2MB splits show no memory leaks (pass = KMEMLEAK reports zero warnings)

## Deliverables

Full CoW engine handling both 4KB and 2MB pages; INVEPT issued only on structural EPT changes (2MB splits), not on every 4KB CoW fault.
