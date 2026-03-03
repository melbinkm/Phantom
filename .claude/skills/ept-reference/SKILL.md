---
name: ept-reference
description: EPT and CoW snapshot reference for Phantom. Auto-load when writing EPT page table code, CoW fault handlers, snapshot/restore, or INVEPT.
user-invocable: false
disable-model-invocation: false
---

# EPT and CoW Snapshot Reference for Phantom

## EPT 4-Level Structure

```
Guest Physical Address (GPA) → EPT Walk → Host Physical Address (HPA)

GPA bits: [47:39] PML4 | [38:30] PDPT | [29:21] PD | [20:12] PT | [11:0] offset

EPT PML4 (512 entries × 8B = 4KB page)
  └── EPT PDPT (512 entries × 8B = 4KB page)
        └── EPT PD (512 entries × 8B = 4KB page)
              ├── 2MB large page entry (bit 7 = PS set)
              └── EPT PT (512 entries × 8B = 4KB page)
                    └── 4KB page entry → HPA
```

## EPT PTE Bit Layout

```c
#define EPT_PTE_READ      (1ULL << 0)   /* Read permission */
#define EPT_PTE_WRITE     (1ULL << 1)   /* Write permission */
#define EPT_PTE_EXEC      (1ULL << 2)   /* Execute permission */
#define EPT_PTE_MEMTYPE   (0x7ULL << 3) /* Memory type field (bits 5:3) */
#define EPT_PTE_MEMTYPE_WB (6ULL << 3)  /* Write-Back — use for all CoW pages */
#define EPT_PTE_MEMTYPE_UC (0ULL << 3)  /* Uncacheable — device memory, no CoW */
#define EPT_PTE_PS        (1ULL << 7)   /* Large page (2MB in PD entry) */
#define EPT_PTE_ACCESSED  (1ULL << 8)   /* A bit (if EPT A/D enabled) */
#define EPT_PTE_DIRTY     (1ULL << 9)   /* D bit (if EPT A/D enabled) */

/* EPTP (EPT Pointer) format */
#define EPTP_MEMTYPE_WB   (6ULL << 0)   /* WB caching for EPT structures */
#define EPTP_PAGEWALK_4   (3ULL << 3)   /* 4-level EPT page walk length */
#define EPTP_AD_ENABLE    (1ULL << 6)   /* Enable EPT A/D bits */
```

## GPA Range Classification

| Range | Type | EPT Treatment |
|-------|------|---------------|
| Guest RAM | RAM | RW WB, CoW-eligible |
| 0xFEE00000–0xFEE00FFF | MMIO (LAPIC) | Trap-and-emulate |
| 0xFEC00000–0xFEC00FFF | MMIO (IOAPIC) | Trap-and-emulate |
| 0xFED00000–0xFED003FF | MMIO (HPET) | Trap-and-emulate |
| Memory holes / reserved | Reserved | EPT-absent (not-present) |

**Only WB pages are CoW-eligible.** UC/WC pages (device memory) must NOT receive CoW private pages.

## CoW Fault Algorithm (Complete)

```c
static int phantom_cow_fault(struct phantom_instance *inst, u64 gpa)
{
    /* 1. Classify GPA — reject non-RAM */
    if (classify_gpa(inst, gpa) != GPA_TYPE_RAM) {
        inst->run_result = PHANTOM_RESULT_CRASH;
        return -EINVAL;
    }

    /* 2. Allocate private page from pre-allocated pool */
    struct page *private_page = phantom_pool_alloc(inst);
    if (!private_page) {
        phantom_abort_iteration(inst);
        return -ENOMEM;   /* PHANTOM_ERROR_POOL_EXHAUSTED */
    }

    /* 3. memcpy original → private */
    u64 *ept_pte  = phantom_ept_walk(inst, gpa, 4);
    u64  orig_hpa = *ept_pte & ~0xFFFULL & EPT_HPA_MASK;
    memcpy(page_address(private_page), phys_to_virt(orig_hpa), PAGE_SIZE);
    u64  priv_hpa = page_to_phys(private_page);

    /* 4. Update EPT entry → private page with RW + WB */
    *ept_pte = priv_hpa | EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_EXEC
                        | EPT_PTE_MEMTYPE_WB;

    /* 5. Append to dirty list */
    inst->dirty_list[inst->dirty_count++] = (struct dirty_entry){
        .gpa = gpa, .orig_hpa = orig_hpa, .priv_hpa = priv_hpa,
    };

    /* 6. NO INVEPT — permission-only change, EPT violation invalidated faulting GPA */
    return 0;  /* Caller does VMRESUME */
}
```

## INVEPT Batching Rules (Critical — From Intel SDM §28.3.3.1)

| Operation | INVEPT Required? | Reason |
|-----------|-----------------|--------|
| 4KB RO→RW CoW fault | **NO** | EPT violation itself invalidated faulting GPA's cached translation |
| 2MB→4KB structural split | **YES (single-context)** | Non-faulting GPAs in same 2MB range may have stale cached 2MB translations |
| Snapshot restore (end-of-iteration) | **YES (one, batched)** | Single INVEPT after ALL dirty-list entries reset |

**Formal invariant:** Every EPT structural change requires INVEPT before next VMRESUME. Permission-only changes to the faulting PTE do not.

Use single-context INVEPT (type 1), not all-context (type 3) — avoids cross-core overhead.

## 2MB → 4KB Page Splitting

When a CoW fault occurs on a GPA covered by a 2MB large-page EPT entry:

1. Allocate 512 × 4KB EPT PTEs; populate by splitting the 2MB mapping (511 pages stay RO at original HPA)
2. Insert new 4KB-level EPT PT into PD entry (replace large-page bit)
3. Only the single faulting 4KB page receives a private CoW copy
4. Issue **single-context INVEPT** before VMRESUME (structural change — stale translations exist)

## Snapshot Create / Restore

### Create (at snapshot point)
1. Mark all guest EPT entries **read-only** (clear EPT_PTE_WRITE on all RAM entries)
2. Record VMCS guest-state fields to host-side struct (see vmx-reference for field list)
3. Execute XSAVE to per-instance XSAVE area (bracketed with kernel_fpu_begin/end)
4. Snapshot = current EPT + saved VMCS + XSAVE area — **no memory copying**

### Restore (end of each iteration)
1. Walk dirty list (typically 10–500 entries)
2. For each entry: reset EPT entry back to `orig_hpa | EPT_PTE_READ | EPT_PTE_EXEC | EPT_PTE_MEMTYPE_WB`
3. Return all private pages to pool (pointer reset — no deallocation)
4. Reset `inst->dirty_count = 0`
5. Restore VMCS guest state from saved struct
6. Execute `kernel_fpu_begin()` → XRSTOR → `kernel_fpu_end()`
7. Issue **single INVEPT (single-context)** after all EPT updates
8. VMRESUME

### Why restore is fast
- Proportional to **dirty page count**, not total guest memory
- No memcpy of page content during restore (pointer swaps only)
- Pre-allocated pool eliminates kmalloc in hot path
- Class A (<50 dirty pages): <5μs; Class B (~200–1000 dirty pages): 10–100μs

## Page Pool Implementation

```c
/* Pool sizing */
/* Class A: default 4096 pages (16MB), covers ~50-page dirty sets with headroom */
/* Class B: default 16384 pages (64MB), covers ~2000-page dirty sets */

/* NUMA-local allocation */
int node = cpu_to_node(cpu);
page = alloc_pages_node(node, GFP_KERNEL, 0);

/* Lock-free per-CPU LIFO free list */
static struct page *phantom_pool_alloc(struct phantom_instance *inst)
{
    int idx = atomic_dec_return(&inst->cow_pool.head);
    if (idx < 0) { atomic_inc(&inst->cow_pool.head); return NULL; }
    return inst->cow_pool.pages[idx];
}
```

**On pool exhaustion:** abort iteration, walk dirty list, return all private pages to pool, issue INVEPT. Return `PHANTOM_ERROR_POOL_EXHAUSTED`. Instance remains usable.

## XSAVE / Extended Register State

- Allocate XSAVE area as 64-byte aligned
- Determine size via `CPUID.(EAX=0Dh, ECX=0).EBX`: SSE+AVX ~832B, +AVX-512 ~2.5KB
- **Fixed XCR0 model (Phase 1–3):** guest XCR0 = host XCR0 at instance creation; trap and reject guest XSETBV
- **At snapshot:** `XSAVE` uses host's XCR0 (already correct — no XSETBV needed)
- **At restore:** `kernel_fpu_begin()` → `XRSTOR` → `kernel_fpu_end()`
- Add ~200–400 cycles for XRSTOR in restore path latency estimates

## Per-Instance Memory Footprint (Class B)

```
guest_mem:    256MB  (alloc_pages_node)
cow_pool:      64MB  (16384 × 4KB)
topa:          16MB  (2 × 8MB double-buffer)
ept_tables:     2MB  (~512 page tables for 256MB guest)
vmcs:           4KB
xsave_area:     4KB
Total:        ~338MB per Class B instance
16 cores:    ~5.4GB — plan 8GB reserved on 64GB machine
```

## EPT Exit Qualification Bits (EPT violation)

- Bit 0: read access caused violation
- Bit 1: write access caused violation
- Bit 2: instruction fetch caused violation
- Bit 3: GPA is readable in EPT
- Bit 4: GPA is writable in EPT
- Bit 5: GPA is executable in EPT
- Bit 7: GPA valid (in GUEST_PHYSICAL_ADDRESS VMCS field)
