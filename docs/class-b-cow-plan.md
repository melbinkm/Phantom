# Class B EPT CoW Snapshot Restore — Design Document

## Problem

Class B (Linux kernel guest, 256MB RAM) fuzzing was functional but could not find
bugs because guest memory was never reset between iterations. VMCS registers and FPU
state restored correctly, but the 256MB EPT RAM stayed writable across iterations —
no CoW tracking, no dirty list, no restore. Result: 1.7M nf_tables iterations, 0
crashes.

## Solution

Extend the existing Class A CoW engine to Class B by adding class_b branches at
every EPT PTE lookup site: snapshot create (mark-all-RO), CoW fault handler,
snapshot restore (dirty list walk), abort iteration, and GPA-to-KVA helper.

## Architecture

```
SNAPSHOT CREATE (HC_ACQUIRE):
  phantom_ept_mark_all_ro_class_b()
    Walk 128 PT pages × 512 entries, clear EPT_PTE_WRITE

FUZZ ITERATION (guest writes to RAM):
  EPT violation (exit 48, write to RO page)
    phantom_cow_fault()
      if class_b: phantom_ept_lookup_pte_class_b()
      Alloc page from CoW pool
      memcpy original → private copy
      Update PTE to point to private copy (RW)
      Add to dirty list (gpa, orig_hpa, priv_hpa)

SNAPSHOT RESTORE (HC_RELEASE / end of iteration):
  phantom_snapshot_restore()
    Walk dirty list
      if class_b: phantom_ept_lookup_pte_class_b()
      Reset PTE → original HPA + RO
      Free private page back to pool
    INVEPT (single-context)
    Restore VMCS + GPRs + XRSTOR (unchanged)
```

## Key Simplification

Class B EPT is all 4KB pages (no 2MB entries). No splitting needed. The 4KB CoW
path is a direct reuse of existing `phantom_cow_4kb_page()`.

## Files Modified

| File | Changes |
|------|---------|
| `kernel/guest_boot.h` | +2 function declarations |
| `kernel/guest_boot.c` | +2 new functions: `phantom_ept_lookup_pte_class_b`, `phantom_ept_mark_all_ro_class_b` |
| `kernel/ept_cow.c` | Class B branches in `phantom_cow_4kb_page`, `phantom_cow_fault`, `phantom_cow_abort_iteration` |
| `kernel/snapshot.c` | Class B branches in `phantom_snapshot_create`, `phantom_snapshot_restore` |
| `kernel/hypercall.c` | Class B branch in `phantom_gpa_to_kva` |
| `userspace/phantom-fuzz/phantom_fuzz.c` | nfnetlink dictionary + crash deduplication |

## CoW Pool Sizing

`PHANTOM_COW_POOL_DEFAULT_CAPACITY` = 4096 pages (16MB). Sufficient for Class B
kernel dirty sets (typical: 100–500 pages, worst case: ~2000 pages).

## Performance Impact

- Mark all RO: 65536 PTE clears ≈ 30–50μs (one-time at snapshot)
- CoW faults: ~0.5–1μs per fault × 200 faults/iter ≈ 100–200μs
- Dirty list restore: ~0.3μs per entry × 200 entries ≈ 60μs
- Expected throughput with CoW: 10k–20k exec/s (down from 29k)
