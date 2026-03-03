# Task 1.3: Basic Read/Write EPT

> **Phase:** VMX Bootstrap + Basic EPT | **Week(s):** 5 | **Depends on:** [Task 1.2](task-1.2-vmcs-configuration-guest-execution.md)

## Objective

Construct a 4-level EPT with correct GPA classification (RAM / MMIO / reserved) and verify that guest R/W to RAM succeeds while accesses to absent/reserved ranges produce clean EPT violations.

## What to Build

- EPT page table construction: 4-level EPT (PML4 → PDPT → PD → PT), GPA-range classification as RAM vs MMIO vs reserved (per Section 2.3 MMIO Handling), RAM ranges as read-write WB mappings, MMIO ranges as trap-and-emulate (EPT-present but with special emulation flag), reserved ranges as EPT-absent (not-present) — any guest access → EPT violation → abort iteration
- EPT walker/dumper (`debug.c`): debug ioctl (`PHANTOM_DEBUG_DUMP_EPT`) that walks the full EPT and prints each mapping, highlighting MMIO regions, RAM regions, and absent regions; used to verify EPT construction correctness before CoW work begins
- Basic read-write guest execution: guest can write to RAM pages and read them back; verify no EPT violations on normal R/W to RAM; verify EPT violations (abort) on guest access to absent/reserved ranges

## Implementation Guidance

### EPT Architecture Diagram

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

### GPA Range Classification

Before EPT construction, classify all GPA ranges:

| Range | Type | EPT Treatment |
|-------|------|---------------|
| 0x0000_0000 – 0x00FF_FFFF | RAM | RW WB, CoW-eligible |
| 0xFEE0_0000 – 0xFEE0_0FFF | MMIO (LAPIC) | Trap-and-emulate |
| 0xFEC0_0000 – 0xFEC0_0FFF | MMIO (IOAPIC) | Trap-and-emulate |
| 0xFED0_0000 – 0xFED0_03FF | MMIO (HPET) | Trap-and-emulate |
| Any other firmware MMIO | MMIO | From e820 map |
| Memory holes / reserved | Reserved | EPT-absent (not-present) |

**Class A EPT map:** Simple flat GPA-to-HPA mapping acceptable. Guest physical memory is a single contiguous region. MMIO ranges are EPT-absent (abort on access).

### Memory Type Consistency

Private CoW pages must inherit the EPT memory type (bits 5:3 of EPT PTE) from the original:
- **WB (type 6):** standard RAM pages — use for all CoW private pages
- **UC (type 0):** device memory — CoW must NOT apply
- **WC (type 1):** framebuffer/device MMIO — CoW must NOT apply

```c
/* EPT PTE bit layout */
#define EPT_PTE_READ      (1ULL << 0)  /* Read permission          */
#define EPT_PTE_WRITE     (1ULL << 1)  /* Write permission         */
#define EPT_PTE_EXEC      (1ULL << 2)  /* Execute permission       */
#define EPT_PTE_MEMTYPE   (0x7ULL << 3) /* Memory type field       */
#define EPT_PTE_MEMTYPE_WB (6ULL << 3) /* Write-Back memory type  */
#define EPT_PTE_MEMTYPE_UC (0ULL << 3) /* Uncacheable             */
#define EPT_PTE_PS        (1ULL << 7)  /* Large page (2MB in PD)  */
#define EPT_PTE_ACCESSED  (1ULL << 8)  /* A bit (if EPT A/D enabled) */
#define EPT_PTE_DIRTY     (1ULL << 9)  /* D bit (if EPT A/D enabled) */
```

### EPT Walker/Dumper (debug.c)

Debug ioctl `PHANTOM_DEBUG_DUMP_EPT`:
- Walks the full 4-level EPT for the specified instance
- Prints each mapped region: GPA range, HPA, permissions, memory type
- Highlights: CoW'd pages (private HPA ≠ original HPA), split 2MB pages, MMIO regions, absent regions
- Output to debugfs file `/sys/kernel/debug/phantom/instance_N/ept_map`

```c
static void phantom_walk_ept(struct phantom_instance *inst)
{
    u64 *pml4 = phys_to_virt(inst->eptp & ~0xFFF);

    for (int i = 0; i < 512; i++) {
        if (!(pml4[i] & EPT_PTE_READ)) continue;
        u64 *pdpt = phys_to_virt(pml4[i] & ~0xFFF);

        for (int j = 0; j < 512; j++) {
            if (!(pdpt[j] & EPT_PTE_READ)) continue;
            /* ... recurse through PD and PT ... */
            /* Print: GPA range, HPA, R/W/X, memory type, CoW status */
        }
    }
}
```

### MMIO CoW Rejection

```c
static int phantom_cow_handler(struct phantom_instance *inst, u64 gpa)
{
    struct gpa_region *region = classify_gpa(inst, gpa);

    if (region->type == GPA_TYPE_MMIO) {
        pr_err("phantom: CoW attempt on MMIO GPA 0x%llx — rejecting\n", gpa);
        /* Emulate the MMIO access instead */
        return phantom_emulate_mmio(inst, gpa);
    }

    if (region->type == GPA_TYPE_RESERVED) {
        /* Reserved range: abort iteration */
        inst->run_result = PHANTOM_RESULT_CRASH;
        return -EFAULT;
    }

    /* RAM: CoW proceeds normally */
    return phantom_cow_ram_page(inst, gpa);
}
```

## Key Data Structures

```c
/* GPA region classification */
enum gpa_type {
    GPA_TYPE_RAM      = 0,  /* CoW-eligible, WB memory type             */
    GPA_TYPE_MMIO     = 1,  /* Trap-and-emulate, no CoW                 */
    GPA_TYPE_RESERVED = 2,  /* EPT-absent, any access → abort           */
};

struct gpa_region {
    u64          gpa_start;
    u64          gpa_end;
    enum gpa_type type;
    u32          ept_memtype;  /* For MMIO: UC or WC; for RAM: WB       */
};

/* EPTP (EPT Pointer) format */
#define EPTP_MEMTYPE_WB   (6ULL << 0)  /* WB caching for EPT structures  */
#define EPTP_PAGEWALK_4   (3ULL << 3)  /* 4-level EPT page walk length   */
#define EPTP_AD_ENABLE    (1ULL << 6)  /* Enable EPT A/D bits            */
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/ept.c` | EPT page table construction, GPA classification |
| `kernel/debug.c` | `PHANTOM_DEBUG_DUMP_EPT` ioctl, EPT walker |
| `kernel/interface.c` | Debug ioctl dispatch |

## Reference Sections

- §2.3: MMIO handling and GPA ranges — LAPIC/IOAPIC/HPET addresses, CoW rejection for MMIO
- §2.3: EPT architecture diagram — 4-level structure, GPA-to-HPA translation
- §3: Class A EPT map — simple flat mapping acceptable, MMIO ranges excluded
- §5.6 Appendix B §2: EPT walker implementation — debugfs output format

## Tests to Run

- Guest read/write to 10 RAM pages completes without EPT violations (pass = no abort, all written values read back correctly)
- EPT violation fires on guest access to an absent GPA (pass = exit reason is EPT violation, iteration aborted cleanly)
- EPT walker output shows correct GPA classification for all three region types (pass = walker output reviewed, classifications match expected layout)

## Deliverables

Basic R/W EPT operational; EPT walker confirms correct GPA classification for RAM, MMIO, and absent regions.
