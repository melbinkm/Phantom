# Task 1.7: Correctness Testing

> **Phase:** CoW Engine + Snapshot/Restore | **Week(s):** 11 | **Depends on:** [Task 1.6](task-1.6-snapshot-restore-integration.md)

## Objective

Validate snapshot/restore correctness at scale: 10,000-cycle endurance, 1000× determinism, TSS dirty-list verification, and zero memory leaks under KMEMLEAK.

## What to Build

- Basic restore correctness test: run guest, snapshot, run again (guest modifies memory), restore, verify memory matches snapshot; verify all VMCS guest-state fields match pre-snapshot values after restore; verify XMM registers restored correctly (write distinctive SIMD patterns, restore, check)
- 10,000-cycle correctness test: 10,000 snapshot/restore cycles with no state corruption and no memory leaks
- Determinism test: identical guest code + identical input produces identical register state after restore 1000 consecutive times
- TSS dirty-list test: guest executes a function causing a privilege-level switch (interrupt or syscall); verify TSS page appears in dirty list; restore snapshot, verify RSP0 field in TSS matches snapshot value

## Implementation Guidance

### XSAVE Correctness Verification

Write distinctive SIMD patterns before snapshot, verify after restore:

```c
/* Test: XMM register preservation across snapshot/restore */
static void test_xmm_preservation(struct phantom_instance *inst)
{
    /* Guest writes 16 distinctive XMM values before ACQUIRE hypercall */
    /* Snapshot is taken at ACQUIRE */
    /* Guest modifies XMM registers during execution */
    /* Snapshot restore should revert all XMM values */

    /* Host-side verification (via ioctl after restore) */
    u8 *xsave = inst->xsave_area;
    /* XMM0–XMM15 start at offset 160 in the XSAVE legacy region */
    /* Each XMM register is 16 bytes */
    for (int i = 0; i < 16; i++) {
        u8 *xmm = xsave + 160 + (i * 16);
        /* Verify against known pattern written by test guest */
        WARN_ON(memcmp(xmm, expected_patterns[i], 16) != 0);
    }
}
```

### TSS Dirty-List Test (Class B Context)

The guest Task State Segment (TSS) page is modified on every privilege-level switch (RSP0 update during syscall/interrupt).

```c
/* Test sequence for TSS dirty-list verification */
/* 1. Take snapshot */
/* 2. Guest executes a privilege-level switch (syscall/interrupt) */
/* 3. Host reads dirty list — TSS GPA must be present */
/* 4. Restore snapshot */
/* 5. Read TSS RSP0 field — must match snapshot value */

static void verify_tss_in_dirty_list(struct phantom_instance *inst)
{
    u64 tss_gpa = inst->guest_tss_gpa;  /* Recorded during boot_params setup */
    bool found = false;

    for (u32 i = 0; i < inst->dirty.count; i++) {
        if (inst->dirty.entries[i].gpa == tss_gpa) {
            found = true;
            break;
        }
    }
    WARN_ON_ONCE(!found);  /* TSS must appear in dirty list */
}
```

**TSS CoW note from §3 (Class B):**
> The guest TSS page is modified on every privilege-level switch (RSP0 update during syscall/interrupt). This page will appear in the dirty list on every iteration. GDT and IDT pages should be read-only (rarely modified after boot) — verify they are NOT in the dirty list under normal operation.

### Determinism Gate (1000/1000)

The determinism test checks that identical input produces identical results across 1000 consecutive runs:

```c
/* What must match across all 1000 runs: */
struct determinism_snapshot {
    u64 gp_regs[16];    /* RAX–R15                                  */
    u64 cr3;             /* Guest CR3                                */
    u64 rsp;             /* Guest RSP                                */
    u64 rip;             /* Guest RIP at exit                        */
    u64 rflags;          /* Guest RFLAGS                             */
    u32 dirty_count;     /* Number of dirty pages                    */
    u64 dirty_gpas[512]; /* Which GPAs were dirtied, in order        */
    /* PT trace byte-identity checked separately for Class B */
};
```

For this task, 1000/1000 determinism is validated for the snapshot/restore engine itself. Full PT trace determinism is validated in Task 3.2.

### Test Ioctl Reference (§9)

```c
/* Test ioctls for kernel unit testing (compiled in with PHANTOM_DEBUG) */
#define PHANTOM_TEST_COW_SINGLE_PAGE     _IO(PHANTOM_IOC_MAGIC, 0x20)
#define PHANTOM_TEST_POOL_EXHAUSTION     _IO(PHANTOM_IOC_MAGIC, 0x21)
#define PHANTOM_TEST_DIRTY_LIST_OVERFLOW _IO(PHANTOM_IOC_MAGIC, 0x22)
#define PHANTOM_TEST_MMIO_REJECT         _IO(PHANTOM_IOC_MAGIC, 0x23)
#define PHANTOM_TEST_XSAVE_RESTORE       _IO(PHANTOM_IOC_MAGIC, 0x24)
```

### Quantified Criteria

From §9 quantified exit criteria table:

| Criterion | Measurement |
|-----------|------------|
| Deterministic execution | Identical input → byte-identical PT trace (with CYCEn=MTCEn=TSCEn=0) and identical register state 1000/1000 times |
| Memory integrity | KMEMLEAK reports zero warnings after 10,000 cycles |
| TSS correctness | RSP0 field byte-identical to snapshot value after restore |

## Key Data Structures

```c
/* Determinism test state */
struct determinism_run {
    u64 gp_regs[16];
    u64 cr3, rsp, rip, rflags;
    u32 dirty_count;
    u64 dirty_gpas[DIRTY_LIST_DEFAULT_MAX];
};
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `tests/unit/test_snapshot.c` | 10,000-cycle endurance test |
| `tests/unit/test_xsave.c` | XMM register preservation test |
| `kernel/interface.c` | Test ioctl dispatch |

## Reference Sections

- §2.3: XSAVE verification — XMM0–XMM15 pattern test, `kernel_fpu_begin/end` bracketing
- §3: TSS CoW note — RSP0 dirty-list tracking, GDT/IDT should NOT appear in dirty list
- §9: Test ioctls — `PHANTOM_TEST_XSAVE_RESTORE`, `PHANTOM_TEST_COW_SINGLE_PAGE`
- §9: Quantified criteria — 1000/1000 determinism definition, stability test thresholds

## Tests to Run

- 10,000 snapshot/restore cycles complete with zero state corruption (pass = GP register state identical for a fixed input at all 10,000 cycles)
- 1000/1000 determinism: identical input produces identical GP register state 1000 consecutive times (pass = all 1000 match cycle 1)
- TSS page appears in dirty list after a privilege-level switch (pass = GPA of TSS found in dirty list inspector output)
- RSP0 field in TSS matches snapshot value after restore (pass = byte-identical)
- KMEMLEAK reports zero warnings after 10,000 cycles (pass = zero leaks)

## Deliverables

Correctness test suite passing; 10,000-cycle endurance and 1000× determinism validated.
