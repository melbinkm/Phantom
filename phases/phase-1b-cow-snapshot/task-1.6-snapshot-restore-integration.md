# Task 1.6: Snapshot/Restore Integration

> **Phase:** CoW Engine + Snapshot/Restore | **Week(s):** 9–10 | **Depends on:** [Task 1.5](task-1.5-full-cow-engine-2mb-splitting.md)

## Objective

Implement complete snapshot creation and restore — save all VMCS guest-state fields, XSAVE extended registers, and EPT state; restore via pointer-swap (no memcpy on restore path) with a single batched INVEPT.

## What to Build

- Snapshot creation: save all VMCS guest-state fields per explicit enumeration in Section 2.3, save general-purpose registers in a host-side structure, execute `XSAVE` to per-instance XSAVE area (64-byte aligned, size from CPUID.0Dh.ECX=0.EBX), save `XCR0` value, mark all guest EPT RAM pages read-only (walk EPT, clear W bit, maintain memory type), reset dirty list to empty, record PT buffer position (for coverage boundary)
- Snapshot restore: walk dirty list — for each entry, reset EPT mapping to original page (read-only); return all private pages to pool via bulk pointer reset (no `memcpy`); restore VMCS guest state from saved structure (all fields from enumeration); execute `kernel_fpu_begin()` → `XRSTOR` from XSAVE area → `kernel_fpu_end()` (fixed XCR0 model: no `XSETBV` needed; see XSAVE implementation notes in §2.3); issue single INVEPT (single-context) after all EPT updates complete; `VMRESUME`

## Implementation Guidance

### snapshot_create() Pseudocode

```c
int phantom_snapshot_create(struct phantom_instance *inst)
{
    /* 1. Save all general-purpose registers (in host memory, not VMCS) */
    inst->snapshot.rax = vcpu->regs[VCPU_REG_RAX];
    /* ... RAX through R15, RIP, RFLAGS ... */

    /* 2. Save all VMCS guest-state fields (explicit enumeration) */
    inst->snapshot.cr0  = vmcs_read(GUEST_CR0);
    inst->snapshot.cr3  = vmcs_read(GUEST_CR3);
    inst->snapshot.cr4  = vmcs_read(GUEST_CR4);
    inst->snapshot.rip  = vmcs_read(GUEST_RIP);
    inst->snapshot.rsp  = vmcs_read(GUEST_RSP);
    /* Segment registers — 8 × 4 sub-fields each */
    inst->snapshot.cs_sel   = vmcs_read(GUEST_CS_SELECTOR);
    inst->snapshot.cs_base  = vmcs_read(GUEST_CS_BASE);
    inst->snapshot.cs_limit = vmcs_read(GUEST_CS_LIMIT);
    inst->snapshot.cs_ar    = vmcs_read(GUEST_CS_AR_BYTES);
    /* ... SS, DS, ES, FS, GS, LDTR, TR ... */
    /* MSRs in VMCS guest-state area */
    inst->snapshot.efer     = vmcs_read64(GUEST_IA32_EFER);
    inst->snapshot.debugctl = vmcs_read64(GUEST_IA32_DEBUGCTL);
    inst->snapshot.pat      = vmcs_read64(GUEST_IA32_PAT);
    /* ... IA32_SYSENTER_CS/ESP/EIP, SMBASE, preemption timer ... */
    /* Guest interrupt state */
    inst->snapshot.interruptibility = vmcs_read(GUEST_INTERRUPTIBILITY_INFO);
    inst->snapshot.activity_state   = vmcs_read(GUEST_ACTIVITY_STATE);

    /* 3. Save extended registers via XSAVE (fixed XCR0 model) */
    /*    Size from CPUID.(EAX=0Dh, ECX=0).EBX — determined at module init */
    WARN_ON(!is_64byte_aligned(inst->xsave_area));
    kernel_fpu_begin();
    xsave(inst->xsave_area, inst->xcr0_supported);  /* XSAVE with host XCR0 */
    kernel_fpu_end();

    /* 4. Mark all guest EPT RAM pages read-only (walk EPT, clear W bit) */
    phantom_ept_mark_all_readonly(inst);
    /* memory type (WB/UC/WC) is preserved — only W bit cleared */

    /* 5. Reset dirty list to empty */
    inst->dirty.count = 0;

    /* 6. Record PT buffer position (coverage boundary marker) */
    inst->snapshot.pt_output_offset = rdmsr(IA32_RTIT_OUTPUT_MASK_PTRS);

    inst->snapshot_taken = true;
    return 0;
}
```

### snapshot_restore() Pseudocode

```c
int phantom_snapshot_restore(struct phantom_instance *inst)
{
    /* 1. Walk dirty list — reset EPT mappings, return private pages to pool */
    for (u32 i = 0; i < inst->dirty.count; i++) {
        struct dirty_entry *e = &inst->dirty.entries[i];
        u64 *pte = phantom_ept_walk(inst, e->gpa, 4);
        /* Reset to original page, read-only (snapshot state) */
        *pte = e->orig_hpa | EPT_PTE_READ | EPT_PTE_EXEC | EPT_PTE_MEMTYPE_WB;
        /* Return private page to pool (pointer swap — NO memcpy) */
        phantom_pool_free(&inst->cow_pool, phys_to_page(e->priv_hpa));
    }
    inst->dirty.count = 0;

    /* 2. Issue single INVEPT after ALL EPT updates complete (batched) */
    phantom_invept_single_context(inst->eptp);

    /* 3. Restore VMCS guest-state fields from snapshot */
    vmcs_write(GUEST_CR0, inst->snapshot.cr0);
    vmcs_write(GUEST_CR3, inst->snapshot.cr3);
    vmcs_write(GUEST_CR4, inst->snapshot.cr4);
    vmcs_write(GUEST_RIP, inst->snapshot.rip);
    vmcs_write(GUEST_RSP, inst->snapshot.rsp);
    /* ... all segment registers, MSRs, interrupt state ... */

    /* 4. Restore GP registers (host memory → vcpu struct) */
    vcpu->regs[VCPU_REG_RAX] = inst->snapshot.rax;
    /* ... RAX through R15, RFLAGS ... */

    /* 5. Restore extended registers via XRSTOR (fixed XCR0 model) */
    /*    No XSETBV needed — XCR0 is already correct under fixed XCR0 model */
    kernel_fpu_begin();
    xrstor(inst->xsave_area, inst->xcr0_supported);
    kernel_fpu_end();
    /*
     * XRSTOR overhead: ~200–400 cycles. Account for this in restore
     * latency estimates. Measure contribution separately in Task 1.8.
     */

    /* 6. VMRESUME */
    return phantom_vmresume(inst);
}
```

### XSAVE Implementation Notes

**Fixed XCR0 model (Phase 1–3 policy):**
- Guest XCR0 is set equal to host's XCR0 at instance creation time
- Guest `XSETBV` instructions are VM-exit trapped and rejected
- This avoids host/guest XCR0 mismatch entirely

**At snapshot:** `XSAVE` uses host's XCR0 — no `XSETBV` needed.

**At restore:** No `XSETBV` needed. Execute `kernel_fpu_begin()` → `XRSTOR` → `kernel_fpu_end()` to bracket within kernel's FPU context discipline.

**XSAVE area sizing (from CPUID at module init):**

```c
static u32 determine_xsave_area_size(void)
{
    u32 eax, ebx, ecx, edx;
    cpuid_count(0x0D, 0, &eax, &ebx, &ecx, &edx);
    /* EBX = size of XSAVE area for all currently enabled features */
    /* Round up to 64-byte alignment */
    return ALIGN(ebx, 64);
    /* SSE + AVX: ~832 bytes; SSE + AVX + AVX-512: ~2.5KB */
}
```

**Pre-condition:** Verify `CR4.OSXSAVE` is set before issuing XSAVE/XRSTOR.

### INVEPT Batching in Restore

The single INVEPT after all dirty-list EPT resets is the critical performance optimization:

```c
/* WRONG — one INVEPT per dirty entry (N × overhead) */
for each dirty entry:
    reset EPT entry
    phantom_invept_single_context(inst->eptp)  /* BAD */

/* CORRECT — batch all EPT updates, single INVEPT at end */
for each dirty entry:
    reset EPT entry
phantom_invept_single_context(inst->eptp)      /* GOOD — one operation */
```

## Key Data Structures

```c
/* Snapshot saved state */
struct phantom_snapshot {
    /* General-purpose registers */
    u64 rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp;
    u64 r8,  r9,  r10, r11, r12, r13, r14, r15;
    u64 rip, rflags;

    /* VMCS guest-state — control registers */
    u64 cr0, cr3, cr4, dr7;

    /* VMCS guest-state — segment registers (8 × 4 sub-fields) */
    struct { u16 sel; u64 base; u32 limit; u32 ar; }
        cs, ss, ds, es, fs, gs, ldtr, tr;

    /* VMCS guest-state — descriptor tables */
    u64 gdtr_base; u32 gdtr_limit;
    u64 idtr_base; u32 idtr_limit;

    /* VMCS guest-state — MSRs */
    u64 efer, debugctl, pat, perf_global_ctrl;
    u64 sysenter_cs, sysenter_esp, sysenter_eip;
    u64 smbase;

    /* VMCS guest-state — interrupt state */
    u32 interruptibility;
    u32 activity_state;
    u32 preempt_timer_value;

    /* PT buffer position at snapshot time */
    u64 pt_output_offset;
};

/* Per-instance XSAVE area */
/* Allocated at instance creation with 64-byte alignment */
/* Size = CPUID.(EAX=0Dh, ECX=0).EBX rounded up to 64 bytes */
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/snapshot.c` | `snapshot_create()`, `snapshot_restore()`, XSAVE/XRSTOR |
| `kernel/ept_cow.c` | EPT mark-all-readonly, dirty list reset |
| `kernel/vmx_core.c` | VMRESUME after restore |

## Reference Sections

- §2.3: VMCS field enumeration — complete list of all 40+ fields to save/restore (hex VMCS field IDs)
- §2.3: XSAVE implementation — fixed XCR0 model, `kernel_fpu_begin/end`, 200–400 cycle XRSTOR overhead
- §2.3: INVEPT batching — single INVEPT after all dirty-list resets, not one per entry

## Tests to Run

- Guest memory matches snapshot state after one restore cycle (pass = byte-identical comparison of all written pages against snapshot)
- All VMCS guest-state fields match pre-snapshot values after restore (pass = field-by-field comparison against saved structure)
- XMM0–XMM15 registers survive restore: write 16 distinctive SIMD patterns, restore, verify all 16 patterns intact (pass = all 16 match expected values)
- 100 snapshot/restore cycles show no state drift (pass = register state at cycle 100 identical to cycle 1 for the same fixed input)
- EPT walker confirms all pages reset to read-only with original HPAs after restore (pass = walker output shows zero private pages)

## Deliverables

Complete snapshot/restore engine with pointer-swap CoW reset (no memcpy on restore path).
