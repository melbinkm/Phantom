# Task 3.2: Determinism Engineering

> **Phase:** Kernel Fuzzing — Class B | **Week(s):** 24–27 | **Depends on:** [Task 3.1](task-3.1-minimal-linux-guest-boot.md)

## Objective

Enumerate and mitigate every non-determinism source in kernel fuzzing, implement the kernel fuzzing harness, and pass the 1000/1000 determinism gate before proceeding to multi-core work.

## What to Build

- Kernel fuzzing harness: kernel module using nyx_api hypercalls; snapshot point after module init, before first iteration
- Address every non-determinism source (see 13-source enumeration below)
- TSS dirty-list verification for Class B: after privilege-level switch in guest, verify TSS page in dirty list; after restore, verify RSP0 field in TSS matches snapshot value
- Document every non-determinism source identified and its mitigation

## Implementation Guidance

### 13 Non-Determinism Sources (Complete Enumeration from §3)

Each source must be explicitly addressed. The determinism test is a **gating criterion**, not a nice-to-have.

| # | Source | Mitigation |
|---|--------|-----------|
| 1 | **TSC** | VMCS TSC offset ensures deterministic `rdtsc` from snapshot point |
| 2 | **APIC timer** | Disable timer interrupts during execution (mask LVTT); verify no spurious APIC timer VM exits; verify `jiffies` effectively frozen |
| 3 | **External interrupts** | VM exit on external interrupt; do not inject into guest during execution |
| 4 | **RNG (get_random_bytes)** | Inject fixed seed via hypercall; `CONFIG_RANDOM_TRUST_CPU=n` |
| 5 | **kstack offset** | `CONFIG_RANDOMIZE_KSTACK_OFFSET=n` |
| 6 | **Slab freelist random** | `CONFIG_SLAB_FREELIST_RANDOM=n` |
| 7 | **RANDSTRUCT** | `CONFIG_GCC_PLUGIN_RANDSTRUCT=n` |
| 8 | **KASLR** | `CONFIG_RANDOMIZE_BASE=n` |
| 9 | **RDRAND/RDSEED direct execution** | Mask CPUID bits (leaf 1 ECX bit 30; leaf 7 EBX bit 18) |
| 10 | **Preemption** | `CONFIG_PREEMPT=n`; single-vCPU guest |
| 11 | **SMP** | `CONFIG_SMP=n` |
| 12 | **jiffies** | Timer interrupt suppression freezes jiffies at snapshot value |
| 13 | **Slab freelist hardened** | `CONFIG_SLAB_FREELIST_HARDENED=n` |

### RDRAND/RDSEED Masking

From §3:

```c
/* Mask RDRAND and RDSEED in guest CPUID responses */
static void phantom_emulate_cpuid(struct phantom_instance *inst, struct vcpu *vcpu)
{
    u32 leaf = vcpu->regs[VCPU_REG_RAX];
    u32 subleaf = vcpu->regs[VCPU_REG_RCX];
    u32 eax, ebx, ecx, edx;

    /* Get base CPUID values from hardware */
    cpuid_count(leaf, subleaf, &eax, &ebx, &ecx, &edx);

    switch (leaf) {
    case 1:
        /* Mask RDRAND (ECX bit 30) */
        ecx &= ~(1 << 30);
        break;
    case 7:
        if (subleaf == 0) {
            /* Mask RDSEED (EBX bit 18) */
            ebx &= ~(1 << 18);
        }
        break;
    }

    vcpu->regs[VCPU_REG_RAX] = eax;
    vcpu->regs[VCPU_REG_RBX] = ebx;
    vcpu->regs[VCPU_REG_RCX] = ecx;
    vcpu->regs[VCPU_REG_RDX] = edx;
}
```

**Note from §3:** Linux ≥ 6.2 uses `alternatives`-based patching at boot from CPUID. Masking at snapshot-time CPUID queries is sufficient for Class B targets — the kernel checks CPUID before using RDRAND.

### External Interrupt Handling

```c
/* VM exit on external interrupt (exit reason 1) */
static int phantom_handle_external_interrupt(struct phantom_instance *inst)
{
    /*
     * External interrupt fired during guest execution.
     * Do NOT inject into guest during fuzzing window.
     * Just resume — host IDT handles the interrupt after VMRESUME.
     *
     * Note: exit reason 1 (external interrupt) is distinct from
     * exit reason 0 (exception or NMI).
     */
    /* The host CPU processes the external interrupt via "acknowledge interrupt
     * on exit" (VM-exit controls bit 15) before delivering VM-exit */
    return phantom_vmresume(inst);
}
```

### PT Determinism Configuration

From §2.4 — ensure timing packets are suppressed for byte-identical traces:

```c
/* IA32_RTIT_CTL bits that MUST be 0 for determinism */
/* CYCEn (bit 1) = 0: disable CYC packets */
/* MTCEn (bit 9) = 0: disable MTC packets */
/* TSCEn (bit 10) = 0: disable TSC packets */
/* PTWEn (bit 4) = 0: disable PTWRITE packets */

/* The determinism test MUST fail if any timing packet type is enabled */
/* Verify by checking decoded trace contains no CYC/MTC/TSC/PTWRITE packets */
```

### Determinism Test: 1000/1000 Gate

**What must match across all 1000 runs (from §9):**

```c
struct determinism_check {
    u64 gp_regs[16];        /* All GP registers: RAX–R15                */
    u64 cr3;                 /* Guest CR3                                */
    u64 rsp;                 /* Guest RSP                                */
    u64 rip;                 /* Guest RIP at exit point                  */
    u64 rflags;              /* Guest RFLAGS                             */
    /* Full PT trace byte-identical (valid when CYCEn=MTCEn=TSCEn=0)   */
    u8  *pt_trace_bytes;
    u32  pt_trace_len;
    /* Dirty page list (same pages dirtied in same order)               */
    u64  dirty_gpas[DIRTY_LIST_DEFAULT_MAX];
    u32  dirty_count;
};
```

**GATE — Do not proceed to Task 3.3 until 1000/1000 passes.**

```
Quantified criterion (§9):
"Identical input produces byte-identical PT trace (with CYCEn=MTCEn=TSCEn=0;
no timing packets) and identical register state 1000/1000 times"
```

### Scaling Criterion Formula (for Task 3.3 Readiness Check)

From §9 quantified criteria:
```
exec_N_cores / (exec_1_core × N) ≥ 0.85 for N ∈ {2, 4, 8}
```

This formula is verified in Task 3.3. Establish the baseline exec_1_core measurement here during determinism testing, which will serve as the denominator.

## Key Data Structures

```c
/* Kernel harness using nyx_api hypercalls */
/* guest/guest_kernel/init_harness.c */
static int harness_thread(void *data)
{
    /* Module init completes */

    /* Take snapshot here */
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

    /* Fuzzing loop */
    while (1) {
        /* Get payload address */
        u8 *payload = (u8 *)kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, 0);

        /* Call target function */
        target_function(payload, payload_size);

        /* Release: triggers PT disable + snapshot restore */
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
}
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/vmx_core.c` | CPUID masking (RDRAND/RDSEED), external interrupt handler |
| `guest/guest_kernel/init_harness.c` | Kernel harness with nyx_api hypercalls |
| `tests/integration/test_determinism.sh` | 1000-run determinism test |

## Reference Sections

- §3: Determinism challenges — 13-source enumeration with complete mitigation list
- §2.4: PT determinism config — timing packet suppression, byte-identical trace requirement
- §9: Quantified determinism gate — 1000/1000 definition, dirty page list matching

## Tests to Run

- **GATE — 1000/1000 determinism:** run identical input 1000 times; all of the following must match across all 1000 runs: all GP registers, CR3, RSP, RIP, RFLAGS after each run; full PT trace byte-identical (valid only when CYCEn=MTCEn=TSCEn=0); dirty page list (same pages dirtied in same order). **Do not proceed to Task 3.3 until 1000/1000 passes.**
- Zero timing packets in any decoded PT trace (pass = libipt decoder finds no CYC/MTC/TSC packets)
- TSS page appears in dirty list after privilege-level switch (pass = GPA of TSS found in dirty list inspector output)
- RSP0 field in TSS matches snapshot value after restore (pass = byte-identical comparison)
- RDRAND and RDSEED absent from guest CPUID (pass = guest CPUID leaf 1 ECX bit 30 = 0; leaf 7 EBX bit 18 = 0)

## Deliverables

Deterministic kernel fuzz loop with every non-determinism source documented and mitigated; 1000/1000 determinism gate passed.
