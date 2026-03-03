# Task 1.2: VMCS Configuration + Guest Execution

> **Phase:** VMX Bootstrap + Basic EPT | **Week(s):** 3–4 | **Depends on:** [Task 1.1](task-1.1-dev-environment-vmx-bootstrap.md)

## Objective

Configure a complete VMCS for a trivial guest, handle VM exits correctly, and execute guest code that communicates results back to the host via VMCALL.

## What to Build

- Full VMCS guest-state setup: all segment registers with all 4 sub-fields (selector, base, limit, access rights), GDTR/IDTR base and limit, CR0/CR3/CR4/DR7, EFER/SYSENTER_CS/ESP/EIP/SMBASE, guest interruptibility state, activity state, VMCS link pointer, entry point configuration, VMCS control fields (pin-based, CPU-based, exit, entry), exception bitmap configuration
- VMCS field validator (`debug.c`): validates all guest-state VMCS fields against Intel SDM §26.3 requirements before every VMLAUNCH; compiled out in production (`#ifdef PHANTOM_DEBUG`); prevents most "VM-entry failure due to invalid guest state" panics during development
- VM exit handler: VMCALL (hypercall dispatch), EPT violation (forward to EPT handler), CPUID (minimal emulation), triple fault (guest crash), I/O (block — no device emulation), external interrupt (re-inject to host), NMI (NMI exiting enabled in pin-based controls; handler is NMI-safe — no spinlocks, no non-reentrant structures entered during exit handling; `nmi_watchdog=0` on dedicated cores per Section 2.6)
- VMCS dump-on-exit-failure: on any unexpected exit reason, automatically dump all VMCS fields via `debug.c`; output is structured (field name + value) parseable by a companion userspace tool
- VMCS error handling tests marked **requires bare metal**: invalid guest state, VM-entry failure (CF=1), and bad control field combinations must be validated on bare-metal hardware — nested KVM may mask invalid VMCS field values that would cause a real VM-entry failure on hardware
- Trivial guest payload: flat binary loaded into guest physical memory; receives a memory address via VMCALL, reads data, returns checksum via VMCALL; proves VM entry works, guest executes, VMCALL returns data to host
- Host-side test via ioctl: load guest → run → read result → verify

## Implementation Guidance

### VMCS Guest-State Field Enumeration (Complete)

The snapshot (Task 1.6) must save/restore all of these. Enumerate them now during VMCS setup to avoid omissions later.

**General-purpose registers** (saved in host memory, not VMCS fields):
- RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, R8–R15, RIP, RFLAGS

**Segment registers** (8 × 4 sub-fields each) — VMCS field hex IDs:

| Register | Selector | Base | Limit | Access Rights |
|----------|----------|------|-------|---------------|
| CS | 0x0802 | 0x6808 | 0x4802 | 0x4816 |
| SS | 0x0804 | 0x680A | 0x4804 | 0x4818 |
| DS | 0x0806 | 0x680C | 0x4806 | 0x481A |
| ES | 0x0800 | 0x6806 | 0x4800 | 0x4814 |
| FS | 0x0808 | 0x680E | 0x4808 | 0x481C |
| GS | 0x080A | 0x6810 | 0x480A | 0x481E |
| LDTR | 0x080C | 0x6812 | 0x480C | 0x4820 |
| TR | 0x080E | 0x6814 | 0x480E | 0x4822 |

**Descriptor table registers:**
- GDTR base: 0x6816, GDTR limit: 0x4810
- IDTR base: 0x6818, IDTR limit: 0x4812

**Control registers:**
- CR0: 0x6800, CR3: 0x6802, CR4: 0x6804, DR7: 0x681A

**MSRs in VMCS guest-state area:**
- `IA32_DEBUGCTL` (0x2802), `IA32_PAT` (0x2804), `IA32_EFER` (0x2806)
- `IA32_PERF_GLOBAL_CTRL` (0x2808, if VMCS control enabled)
- `IA32_BNDCFGS` (0x2812, if MPX enabled)
- `IA32_RTIT_CTL` (0x2814, if PT-in-VMX supported)

**System registers:**
- SMBASE (0x6078), `IA32_SYSENTER_CS` (0x482A)
- `IA32_SYSENTER_ESP` (0x6824), `IA32_SYSENTER_EIP` (0x6826)
- VMX preemption timer value (0x482E, if preemption timer enabled)

**Guest interrupt state:**
- Interruptibility state (0x4824), Pending debug exceptions (0x6822)
- VMCS link pointer (0x2800), Activity state (0x4826)

**PDPTE entries** (0x280A–0x2810): required when guest uses PAE paging (CR4.PAE=1).

### NMI Handling Design

NMIs can arrive at any time, including during guest execution. With "NMI exiting" (pin-based VM-execution control bit 3) enabled:
- An NMI during guest execution causes a VM exit with basic exit reason **0** ("Exception or NMI")
- The VM-exit interruption-information field (VMCS 0x4404) will have vector=2, type=2 (NMI), valid bit set
- The NMI is **not** delivered to the guest

**Re-delivery to host (recommended approach — APIC self-NMI):**

```c
static void phantom_handle_nmi_exit(void)
{
    /*
     * NMI exiting fired — guest NMI not delivered.
     * Re-deliver to host via APIC self-NMI.
     * KVM uses this same approach (kvm_inject_nmi / self_nmi).
     */
    apic_write(APIC_ICR,
               APIC_DEST_SELF | APIC_DELIVERY_MODE_NMI);
    /*
     * NMI-safe: no spinlocks held here, no non-reentrant
     * structures accessed. Handler returns and NMI fires
     * through host IDT normally.
     */
}
```

**Host configuration:** Add `nmi_watchdog=0` to kernel cmdline on dedicated fuzzing cores to suppress NMI watchdog.

### VMCS Dump Format (debug.c)

```
PHANTOM VMCS DUMP [instance=N, cpu=M, exit_reason=X, iteration=Y]
  GUEST_RIP=0x... GUEST_RSP=0x... GUEST_RFLAGS=0x...
  GUEST_CR0=0x... GUEST_CR3=0x... GUEST_CR4=0x...
  EXIT_QUALIFICATION=0x... VM_INSTRUCTION_ERROR=N
  GUEST_CS: sel=0x... base=0x... limit=0x... ar=0x...
  ... [all fields]
```

Output via `trace_printk` (not `printk`) to avoid lock contention. Structured format parseable by `tools/vmcs-dump/`.

### VMCS Field Validator (debug.c §5 — compiled out in production)

Before every VMLAUNCH and VMRESUME (in `#ifdef PHANTOM_DEBUG` builds):

```c
static int phantom_validate_vmcs_guest_state(void)
{
    u32 ar_cs = vmcs_read32(GUEST_CS_AR_BYTES);
    u32 ar_ss = vmcs_read32(GUEST_SS_AR_BYTES);
    u64 cr0   = vmcs_read(GUEST_CR0);
    u64 cr4   = vmcs_read(GUEST_CR4);

    /* Check CR0 fixed bits (Intel SDM §26.3.1.1) */
    u64 cr0_fixed0 = rdmsr(MSR_IA32_VMX_CR0_FIXED0);
    u64 cr0_fixed1 = rdmsr(MSR_IA32_VMX_CR0_FIXED1);
    if ((cr0 & cr0_fixed0) != cr0_fixed0 ||
        (~cr0 & ~cr0_fixed1) != 0) {
        pr_err("phantom: VMCS CR0 fixed bit violation: cr0=0x%llx\n", cr0);
        return -EINVAL;
    }

    /* Check CS access rights: must not be unusable (bit 16 = 0 for CS) */
    if (ar_cs & VMX_SEGMENT_AR_UNUSABLE) {
        pr_err("phantom: VMCS CS marked unusable\n");
        return -EINVAL;
    }

    /* ... all other §26.3 checks ... */
    return 0;
}
```

## Key Data Structures

```c
/* VM exit reason codes (Intel SDM Vol. 3C Appendix C) */
#define VMX_EXIT_EXCEPTION_NMI    0   /* Exception or NMI                   */
#define VMX_EXIT_EXTERNAL_INT     1   /* External interrupt                  */
#define VMX_EXIT_TRIPLE_FAULT     2   /* Triple fault                        */
#define VMX_EXIT_CPUID           10   /* CPUID instruction                   */
#define VMX_EXIT_VMCALL          18   /* VMCALL instruction (hypercall)      */
#define VMX_EXIT_EPT_VIOLATION   48   /* EPT violation                       */
#define VMX_EXIT_EPT_MISCONFIG   49   /* EPT misconfiguration                */
#define VMX_EXIT_PREEMPT_TIMER   52   /* VMX preemption timer fired          */
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/vmx_core.c` | VMCS guest-state setup, VM exit dispatch, NMI handler |
| `kernel/debug.c` | VMCS dump-on-failure, VMCS field validator |
| `kernel/hypercall.c` | Basic VMCALL handler skeleton |
| `kernel/nmi.c` | NMI-exiting handler, APIC self-NMI re-delivery |

## Reference Sections

- §2.3: VMCS field enumeration with hex IDs — all segment registers, MSRs, system registers, interrupt state
- §2.6: NMI handling design — NMI exiting, APIC self-NMI re-delivery, NMI-safe handler requirements
- §5.6 Appendix B §1: VMCS dump format — structured output, trace_printk usage
- §5.6 Appendix B §5: VMCS field validator — Intel SDM §26.3 checks, compilation guard

## Tests to Run

- Guest returns the correct checksum value for a known input (pass = host-side verification succeeds)
- VMCS field validator catches at least one deliberately malformed field and rejects VMLAUNCH (pass = validator fires, no VM entry attempted)
- VMCALL data passes correctly in both directions: host→guest payload address, guest→host checksum (pass = checksum value matches expected)
- VMCS dump is produced on an unhandled exit reason (pass = structured dump appears in trace log with field names and values)
- NMI delivered during guest execution is handled without handler corruption (pass = no host oops, NMI visible in host via re-delivery; test on bare metal or with a real NMI source — nested KVM NMI injection is a fallback)
- **Bare metal:** deliberately invalid segment access rights, out-of-range CR0 fixed bits, and a reserved-field violation each produce the expected VM-entry failure without host panic (pass = tests pass on bare metal; nested KVM result alone is insufficient for these cases)

## Deliverables

Guest code runs and returns results to host via `/dev/phantom` ioctl.
