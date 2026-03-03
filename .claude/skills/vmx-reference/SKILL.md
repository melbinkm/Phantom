---
name: vmx-reference
description: VMX instruction reference for Phantom kernel module development. Auto-load when writing VMXON, VMCS, VMLAUNCH, VMRESUME, VM exit handler code.
user-invocable: false
disable-model-invocation: false
---

# VMX Reference for Phantom

## VMXON Region Setup

```c
/* 1. Check VT-x support: CPUID.1:ECX.VMX[bit 5] */
if (!(cpuid_ecx(1) & (1 << 5))) return -ENODEV;

/* 2. Allocate 4KB VMXON region, page-aligned */
vmxon_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
phys_addr  = page_to_phys(vmxon_page);

/* 3. Write VMCS revision identifier into first 4 bytes */
u32 revision = rdmsr(MSR_IA32_VMX_BASIC) & 0x7fffffff;
*(u32 *)page_address(vmxon_page) = revision;

/* 4. Enable CR4.VMXE */
write_cr4(read_cr4() | X86_CR4_VMXE);

/* 5. Execute VMXON */
asm volatile("vmxon %0" :: "m"(phys_addr) : "cc", "memory");
```

## VMXON Return Codes

- `CF=1` — VMXON failed (VMX already active, region not page-aligned, wrong revision ID, or other error). **Authoritative conflict check.**
- `ZF=1` — VM-instruction error; read VMCS field `VM_INSTRUCTION_ERROR` (0x4400) if a VMCS is current.
- `CF=ZF=0` — VMXON succeeded.

## CR4.VMXE Pre-Check

`read_cr4() & X86_CR4_VMXE` is a fast hint that VMX is in use on this core. It is a TOCTOU pre-check only — the VMXON attempt is the definitive ownership check.

**Advisory warning (not enforcement):** emit `pr_warn` if `kvm_intel` is loaded, but the VMXON attempt is what matters.

## Module Init: Partial VMXON Recovery

If VMXON fails on core N, execute VMXOFF on cores 0..N-1 before returning error. Prevents VMX state leak on multi-core init failure.

## VMCS Field Enumeration (hex IDs)

### Segment Registers (8 × 4 sub-fields)

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

### Descriptor Tables
- GDTR: base=0x6816, limit=0x4810
- IDTR: base=0x6818, limit=0x4812

### Control Registers
- CR0=0x6800, CR3=0x6802, CR4=0x6804, DR7=0x681A

### MSRs in VMCS Guest-State Area
- `IA32_DEBUGCTL`=0x2802, `IA32_PAT`=0x2804, `IA32_EFER`=0x2806
- `IA32_PERF_GLOBAL_CTRL`=0x2808, `IA32_BNDCFGS`=0x2812
- `IA32_RTIT_CTL`=0x2814 (if PT-in-VMX supported)

### System Registers
- SMBASE=0x6078, `IA32_SYSENTER_CS`=0x482A
- `IA32_SYSENTER_ESP`=0x6824, `IA32_SYSENTER_EIP`=0x6826
- VMX preemption timer=0x482E

### Guest Interrupt State
- Interruptibility state=0x4824, Pending debug exceptions=0x6822
- VMCS link pointer=0x2800, Activity state=0x4826
- PDPTE entries=0x280A–0x2810 (PAE paging)

## VM Exit Reason Codes

```c
#define VMX_EXIT_EXCEPTION_NMI    0   /* Exception or NMI — check interruption-info */
#define VMX_EXIT_EXTERNAL_INT     1   /* External interrupt — re-inject to host */
#define VMX_EXIT_TRIPLE_FAULT     2   /* Guest triple-faulted — crash result */
#define VMX_EXIT_CPUID           10   /* CPUID — minimal emulation */
#define VMX_EXIT_VMCALL          18   /* Hypercall dispatch */
#define VMX_EXIT_EPT_VIOLATION   48   /* CoW fault handler */
#define VMX_EXIT_EPT_MISCONFIG   49   /* EPT misconfiguration — debug error */
#define VMX_EXIT_PREEMPT_TIMER   52   /* Watchdog timeout — abort iteration */
```

## VM Entry/Exit Control Bits

### Pin-Based VM-Execution Controls
- Bit 3: NMI exiting — enable so NMIs cause VM exit (reason 0) instead of guest delivery
- Bit 5: Virtual NMIs — optional, for NMI-window exiting approach
- Bit 6: Activate VMX preemption timer — enable for watchdog

### VM-Entry Controls
- Bit 18: Load IA32_RTIT_CTL — preferred PT enable on entry (PT-in-VMX)

### VM-Exit Controls
- Bit 25: Clear IA32_RTIT_CTL — preferred PT disable on exit (PT-in-VMX)

## NMI Handling

With "NMI exiting" (pin-based bit 3) enabled:
- NMI during guest → VM exit with reason 0
- Interruption-info field (VMCS 0x4404): vector=2, type=2, valid bit set
- NMI is NOT delivered to guest

**Re-delivery (recommended — APIC self-NMI):**
```c
apic_write(APIC_ICR, APIC_DEST_SELF | APIC_DELIVERY_MODE_NMI);
```
KVM uses this same approach (`self_nmi()` / `kvm_inject_nmi()`).

**Avoid `INT 2`** — it does not set NMI-blocking and does not follow the NMI delivery path.

VM exit handler must be NMI-safe: no spinlocks held, no non-reentrant structures accessed.

**Host config:** Add `nmi_watchdog=0` to kernel cmdline on dedicated fuzzing cores.

## VMX Preemption Timer (Watchdog)

- VMCS pin-based control bit 6: "activate VMX preemption timer"
- Countdown rate: determined by `IA32_VMX_MISC` bits 4:0 (typically TSC / 2^N)
- Set value in VMCS field 0x482E before every VMRESUME
- Timeout → VM exit reason 52 (`VMX_EXIT_PREEMPT_TIMER`)
- **On timeout:** set `PHANTOM_RESULT_TIMEOUT`, perform snapshot restore, return to userspace

## VMCS Field Validator (debug builds only)

Validate all guest-state VMCS fields against Intel SDM §26.3 before every VMLAUNCH/VMRESUME:
- CR0/CR4 fixed bits: check against `IA32_VMX_CR0_FIXED0/1`, `IA32_VMX_CR4_FIXED0/1`
- Segment register access rights: S/E/W bit consistency
- Control field consistency

Guard with `#ifdef PHANTOM_DEBUG`. Compiled out in production.
