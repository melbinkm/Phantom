# Task 0.1: VMX Feasibility Spike

> **Phase:** Feasibility Spike | **Week(s):** 0 (Days 1–5) | **Depends on:** *(none)*

## Objective

Validate the development environment and basic VMX instruction sequencing before any Phase 1 production code is written. This is a **throwaway spike** — learning and risk reduction only.

## What to Build

- Load Bareflank (or equivalent minimal VMX example) in nested KVM on the development machine
- Enter VMX root mode (`VMXON`) successfully
- Launch a trivial guest (infinite loop or VMCALL exit)
- Handle one VMCALL exit in the host
- Handle one EPT violation (access to unmapped page)
- Exit VMX root mode (`VMXOFF`) cleanly
- Crash once and diagnose via serial console or kdump

## Implementation Guidance

### Deployment Architecture

Phantom runs on a **dedicated fuzzing machine**. The host Linux installation exists solely to provide a userspace environment for frontends, corpus management, and PT decoding. KVM must not be loaded during VMX experiments.

```
┌────────────────────────────────────────────────────────────┐
│                      USERSPACE                              │
│   ┌──────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│   │  AFL++   │  │ kAFL/Python  │  │  PT Decode Daemon   │ │
│   │  mutator │  │  frontend    │  │  (libipt, bitmap)   │ │
│   └────┬─────┘  └──────┬───────┘  └──────────┬──────────┘ │
│        └───────────────┼────────────────────┘              │
│                        ▼                                    │
│              /dev/phantom (ioctl + mmap)                    │
├────────────────────────┼───────────────────────────────────┤
│                   KERNEL SPACE                              │
│   ┌──────────────────────────────────────────────────┐     │
│   │            phantom.ko (GPL-2.0)                   │     │
│   │  ┌───────────┐ ┌──────────────┐ ┌─────────────┐  │     │
│   │  │ VMX Core  │ │ EPT Manager  │ │  Intel PT   │  │     │
│   │  │ VMXON     │ │ CoW engine   │ │  MSR config │  │     │
│   │  │ VMCS Mgmt │ │ Page fault   │ │  ToPA setup │  │     │
│   │  │ VM Entry/ │ │ handler      │ │  (no decode)│  │     │
│   │  │ Exit      │ │              │ │             │  │     │
│   │  └───────────┘ └──────────────┘ └─────────────┘  │     │
│   └──────────────────────────────────────────────────┘     │
├────────────────────────────────────────────────────────────┤
│                       HARDWARE                              │
│   Intel VT-x (VMX)  │  EPT + A/D bits  │  Intel PT        │
└────────────────────────────────────────────────────────────┘
```

### VMX-Root Exclusivity (Context for the Spike)

**Phantom requires exclusive VMX-root ownership.** Key facts to validate during this spike:

- `kvm_intel` module must be unloaded before loading any VMX example. Run: `sudo rmmod kvm_intel kvm`
- `phantom.ko` will check VMX ownership on each designated core by attempting `VMXON`; if VMXON fails with CF=1 (VMX-already-active), another entity owns VMX on that core
- Pre-check `CR4.VMXE` via `read_cr4()` as a fast hint — if already set, VMX is in use on that core
- The machine should be a dedicated fuzzing box — not a shared development server

During the spike, verify:
1. After `rmmod kvm_intel`, `CR4.VMXE` is 0 on all cores
2. `VMXON` succeeds (CF=0, ZF=0) after the module is unloaded
3. `VMXON` fails (CF=1) if you attempt it while KVM is loaded

### VMXON Region Setup (Step-by-Step)

```c
/* 1. Check CPU supports VT-x */
if (!(cpuid_ecx(1) & (1 << 5))) {
    pr_err("VMX not supported\n");
    return -ENODEV;
}

/* 2. Allocate 4KB VMXON region, page-aligned */
vmxon_region = (u32 *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
phys_addr = virt_to_phys(vmxon_region);

/* 3. Write VMCS revision identifier into first 4 bytes */
u32 revision = rdmsr_safe(MSR_IA32_VMX_BASIC) & 0x7fffffff;
*vmxon_region = revision;

/* 4. Enable CR4.VMXE */
cr4 = read_cr4();
write_cr4(cr4 | X86_CR4_VMXE);

/* 5. Execute VMXON with physical address */
asm volatile("vmxon %0" :: "m"(phys_addr) : "cc", "memory");

/* 6. Check CF and ZF for success */
/* CF=1:    VMXON failed — VMX already active on this core, VMXON region not  */
/*          page-aligned, revision ID wrong, or other instruction error       */
/* ZF=1:    VM-instruction error — treat as failure; error code readable from */
/*          VM_INSTRUCTION_ERROR VMCS field (0x4400) if a VMCS is current    */
/* CF=ZF=0: VMXON succeeded                                                   */
```

### EPT Violation Handler (Spike Minimum)

For the spike, a minimal EPT violation handler just needs to:

```c
static void handle_ept_violation(struct vcpu *vcpu)
{
    u64 gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
    u64 exit_qual = vmcs_read(EXIT_QUALIFICATION);

    pr_info("EPT violation: GPA=0x%llx qual=0x%llx\n", gpa, exit_qual);

    /* For the spike: just abort — no CoW yet */
    vcpu->run_result = PHANTOM_RESULT_CRASH;
    /* Do NOT attempt VMRESUME — guest is aborted */
}
```

The exit qualification bits for EPT violations:
- Bit 0: read access caused violation
- Bit 1: write access caused violation
- Bit 2: instruction fetch caused violation
- Bit 3: guest physical address is readable in EPT
- Bit 4: guest physical address is writable in EPT
- Bit 5: guest physical address is executable in EPT
- Bit 7: GPA valid (in GUEST_PHYSICAL_ADDRESS VMCS field)

### kdump Post-Mortem Procedure

When a host kernel panic occurs (expected during this spike):

1. kdump captures crash dump to dedicated partition (configured at OS install, Week 1 deliverable)
2. Boot to recovery: `crash /usr/lib/debug/vmlinux /var/crash/<dump>/vmcore`
3. Examine Phantom state:
   - `crash> mod -s phantom` — load Phantom module symbols
   - `crash> bt <phantom_vmx_exit_handler>` — backtrace from last known handler
   - `crash> struct phantom_instance <addr>` — inspect per-CPU instance state

**Serial console to a second machine is a hard requirement** — not optional. Without it, debugging host panics in the nested KVM environment is infeasible. Set up in Week 1 before writing any VMX code. Procedure:
- Development machine: add `console=ttyS0,115200` to kernel cmdline
- Second machine: `screen /dev/ttyUSB0 115200` (or minicom)
- Verify: reboot dev machine, confirm boot messages appear on second machine

## Key Data Structures

```c
/* Minimal VMXON/VMCS region layout */
struct vmxon_region {
    u32 revision_id;  /* IA32_VMX_BASIC[30:0] — VMCS revision identifier */
    u8  data[4092];   /* Remainder of 4KB page — processor-managed        */
};

/* Minimal VM exit reason encoding */
#define VMX_EXIT_VMCALL          18  /* Guest executed VMCALL instruction  */
#define VMX_EXIT_EPT_VIOLATION   48  /* Guest accessed unmapped/wrong-perm EPT */
#define VMX_EXIT_TRIPLE_FAULT     2  /* Guest triple-faulted               */
```

## Source Files to Modify

This spike produces **throwaway code only** — no source files survive into Phase 1. Suggested spike file layout:
- `spike/vmxon_test.c` — VMXON/VMXOFF and basic guest launch
- `spike/ept_test.c` — minimal EPT setup and violation handler
- `spike/notes.md` — findings, surprises, tooling gaps

## Reference Sections

- §2.1: Deployment model and architecture diagram — full ASCII diagram of Phantom's component stack
- §2.2: VMX-root exclusivity — why kvm_intel must be unloaded, VMXON conflict detection procedure
- §5.6 (Appendix B): kdump post-mortem procedure — step-by-step crash dump analysis
- §7: Hardware requirements — CPU, RAM, serial console, second machine spec

## Tests to Run

- `VMXON` succeeds on the nested KVM host (pass = no CF=1 error, no host panic)
- Trivial guest exits via VMCALL (pass = exit reason in host handler matches VMCALL, execution returns to host)
- EPT violation on an unmapped page is caught and handled rather than producing a host panic (pass = host handler receives the exit, iteration aborted cleanly)
- Serial console captures crash output on the second machine, or kdump produces a usable crash dump (pass = either method yields readable post-mortem data)

## Deliverables

- Written notes on what worked, what was surprising, and any tooling gaps discovered — these notes inform Phase 1 implementation

## Exit Criteria

Notes exist and cover each of the 7 items above. If the spike takes >5 days (e.g., nested KVM setup issues, debugging environment problems), extend Phase 1a by 1 week before starting. Do not skip the spike to "save time" — the spike saves more time than it costs.

**Validates:** Development environment setup (nested KVM, serial console, kdump), basic VMX instruction sequencing, VMCS field access, EPT violation handling path.
