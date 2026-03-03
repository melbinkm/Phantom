# Task 3.1: Minimal Linux Guest Boot

> **Phase:** Kernel Fuzzing — Class B | **Week(s):** 22–23 | **Depends on:** [Task 2.4](../phase-2-fuzzing-pipeline/task-2.4-class-a-hardening-bugs.md)

## Objective

Boot a minimal Linux kernel (bzImage) inside Phantom, reaching the custom harness init. Handle all MSR exits, deterministic TSC, and APIC timer suppression.

## What to Build

- Guest kernel preparation: custom `defconfig` (minimal kernel, no modules, no initrd, no networking); disable `CONFIG_PREEMPT`, `CONFIG_SMP`, `CONFIG_RANDOMIZE_BASE`, `CONFIG_RANDOMIZE_KSTACK_OFFSET`, `CONFIG_SLAB_FREELIST_RANDOM`, `CONFIG_SLAB_FREELIST_HARDENED`, `CONFIG_GCC_PLUGIN_RANDSTRUCT`, `CONFIG_RANDOM_TRUST_CPU`; enable `CONFIG_KASAN` for bug detection; custom `init`: kernel thread that loads fuzzing harness and enters fuzz loop
- Guest kernel loading: parse bzImage format and extract protected-mode kernel; populate `boot_params` structure with e820 map (RAM + APIC/IOAPIC/HPET reserved) and memory sizing fields; configure VMCS for Linux boot protocol; map kernel into guest EPT (RAM pages, not identity-mapped to host physical)
- Additional VM exit handling: MSR access (RDMSR/WRMSR for kernel-expected MSRs), TSC virtualisation via VMCS TSC offset field for deterministic timestamps, APIC timer suppression via LVTT mask during execution window, realistic CPUID emulation matching a real CPU

## Implementation Guidance

### Class B Guest Boot Protocol

The guest kernel expects the following from the boot loader (Phantom fills this role):

**boot_params structure (from §3 Class B):**

```c
struct boot_params {
    /* e820 memory map — must match a plausible server config */
    struct e820_entry e820_map[E820_MAX_ENTRIES];
    u8    e820_entries;         /* Number of valid e820 entries             */

    /* Memory sizing fields */
    u32   alt_mem_k;            /* Alternative extended memory (KB)        */
    u16   mem_upper;            /* Extended memory above 1MB (KB)          */
    u16   mem_lower;            /* Extended memory below 1MB (KB)          */

    /* Kernel command line */
    u32   cmd_line_ptr;         /* Physical address of command line string */

    /* ... other Linux boot protocol fields ... */
};

/* Example e820 map for 256MB Class B guest */
static struct e820_entry class_b_e820[] = {
    { .addr = 0x00000000, .size = 0x0009F000, .type = E820_RAM },    /* Low RAM */
    { .addr = 0x00100000, .size = 0x0EF00000, .type = E820_RAM },    /* Main RAM (256MB - 1MB) */
    { .addr = 0xFEE00000, .size = 0x00001000, .type = E820_RESERVED }, /* LAPIC */
    { .addr = 0xFEC00000, .size = 0x00001000, .type = E820_RESERVED }, /* IOAPIC */
    { .addr = 0xFED00000, .size = 0x00000400, .type = E820_RESERVED }, /* HPET */
};
```

### Required defconfig Flags

From §3 Class B:

```
# Disable randomisation sources (determinism)
CONFIG_RANDOMIZE_BASE=n
CONFIG_RANDOMIZE_KSTACK_OFFSET=n
CONFIG_SLAB_FREELIST_RANDOM=n
CONFIG_SLAB_FREELIST_HARDENED=n
CONFIG_GCC_PLUGIN_RANDSTRUCT=n
CONFIG_RANDOM_TRUST_CPU=n

# Disable preemption and SMP (single-vCPU fuzzing)
CONFIG_PREEMPT=n
CONFIG_SMP=n

# Enable bug detection
CONFIG_KASAN=y

# Minimal config (no modules, no networking, no initrd)
CONFIG_MODULES=n
CONFIG_NET=n
CONFIG_BLK_DEV_INITRD=n
```

### MSR Exit Handling

The guest kernel probes various MSRs during boot. Implement handlers:

```c
static int phantom_handle_msr_read(struct phantom_instance *inst, u32 msr)
{
    switch (msr) {
    case MSR_IA32_APICBASE:
        /* Return APIC base with APIC enabled, xAPIC mode */
        vcpu_set_reg(inst, VCPU_REG_RAX, 0xFEE00900);
        return 0;
    case MSR_IA32_TSC:
        /* Return deterministic TSC = snapshot_tsc + inst->tsc_offset */
        vcpu_set_reg(inst, VCPU_REG_RAX, inst->snapshot_tsc + inst->tsc_offset);
        return 0;
    case MSR_IA32_MISC_ENABLE:
        /* Turbo boost disabled, XD bit enable */
        vcpu_set_reg(inst, VCPU_REG_RAX, 0x850089);
        return 0;
    /* ... other kernel-expected MSRs ... */
    default:
        pr_warn_ratelimited("phantom: unhandled RDMSR 0x%x\n", msr);
        /* Return 0 — most MSRs safe to return 0 for a minimal guest */
        vcpu_set_reg(inst, VCPU_REG_RAX, 0);
        vcpu_set_reg(inst, VCPU_REG_RDX, 0);
        return 0;
    }
}
```

### TSC Virtualisation

Use VMCS TSC offset field for deterministic `rdtsc`:

```c
/* VMCS field 0x2010: TSC_OFFSET (64-bit) */
/* Guest rdtsc = host_tsc + TSC_OFFSET */

/* At snapshot time: record the snapshot TSC */
inst->snapshot_tsc = rdtsc_ordered();
/* Set TSC_OFFSET so guest rdtsc = 0 at snapshot point */
vmcs_write64(TSC_OFFSET, -(u64)inst->snapshot_tsc);

/* Result: guest rdtsc returns 0 at snapshot, advances deterministically
 * from there based on actual instruction count */
```

### APIC Timer Suppression

During the fuzzing execution window, suppress all APIC timer interrupts:

```c
/* At snapshot point (ACQUIRE hypercall handler) */
static void phantom_suppress_apic_timer(struct phantom_instance *inst)
{
    /* Mask LVTT (Local Vector Table Timer) in APIC */
    /* Guest-visible APIC is emulated — store masked state */
    inst->apic_lvtt_masked = true;

    /* Any APIC timer VM exit during execution window is a bug */
    inst->expect_apic_timer_exit = false;
}

/* Verify: zero spurious APIC timer VM exits during execution */
/* On exit reason = APIC timer during execution window: */
static int phantom_handle_unexpected_apic_timer(struct phantom_instance *inst)
{
    pr_warn("phantom: spurious APIC timer during execution — check LVTT mask\n");
    inst->apic_timer_spurious_count++;
    /* Do not inject to guest — guest timer should be frozen */
    return phantom_vmresume(inst);
}
```

**jiffies freeze:** Since timer interrupts are suppressed during execution, `jiffies` is effectively frozen at snapshot value — this is correct and desirable.

### GDT/IDT/TSS CoW Notes

From §3:
- **TSS page:** Modified on every privilege-level switch (RSP0 update). Will appear in dirty list every iteration. Verify and test explicitly.
- **GDT and IDT pages:** Should be read-only after boot. Verify they do NOT appear in dirty list under normal operation.
- **Custom init:** A kernel thread that loads the fuzzing harness module and enters the fuzz loop. Snapshot taken after module init completes.

## Key Data Structures

```c
/* bzImage protected-mode kernel header (at offset 0x1F1 in bzImage) */
struct linux_kernel_header {
    u8  setup_sects;      /* Size of real-mode code in 512-byte sectors */
    u16 root_flags;
    u32 syssize;          /* Size of 32-bit code in 16-byte paragraphs */
    /* ... */
    u32 header;           /* Magic: 0x53726448 ("HdrS") */
    u16 version;          /* Boot protocol version */
    u32 realmode_swtch;
    u16 start_sys_seg;
    u32 code32_start;     /* Load address for 32-bit kernel */
    u32 ramdisk_image;
    u32 ramdisk_size;
    /* ... */
    u64 pref_address;     /* Preferred load address for 64-bit kernel */
};
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/vmx_core.c` | MSR exit handler, TSC virtualisation, APIC timer suppression |
| `kernel/ept.c` | Class B EPT map with realistic e820-derived layout |
| `guest/guest_kernel/defconfig` | Minimal kernel config for Class B |
| `guest/guest_kernel/init_harness.c` | Custom kernel init for fuzzing |

## Reference Sections

- §3: Class B full — `boot_params`, e820 map requirements, determinism source overview, defconfig flags
- §3: TSS CoW note — RSP0 dirty-list tracking, GDT/IDT not-in-dirty-list verification

## Tests to Run

- Kernel reaches custom init and prints "ready" via VMCALL/PRINTF hypercall (pass = host-side receives expected PRINTF output string)
- MSR exits handled without host crash for all kernel-expected MSRs (pass = no unexpected exit reason, no host oops across a full boot sequence)
- TSC reads are deterministic across two independent runs (pass = same rdtsc value at fixed instruction offset in both runs)
- No spurious APIC timer VM exits during fuzzing execution window (pass = zero timer exits in exit reason log during an iteration)
- e820 map is correct in guest boot log (pass = guest dmesg shows the expected memory layout matching host-provided boot_params)

## Deliverables

Minimal Linux kernel boots inside Phantom and reaches harness entry point.
