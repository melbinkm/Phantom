# Phantom — Determinism Sources and Mitigations

All 13 non-determinism sources that must be eliminated before the 1000/1000
gate (Task 3.2 gating criterion).  Each entry states whether the mitigation
is compile-time (guest defconfig) or runtime (phantom.ko), and how to verify
it.

---

## Source 1: TSC (Time Stamp Counter)

| Field | Value |
|-------|-------|
| Type | runtime |
| Mitigation | VMCS `TSC_OFFSET` field zeroed at snapshot restore; guest `rdtsc` reads a deterministic value from the snapshot point |
| File | `kernel/vmx_core.c` — `phantom_snapshot_restore()` |
| Verification | After two identical-input runs, `rdtsc` guest result at HC_RELEASE must be identical |

The VMX preemption timer is also disabled during fuzzing iterations
(`VMCS_PREEMPTION_TIMER_VALUE = 0`) to prevent timer-driven divergence.

---

## Source 2: APIC Timer

| Field | Value |
|-------|-------|
| Type | runtime |
| Mitigation | `CONFIG_X86_LOCAL_APIC=n` in guest defconfig disables the APIC entirely; timer interrupts cannot fire |
| File | `guest/guest_kernel/defconfig` |
| Verification | `dmesg` in guest shows no APIC initialisation; `jiffies` stays at boot value across iterations |

Without a local APIC, no LVTT timer fires, so jiffies is effectively frozen
at the value captured at the HC_ACQUIRE snapshot point.

---

## Source 3: External Interrupts

| Field | Value |
|-------|-------|
| Type | runtime |
| Mitigation | VM-exit on external interrupt (pin-based VMCS control bit 0); host IDT handles the interrupt; interrupt is NOT injected into guest during the fuzzing window |
| File | `kernel/vmx_core.c` — `phantom_handle_external_interrupt()` |
| Verification | After any external-interrupt VM-exit (reason 1), count must equal zero injections into guest |

The "acknowledge interrupt on exit" VM-exit control (bit 15 of VM-exit
controls) is set so the host CPU processes the interrupt before the VM-exit
handler runs, eliminating the interrupt from guest state entirely.

---

## Source 4: RNG (get_random_bytes / /dev/urandom)

| Field | Value |
|-------|-------|
| Type | compile-time + runtime |
| Mitigation | `CONFIG_RANDOM_TRUST_CPU=n`, `CONFIG_RANDOM_TRUST_BOOTLOADER=n` prevent seed injection from hardware RNG at boot; snapshot captures entropy pool state; HC_ACQUIRE restores it |
| File | `guest/guest_kernel/defconfig` |
| Verification | Two runs with same input must produce same `get_random_bytes` output (verify via kernel printk in test harness) |

---

## Source 5: Kernel Stack Offset Randomisation

| Field | Value |
|-------|-------|
| Type | compile-time |
| Mitigation | `CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=n` |
| File | `guest/guest_kernel/defconfig` |
| Verification | Stack pointer at syscall entry identical across all runs |

---

## Source 6: Slab Freelist Randomisation

| Field | Value |
|-------|-------|
| Type | compile-time |
| Mitigation | `CONFIG_SLAB_FREELIST_RANDOM=n` |
| File | `guest/guest_kernel/defconfig` |
| Verification | `kmalloc` return addresses identical across runs |

---

## Source 7: RANDSTRUCT (GCC plugin struct layout randomisation)

| Field | Value |
|-------|-------|
| Type | compile-time |
| Mitigation | `CONFIG_GCC_PLUGINS=n` disables all GCC plugins including RANDSTRUCT; `CONFIG_GCC_PLUGIN_RANDSTRUCT=n` stated explicitly for clarity |
| File | `guest/guest_kernel/defconfig` |
| Verification | Struct field offsets in `System.map` must be identical across kernel builds |

Note: `CONFIG_GCC_PLUGIN_RANDSTRUCT=n` is redundant when `CONFIG_GCC_PLUGINS=n`
is set.  It is included explicitly so this audit table is complete and machine-
searchable.

---

## Source 8: KASLR (Kernel Address Space Layout Randomisation)

| Field | Value |
|-------|-------|
| Type | compile-time |
| Mitigation | `CONFIG_RANDOMIZE_BASE=n` |
| File | `guest/guest_kernel/defconfig` |
| Verification | `_text` symbol address in `System.map` identical across boots |

---

## Source 9: RDRAND / RDSEED Instructions

| Field | Value |
|-------|-------|
| Type | runtime |
| Mitigation | CPUID emulator masks RDRAND capability (leaf 1 ECX bit 30 = 0) and RDSEED capability (leaf 7 EBX bit 18 = 0); Linux checks CPUID before using these instructions |
| File | `kernel/cpuid_emul.c` — `phantom_cpuid_emulate()` |
| Verification | Guest `cpuid` with leaf 1: ECX bit 30 must be 0; leaf 7 subleaf 0: EBX bit 18 must be 0 |

Linux ≥ 6.2 uses `alternatives`-based patching from CPUID results at boot.
Masking at snapshot-time CPUID queries is sufficient because the kernel reads
CPUID before the snapshot point.

---

## Source 10: Preemption

| Field | Value |
|-------|-------|
| Type | compile-time |
| Mitigation | `CONFIG_PREEMPT_NONE=y` — no voluntary or forced preemption; single-vCPU guest |
| File | `guest/guest_kernel/defconfig` |
| Verification | No preempt-related context switches visible in guest trace |

---

## Source 11: SMP (Symmetric Multi-Processing)

| Field | Value |
|-------|-------|
| Type | compile-time |
| Mitigation | `CONFIG_SMP=n`, `CONFIG_NR_CPUS=1` — uniprocessor kernel, no IPI races |
| File | `guest/guest_kernel/defconfig` |
| Verification | Guest `nr_cpu_ids == 1` at runtime |

---

## Source 12: jiffies

| Field | Value |
|-------|-------|
| Type | runtime (depends on source 2) |
| Mitigation | APIC timer suppression (source 2) eliminates the interrupt that increments `jiffies`; `jiffies` is frozen at the value captured at HC_ACQUIRE |
| File | `guest/guest_kernel/defconfig` (via `CONFIG_X86_LOCAL_APIC=n`) |
| Verification | `jiffies` value identical at HC_RELEASE across all 1000 runs |

---

## Source 13: Slab Freelist Hardening

| Field | Value |
|-------|-------|
| Type | compile-time |
| Mitigation | `CONFIG_SLAB_FREELIST_HARDENED=n` |
| File | `guest/guest_kernel/defconfig` |
| Verification | No hardening-related entropy consumed at `kmalloc` time |

---

## Determinism Gate Definition

```
Quantified criterion (§9 of project-phantom-dev-plan-v2.md):
"Identical input produces byte-identical PT trace (with CYCEn=MTCEn=TSCEn=0;
 no timing packets) and identical register state 1000/1000 times."
```

Fields checked across all 1000 iterations:

| Field | Size | Notes |
|-------|------|-------|
| RIP | u64 | Guest instruction pointer at HC_RELEASE |
| RSP | u64 | Guest stack pointer at HC_RELEASE |
| RFLAGS | u64 | Guest flags at HC_RELEASE |
| CR3 | u64 | Guest page table root at HC_RELEASE |
| RAX..R15 | 16×u64 | All general-purpose registers |
| dirty_count | u32 | Number of dirtied pages |
| dirty_gpas[] | u64[] | GPAs of each dirtied page, in order |

Intel PT trace bytes are also checked (byte-identical) when
`CYCEn=MTCEn=TSCEn=PTWEn=0` in `IA32_RTIT_CTL`.

---

## PT Timing Packet Suppression

`IA32_RTIT_CTL` bits that MUST be 0 for byte-identical traces:

| Bit | Name | Must be |
|-----|------|---------|
| 1 | CYCEn | 0 — disable CYC packets |
| 4 | PTWEn | 0 — disable PTWRITE packets |
| 9 | MTCEn | 0 — disable MTC packets |
| 10 | TSCEn | 0 — disable TSC packets |

Verification: decoded trace (via libipt) must contain zero CYC, MTC, TSC,
or PTWRITE packets.

---

## Verification Script

```bash
sudo bash tests/integration/test_determinism.sh \
  /root/phantom/linux-6.1.90/arch/x86/boot/bzImage \
  1000
```

Or directly with the Python checker:

```bash
sudo python3 tests/integration/determinism_check.py \
  --bzimage /root/phantom/linux-6.1.90/arch/x86/boot/bzImage \
  --iterations 1000
```
