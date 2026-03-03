# Project Phantom — Bare-Metal Hypervisor Fuzzer

## Development Plan v2.1

**Classification:** Internal — Development Team
**Date:** March 2026
**Project Lead:** Melbin
**Estimated Timeline:** ~10 months (40 weeks) to publishable release
**Revision Notes:** v2.0 incorporates architectural review feedback. Key changes: Class C (full VM/userland) removed from scope, EPT Copy-on-Write snapshot design from day one, Intel PT decode moved to userspace, performance claims narrowed, timeline extended, GPL licensing addressed. v2.1 adds: MMIO/XSAVE/NMI/watchdog design, expanded VMCS field enumeration, Week 0 feasibility spike, Phase 1 split into 1a/1b (Weeks 1–12), new sections 2.5–2.7 (watchdog, NMI, shared memory coherency), 5.5–5.6 (error handling, observability), 6.5–6.9 (security model, design alternatives, rollback, memory accounting, kernel compatibility), NUMA allocation strategy, quantified test exit criteria, and updated paper evaluation methodology.

---

## 1. Executive Summary

Project Phantom is a purpose-built micro-hypervisor for coverage-guided fuzzing. It operates as a Linux kernel module that takes exclusive ownership of VMX-root on dedicated hardware, replacing the KVM + QEMU stack with a minimal, fuzzing-optimised alternative. The result is significant throughput improvement over state-of-the-art hypervisor-based fuzzers (kAFL/Nyx) while retaining compatibility with existing AFL++/kAFL frontends and guest harnesses.

### What Phantom Is Not

Phantom is not a general-purpose hypervisor. It does not run arbitrary VMs, emulate devices beyond the bare minimum, or coexist with KVM. It is a **dedicated fuzzing appliance** that happens to use hardware virtualisation as its execution engine.

### Scope (v2.0)

| In Scope | Out of Scope (Future Work) |
|----------|---------------------------|
| Class A: Standalone parser/function fuzzing | Class C: Full VM with userland binaries |
| Class B: Kernel module fuzzing (minimal Linux guest) | Virtio device emulation |
| kAFL/Nyx harness ABI compatibility | General-purpose VM hosting |
| AFL++ frontend integration | Windows guest support |
| Multi-core parallel fuzzing | FPGA/SmartNIC acceleration |
| Intel PT coverage (userspace decode) | |

### Performance Targets (Single Core)

| Metric | kAFL/Nyx (Current SOTA) | Phantom Target (Class A) | Phantom Target (Class B) |
|--------|------------------------|--------------------------|--------------------------|
| Exec/sec | 10k–20k | 50k–500k | 30k–100k |
| Snapshot restore latency | 100–500μs | <5μs (tiny dirty set) to ~50μs (large dirty set) | 10–100μs (kernel-sized dirty set) |
| Coverage overhead | 1–5% | <1% (PT config in kernel, decode in userspace, off hot path) | <1% |
| Input injection latency | ~5μs (hypercall through KVM+QEMU) | <1μs (EPT write) | <1μs |
| Memory per instance | 200MB–1GB | 10–50MB | 50–200MB |

**Performance claim guidance:** Benchmarks will report "Nx faster than kAFL/Nyx for target class Y on hardware Z with dirty page footprint W." We do not claim a blanket multiplier. Expected range: **3–10x for kernel targets (Class B), 10–50x for standalone parsers (Class A)**, with the speedup heavily dependent on dirty page footprint per iteration.

---

## 2. Architecture

### 2.1 Deployment Model

Phantom runs on a **dedicated fuzzing machine**. The host Linux installation exists solely to provide a userspace environment for frontends, corpus management, and PT decoding. KVM must not be loaded.

```
┌────────────────────────────────────────────────────────────┐
│                      USERSPACE                              │
│                                                             │
│   ┌──────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│   │  AFL++   │  │ kAFL/Python  │  │  PT Decode Daemon   │ │
│   │  mutator │  │  frontend    │  │  (libipt, bitmap)   │ │
│   └────┬─────┘  └──────┬───────┘  └──────────┬──────────┘ │
│        └───────────────┼────────────────────┘              │
│                        ▼                                    │
│              /dev/phantom (ioctl + mmap)                    │
│              ┌────────────────────────────┐                 │
│              │  Shared memory regions:    │                 │
│              │  - Payload buffer          │                 │
│              │  - Coverage bitmap (64KB)  │                 │
│              │  - ToPA PT trace buffer    │                 │
│              │  - Status/control struct   │                 │
│              └────────────────────────────┘                 │
├────────────────────────┼───────────────────────────────────┤
│                   KERNEL SPACE                              │
│                        ▼                                    │
│   ┌──────────────────────────────────────────────────┐     │
│   │            phantom.ko (GPL-2.0)                   │     │
│   │                                                   │     │
│   │  ┌───────────┐ ┌──────────────┐ ┌─────────────┐ │     │
│   │  │ VMX Core  │ │ EPT Manager  │ │  Intel PT   │ │     │
│   │  │ VMXON     │ │ CoW engine   │ │  MSR config │ │     │
│   │  │ VMCS Mgmt │ │ Page fault   │ │  ToPA setup │ │     │
│   │  │ VM Entry/ │ │ handler      │ │  (no decode)│ │     │
│   │  │ Exit      │ │              │ │             │ │     │
│   │  └───────────┘ └──────────────┘ └─────────────┘ │     │
│   │  ┌───────────┐ ┌──────────────┐ ┌─────────────┐ │     │
│   │  │ Hypercall │ │  Snapshot    │ │  Per-CPU    │ │     │
│   │  │ Handler   │ │  Controller  │ │  Instance   │ │     │
│   │  │ (nyx ABI) │ │  (CoW reset) │ │  Manager    │ │     │
│   │  └───────────┘ └──────────────┘ └─────────────┘ │     │
│   └──────────────────────────────────────────────────┘     │
├────────────────────────────────────────────────────────────┤
│                       HARDWARE                              │
│   Intel VT-x (VMX)  │  EPT + A/D bits  │  Intel PT        │
│   PML (optional)     │  ToPA             │  IP Filtering    │
└────────────────────────────────────────────────────────────┘
```

### 2.2 VMX-Root Exclusivity

**Phantom requires exclusive VMX-root ownership.** This means:

- `kvm_intel` module must be unloaded before loading `phantom.ko` (advisory — emits `pr_warn` if detected)
- `phantom.ko` checks VMX ownership on each designated core by attempting `VMXON`; if VMXON fails with CF=1 (VMX-already-active), module load aborts with a per-core diagnostic. Pre-checks `CR4.VMXE` as a fast hint. This is the authoritative VMX conflict check — module presence alone does not determine VMX state.
- The machine is a dedicated fuzzing box — not a shared development server
- Module init: `VMXON` on all designated cores; module cleanup: `VMXOFF` + full state restore

This is a hard constraint, not an implementation detail. The plan does not attempt KVM coexistence.

### 2.3 EPT Copy-on-Write Snapshot Design

This is the core architectural decision and Phantom's primary performance advantage. The snapshot engine uses EPT-based Copy-on-Write rather than dirty page copying.

**Snapshot creation:**

1. At snapshot point, mark all guest EPT entries as **read-only**
2. Record VMCS guest state fields to a host-side structure (see enumeration below)
3. The "snapshot" is the current EPT mapping + saved VMCS — no memory copying

**During execution (post-snapshot):**

1. Guest writes to a page → EPT violation (write to read-only page)
2. EPT violation handler:
   - Allocates a **private page** from a pre-allocated pool
   - Copies original page content to private page
   - Updates EPT entry to point to private page with read-write permissions
   - Records the private page in a per-iteration **dirty list**
3. Guest resumes with write succeeding on the private page

**Snapshot restore:**

1. Walk the dirty list (typically 10–500 entries for kernel fuzzing)
2. For each entry: reset EPT mapping back to the original read-only page
3. Release private pages back to the pool (no deallocation, just pointer reset)
4. Restore VMCS guest state from saved structure
5. Flush relevant TLB entries (INVEPT) — **single INVEPT after all EPT updates**
6. `VMRESUME`

**Why this is fast:**

- Restore is proportional to **number of dirty pages**, not total guest memory
- No memcpy of page content during restore (just pointer swaps in EPT)
- Pre-allocated page pool avoids `kmalloc` in the hot path
- For Class A targets with tiny dirty sets (10–50 pages): restore is <5μs
- For Class B targets with larger dirty sets (200–1000 pages): restore is 10–100μs

**Critical design details:**

- Page pool must be sized for worst-case dirty set × number of parallel instances
- Pool exhaustion → abort iteration, not host panic
- EPT invalidation strategy: per-context INVEPT (not global) to avoid cross-core TLB shootdowns
- Must handle 2MB large pages: split to 4KB on first CoW fault in that region

```
SNAPSHOT STATE                    DURING EXECUTION

EPT                               EPT
┌─────────┐                       ┌─────────┐
│ Page 0  │──→ [Original 0] RO    │ Page 0  │──→ [Original 0] RO
│ Page 1  │──→ [Original 1] RO    │ Page 1  │──→ [Private  1] RW  ← guest wrote here
│ Page 2  │──→ [Original 2] RO    │ Page 2  │──→ [Original 2] RO
│ Page 3  │──→ [Original 3] RO    │ Page 3  │──→ [Private  3] RW  ← guest wrote here
└─────────┘                       └─────────┘

RESTORE: reset Page 1 → Original 1 (RO), Page 3 → Original 3 (RO)
         return Private 1, Private 3 to pool
         restore VMCS, INVEPT, VMRESUME
         (no page content was copied)
```

#### MMIO Handling

Guest physical address (GPA) ranges must be classified before EPT construction:

- **RAM** (CoW-eligible): guest-usable physical memory pages. CoW applies normally.
- **MMIO** (trap-and-emulate): the following GPA ranges are MMIO and must NOT receive CoW private pages:
  - `0xFEE00000` — Local APIC (LAPIC) registers
  - `0xFEC00000` — I/O APIC (IOAPIC) registers
  - `0xFED00000` — HPET registers
  - Any other firmware/device MMIO regions identified from e820 map
- **Reserved** (not-present in EPT): holes in physical memory map — EPT entry absent, any guest access triggers EPT violation → abort iteration.

**CoW handler must reject MMIO pages.** If an EPT violation fires on an MMIO GPA:
- Do not allocate a private page
- Emulate the MMIO access (read/write the appropriate virtual register)
- Resume guest with result in guest register state

#### Memory Type Consistency

Private CoW pages must inherit the EPT memory type (bits 5:3 of EPT PTE) from the original EPT mapping:

- WB (Write-Back, type 6): standard RAM pages — use this for all CoW private pages
- UC (Uncacheable, type 0): device memory — CoW must not apply
- WC (Write-Combining, type 1): framebuffer / device MMIO — CoW must not apply

Before marking a page CoW-eligible during EPT construction, check the memory type field. Only WB pages enter the CoW pool.

#### INVEPT Batching Strategy

**SDM guarantee (§28.3.3.1):** An EPT violation invalidates cached translations for the *faulting* GPA only. Other GPAs may retain stale cached translations. This determines when INVEPT is and is not required.

**4KB RO→RW promotion (permission-only change, no structural change):** Do NOT issue INVEPT. The faulting GPA's cached translation was invalidated by the EPT violation itself (SDM §28.3.3.1). Update the EPT entry and execute VMRESUME immediately. The CPU re-walks the EPT for the faulting GPA and picks up the new RW permission. No other GPAs are affected — the page-table structure is unchanged.

**2MB→4KB structural split:** INVEPT IS required before VMRESUME. When a 2MB EPT large-page entry is replaced with a 4KB-level EPT page table (see §2MB Page Splitting below), the page-table structure changes. Non-faulting GPAs within the same 2MB range may have stale cached 2MB translations pointing to the old large-page frame. Issue a single-context INVEPT (type 1) after completing the split and before VMRESUME.

**During restore (end-of-iteration reset):** Issue a **single INVEPT (single-context, type 1)** after all EPT entries in the dirty list have been reset to their original mappings. This batches all invalidations into one operation. (Unchanged — already correct.)

**Formal invariant:** Every EPT structural change (page-table level insertion or removal) requires INVEPT before the next VMRESUME. Permission-only changes to the faulting PTE do not require INVEPT — the EPT violation itself invalidates the faulting GPA's cached translation.

**Alternative considered:** `INVVPID` type 3 (all-context) — rejected due to cross-core overhead. Single-context INVEPT is sufficient because Phantom uses per-instance EPT pointers and cores are not sharing EPT structures.

#### 2MB Page Splitting

When a CoW fault occurs on a GPA covered by a 2MB EPT large-page entry:

1. Allocate 512 × 4KB EPT PTEs, populate by splitting the 2MB mapping
2. Insert the new 4KB-level EPT PT into the EPT PD entry (replacing the large-page bit)
3. Only the single faulting 4KB page receives a private CoW copy; the remaining 511 pages stay read-only mapped to the original 2MB frame
4. Track split pages per iteration in a per-instance split-page list for potential re-coalescing at restore time (optimisation — not required for correctness in Phase 1)

#### VMCS Guest State: Explicit Field Enumeration

The snapshot must save and restore the following VMCS guest-state fields (not just "GP regs, segment regs, CR0/3/4, EFER, etc."):

**General-purpose registers** (saved in host memory, not VMCS fields):
- RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, R8–R15, RIP, RFLAGS

**Segment registers** (8 × 4 sub-fields each):
- CS, SS, DS, ES, FS, GS, LDTR, TR
- Each with: selector, base, limit, access rights (as per Intel SDM Vol. 3C §24.4.1)

**Descriptor table registers:**
- GDTR: base (64-bit), limit (32-bit)
- IDTR: base (64-bit), limit (32-bit)

**Control registers:**
- CR0, CR3, CR4, DR7

**MSRs stored in VMCS guest-state area:**
- `IA32_DEBUGCTL` (VMCS field 0x2802)
- `IA32_PAT` (VMCS field 0x2804)
- `IA32_EFER` (VMCS field 0x2806)
- `IA32_PERF_GLOBAL_CTRL` (VMCS field 0x2808, if VMCS control enabled)
- `IA32_BNDCFGS` (VMCS field 0x2812, if MPX enabled)
- `IA32_RTIT_CTL` (VMCS field 0x2814, if PT-in-VMX supported)

**System registers:**
- SMBASE (VMCS field 0x6078)
- `IA32_SYSENTER_CS` (VMCS field 0x482A)
- `IA32_SYSENTER_ESP` (VMCS field 0x6824)
- `IA32_SYSENTER_EIP` (VMCS field 0x6826)
- VMX preemption timer value (VMCS field 0x482E, if preemption timer enabled)

**Guest interrupt state:**
- Interruptibility state (VMCS field 0x4824)
- Pending debug exceptions (VMCS field 0x6822)
- VMCS link pointer (VMCS field 0x2800)
- Activity state (VMCS field 0x4826)

**PDPTE entries** (4 × 64-bit, VMCS fields 0x280A–0x2810): required when guest is using PAE paging (CR4.PAE=1, CR0.PG=1, IA32_EFER.LME=0 or 32-bit PAE mode).

#### XSAVE / Extended Register State

The snapshot must save and restore extended processor state beyond the basic FPU/SSE context.

**At snapshot time:** Execute `XSAVE` (or `XSAVEOPT`) to a per-instance XSAVE area to capture:
- SSE state: XMM0–XMM15 (128-bit each)
- AVX state: YMM0–YMM15 upper halves (if OSXSAVE + AVX)
- AVX-512 state: ZMM0–ZMM31 + mask registers k0–k7 (if AVX-512 supported)
- PKRU (Protection Key Rights for User pages, if PKU supported)

**At restore time:** Execute `XRSTOR` from the saved XSAVE area.

**Implementation notes:**
- Determine required XSAVE area size via `CPUID.(EAX=0Dh, ECX=0).EBX`:
  - SSE + AVX: ~832 bytes
  - SSE + AVX + AVX-512: ~2.5KB
- **Fixed XCR0 model (Phase 1–3 policy):** The guest XCR0 is set equal to the host's XCR0 at instance creation time. Guest `XSETBV` instructions cause a VM exit (trapped) and are rejected — the guest cannot change XCR0. This avoids host/guest XCR0 mismatch entirely. Blindly executing `XSETBV` in VMX-root with the guest's XCR0 value modifies the physical XCR0 that the host kernel relies on for its own FPU context; if the guest XCR0 differs from the host's, host kernel FPU operations after the XRSTOR will produce incorrect results.
- **At snapshot:** `XSAVE` uses the host's XCR0 (no `XSETBV` needed — XCR0 is already correct). Save the XSAVE area.
- **At restore:** No `XSETBV` needed (XCR0 is already correct under the fixed XCR0 model). Execute `kernel_fpu_begin()` → `XRSTOR` from saved area → `kernel_fpu_end()` to bracket the operation within the kernel's FPU context discipline. This ensures the host kernel's lazy FPU save is aware the xstate was touched.
- **Alternative (future — virtualised XCR0):** If a future design allows guest XCR0 to differ from host: save host XCR0 → `XSETBV(guest_xcr0)` → `XRSTOR` → `XSETBV(host_xcr0)` → restore host xstate. This is complex and not needed for Phase 1–3 targets (bare-metal parsers and minimal Linux guests use the same feature set as the host).
- Verify `CR4.OSXSAVE` is set before issuing XSAVE/XRSTOR in VM exit handler
- Account for **~200–400 cycles additional latency** in restore path for XRSTOR; include in restore latency estimates
- Allocate XSAVE area as 64-byte aligned (required by `XSAVE`/`XRSTOR`)
- If guest does not use AVX/AVX-512 (detectable via CPUID probing during guest boot), save only SSE state to reduce overhead

### 2.4 Intel PT: Kernel Configures, Userspace Decodes

The kernel module is responsible only for Intel PT hardware configuration. All trace decoding happens in a userspace daemon.

**Kernel responsibilities (phantom.ko):**

- Program `IA32_RTIT_CTL` MSR (enable PT, configure filtering)
- Set up ToPA (Table of Physical Addresses) for trace output buffers
- Configure IP filtering to trace only the guest target range
- Enable/disable PT tracing across VM entry/exit boundaries (see below)
- Expose ToPA buffers to userspace via `mmap` on `/dev/phantom`

**PT Enable/Disable Strategy (replacing ambiguous "toggle TraceEn" approach):**

The preferred approach for enabling PT only during guest execution is:

1. **VMCS entry/exit PT controls (preferred):** Use VMCS VM-entry control bit 18 ("load IA32_RTIT_CTL") and VM-exit control bit 25 ("clear IA32_RTIT_CTL") if the CPU supports PT-in-VMX (check `IA32_VMX_TRUE_ENTRY_CTLS` bit 18 and `IA32_VMX_TRUE_EXIT_CTLS` bit 25 via RDMSR at module init). This is the cleanest mechanism — hardware automatically enables PT on VM entry and disables it on VM exit with no handler overhead.

2. **VMCS MSR load/store lists (fallback):** If PT-in-VMX controls are unavailable, add `IA32_RTIT_CTL` to the VMCS VM-entry MSR-load list (to enable PT on entry) and VM-exit MSR-store/load lists (to save PT state on exit and restore host PT state). More complex but functionally equivalent.

3. **Avoid:** Manual MSR writes in the VM exit handler. Writing `IA32_RTIT_CTL` in the exit handler creates an ambiguous tracing window (are we tracing exit handler code?) and adds latency on every VM exit.

**Important:** Host code executing in the VM exit handler is **NOT traced** under either preferred approach. This is correct for coverage accuracy — we want only guest execution traced. Verify this during PT integration testing.

**PT packet options for determinism:** Raw PT byte identity holds only if timing packets are suppressed. Configure `IA32_RTIT_CTL` with the following bits cleared at instance creation and never changed:
- `CYCEn` (bit 1) = 0 — disable CYC (cycle-count) packets; these vary with wall-clock timing even for identical control flow
- `MTCEn` (bit 9) = 0 — disable MTC (mini-TSC) packets; same reason
- `TSCEn` (bit 10) = 0 — disable TSC packets; same reason
- `PTWEn` (bit 4) = 0 — disable PTWRITE packets (unless the target is known to use the PTWRITE instruction)

With these disabled, the PT packet stream contains only control-flow packets (TNT, TIP, FUP, MODE, PSB, PSBEND, CBR) whose byte sequence is fully determined by the executed instruction stream. Identical control flow then produces a byte-identical trace, making the determinism gate valid. **The determinism test must fail if any timing packet type is accidentally enabled.** Verify by checking the decoded trace contains no CYC/MTC/TSC/PTWRITE packets.

**ToPA output registers and per-iteration reset procedure:**

Two distinct MSRs govern PT output:
- `IA32_RTIT_OUTPUT_BASE` (MSR 0x560): physical address of the ToPA table — set once at instance creation, **constant across iterations** (always points to the start of the ToPA table, never modified during fuzzing).
- `IA32_RTIT_OUTPUT_MASK_PTRS` (MSR 0x561): the current write pointer — encodes the current ToPA table entry index (bits [47:3]) and byte offset within the current output region (bits [31:7]). This is advanced by hardware as PT writes packets. **Reset to zero at each iteration boundary** to restart writing from the beginning of the ToPA buffer.

Exact MSR sequence at each iteration boundary (executed in VMX-root after VM exit, before signalling userspace):
1. PT is already stopped: `IA32_RTIT_CTL.TraceEn` was cleared by the VM-exit control (`clear IA32_RTIT_CTL` on exit); verify with `RDMSR(0x570)` bit 0 = 0 in debug builds.
2. Read byte count: `RDMSR(IA32_RTIT_STATUS)` (MSR 0x571) → extract `PacketByteCnt` field (bits [48:32]). This is the number of valid PT bytes written this iteration.
3. Signal userspace: write byte count to the shared status structure; increment eventfd counter via `eventfd_signal()`.
4. Reset write pointer: `WRMSR(IA32_RTIT_OUTPUT_MASK_PTRS, 0)` — resets both table-entry index and byte offset to zero (start of first ToPA output region).
5. Clear status register: `WRMSR(IA32_RTIT_STATUS, 0)` — clears `PacketByteCnt`, overflow flag, and trigger/error bits.
6. `IA32_RTIT_OUTPUT_BASE` is NOT written — it remains pointing to the ToPA table throughout.

PT is re-enabled on the next VM entry via the `load IA32_RTIT_CTL` VM-entry control (or MSR-load list entry), which restores `IA32_RTIT_CTL` with `TraceEn=1`.

**Userspace responsibilities (phantom-pt-decode daemon):**

- `mmap` the ToPA buffer from `/dev/phantom`
- After each iteration: read the raw PT packets
- Decode using `libipt` to reconstruct control flow
- Convert to AFL-compatible 64KB edge bitmap
- Write bitmap to shared memory region (also mmap'd by AFL++/kAFL frontend)
- Pipeline: decode iteration N while kernel executes iteration N+1

**Why this split matters:**

- `libipt` is a complex C library designed for userspace; porting to kernel is fragile
- Decode errors in kernel → host panic; decode errors in userspace → log and retry
- Decode latency is **off the hot path**: kernel runs the next iteration while userspace decodes the previous one's trace (pipelined)
- Easier to debug, profile, and replace the decoder

**PT Decode Backpressure Design:**

To handle cases where userspace decode lags behind kernel execution:

- **Double-buffering:** Allocate two ToPA buffers per instance (buffer A and buffer B). Kernel writes iteration N trace to buffer A while userspace decodes buffer B (iteration N-1 trace). After each iteration, swap roles. This eliminates any decode-window blocking in the common case.
- **Notification primitive:** Use `eventfd` for kernel-to-userspace iteration-complete signalling. The kernel increments the eventfd counter via `eventfd_signal()` after each iteration completes. This is lower-latency and lower-overhead than alternatives (character device `read()` wakeup, signals, etc.). Note: `eventfd` and `poll`/`epoll` are complementary, not alternatives — `epoll` is the correct way to wait on eventfds.
- **Multiplexing:** The userspace decode daemon uses `epoll` to wait on multiple eventfds (one per managed instance) in a single thread. When an eventfd fires, the daemon decodes the corresponding instance's ToPA buffer.
- **Backpressure policy (default — correctness-first):** If the decode daemon has not finished decoding buffer B by the time the kernel needs to write buffer B again, the kernel waits (blocks in IOCTL) rather than overwriting un-decoded data. This preserves coverage accuracy at the cost of throughput reduction during backpressure events. A health metric — "decode lag events per 1000 iterations" — is exposed via debugfs.
- **Configurable skip mode:** A per-instance flag `skip_coverage_on_lag` allows the kernel to skip coverage recording for iterations where the decode daemon is behind. This maximises throughput at the cost of potentially missing some coverage edges. Default: off (correctness-first). Enable explicitly for throughput benchmarks.

**Pipeline timing:**

```
Core (kernel):   [run iter N] [restore] [run iter N+1] [restore] [run iter N+2]
                      │                      │
                      ▼                      ▼
Decode (user):   [decode N-1] [bitmap]  [decode N]  [bitmap]  [decode N+1]
```

The decode of iteration N happens in parallel with execution of iteration N+1. This means decode latency does not directly impact exec/sec, as long as decode throughput keeps up with execution throughput.

### 2.5 Watchdog Timer

**Mechanism:** Use the **VMX preemption timer** (VMCS pin-based VM-execution control bit 6, "activate VMX preemption timer"). This is a hardware countdown that causes a VM exit with exit reason 52 (`VMX_EXIT_PREEMPTION_TIMER`) when it reaches zero. It is TSC-scaled: the preemption timer counts down at a rate determined by `IA32_VMX_MISC` bits 4:0 (typically TSC / 2^N ticks).

**Why preemption timer over APIC timer injection:**
- No guest interrupt injection required — preserves guest interrupt state and execution determinism
- Fires as a VM exit regardless of guest interrupt masking (EFLAGS.IF, LAPIC mask)
- Instance remains in a clean, recoverable state after timeout VM exit
- No interaction with guest APIC state or timer virtualisation

**Per-iteration timeout budget:**
- Expressed in TSC ticks, converted to preemption timer ticks at instance creation
- Set in VMCS field 0x482E (32-bit) on every VMRESUME
- Typical budget: 10M–100M TSC ticks (≈3–30ms at 3GHz), configurable per target class

**On timeout VM exit (reason 52):**
1. The preemption timer fires → VM exit reason 52 → iteration is aborted (no useful result from this iteration's execution).
2. Set iteration result to `PHANTOM_RESULT_TIMEOUT` in the status word.
3. Perform snapshot restore (reset dirty list, restore VMCS, XRSTOR, INVEPT) — this is mandatory to return guest state to the snapshot point before the next iteration can begin.
4. Return to userspace. The instance is fully usable for the next `PHANTOM_RUN_ITERATION` call.

### 2.6 NMI Handling

NMIs (Non-Maskable Interrupts) can arrive at any time, including during guest execution. Mishandling them corrupts host state.

**VM exit on NMI:** With "NMI exiting" (pin-based VM-execution control bit 3) enabled, an NMI during guest execution causes a VM exit with basic exit reason **0** ("Exception or NMI"). The VM-exit interruption-information field (VMCS 0x4404) will have vector=2, type=2 (NMI), valid bit set. The NMI is **not** delivered to the guest. Note: exit reason 0 is "Exception or NMI"; external interrupts are exit reason **1** — these are distinct exit reasons.

**Re-delivery to host:** After completing the VM exit handler, re-deliver the NMI to the host via one of these approaches:

- **(a) APIC self-NMI (recommended):** Write to the local APIC ICR (destination=self, delivery mode=NMI). This queues an NMI that the host IDT handles normally after the VM exit handler returns. This is the approach used by KVM (`self_nmi()` / `kvm_inject_nmi()`). Clean separation between VMX-root handler and NMI delivery.
- **(b) Virtual-NMI IRET unblocking:** If using "virtual NMIs" (pin-based bit 5), IRET in VMX-root mode clears NMI-blocking, allowing a pending NMI to be delivered through the host IDT. Requires careful stack management to ensure the IRET frame is correct.
- **Avoid `INT 2`:** `INT 2` is a software interrupt to vector 2. It does not set NMI-blocking and does not follow the NMI delivery path — it has different semantics from a hardware NMI and must not be used for NMI re-delivery.
- **Avoid direct IDT call:** Bypasses the NMI-blocking protocol and can corrupt host NMI state.

**VM exit handler (NMI path):**
1. Re-deliver NMI to host via APIC self-NMI (option a above) or virtual NMIs (option b above).
2. The VM exit handler must be **NMI-safe**: no spinlocks held during NMI delivery, no non-reentrant data structures accessed.

**"NMI-window exiting" (VMCS primary processor-based VM-execution control, bit 22):** Consider enabling this for deferred NMI processing. When set, the CPU exits when the guest is in a state where it can receive an NMI (i.e., NMI-blocking cleared). This allows deferring NMI re-injection to a safe point without losing the NMI.

**Host configuration:** On dedicated fuzzing cores, add `nmi_watchdog=0` to the kernel command line to suppress the NMI watchdog. This eliminates a major source of unexpected NMI events and simplifies the NMI handler. Remaining NMI sources (hardware errors, `perf` NMIs) must still be handled gracefully.

### 2.7 Shared Memory Coherency Model

Phantom's correctness depends on the host CPU correctly observing guest memory writes and the guest correctly observing host-written payload data. The single-core execution model simplifies this significantly.

**Payload buffer (host writes, guest reads):**
- Host userspace writes the fuzz payload into the payload buffer via the mmap'd region
- **Correctness invariant:** The host's payload store must be globally visible before the guest's first load from the payload buffer. Additionally, VMCS writes (via VMWRITE) must be committed before VMRESUME.
- **Implementation (same-core pinning):** Phantom pins each instance's ioctl execution to the same physical core that executes VMRESUME. On x86, a core's stores are visible to its own subsequent loads in program order (TSO guarantee). This means no explicit memory barrier is needed between the payload write and VMRESUME — program order suffices. Same-core pinning is a **correctness simplification** (it reduces the memory model to single-core sequential consistency and eliminates all inter-core barriers from the hot path), not a fundamental correctness requirement — a cross-core design would require `smp_store_release()` on the payload write and acquire semantics before VMRESUME.
- **Affinity enforcement:** The ioctl handler calls `get_cpu()` (disables preemption, returns current CPU) and verifies it matches the instance's pinned core. If not, returns `-EINVAL`. `put_cpu()` after VMRESUME returns. This prevents CPU migration during the ioctl, which would break the same-core assumption.
- Map the payload buffer as **WB (Write-Back)** in both the host virtual mapping and the guest EPT mapping. WC or UC mappings would add unnecessary write latency.

**Cross-core coherency:** Under the per-CPU pinning model (each instance pinned to a dedicated physical core), there are no cross-core coherency concerns for the payload buffer or guest memory. No MFENCE or inter-processor flush is required during the hot path. MFENCE may be needed during instance setup/teardown when ownership transfers between cores.

**Cross-core case (not currently used):** If a future design allows the ioctl to run on a different core than VMRESUME, the payload write must use `smp_store_release()` and the guest-visible mapping must ensure acquire semantics (or a full `smp_mb()` before VMRESUME). This adds ~10–30 cycles. Not implemented in the current per-CPU pinning model; documented here for completeness.

**Guest-to-host result delivery (status word):** Guest writes iteration result (ok/crash/timeout/kasan) via VMCALL (hypercall). The hypercall handler runs in VMX-root mode on the same physical core. No memory barrier is needed — the store from the hypercall handler is visible to the subsequent ioctl return on the same core.

---

## 3. Target Classes

### Class A: Standalone Parser / Function (Primary)

The target is a single function compiled into a minimal guest binary. No OS required.

- Guest is a flat binary or minimal ELF loaded directly by Phantom
- Function receives fuzz input via shared memory (VMCALL to get payload address)
- Function returns via VMCALL (normal exit) or triggers exception (crash)
- Dirty page footprint: typically 10–50 pages (stack + heap)
- Expected throughput: 50k–500k exec/sec

**EPT memory map (Class A):** Simple flat GPA-to-HPA identity mapping is acceptable. Guest physical memory is a single contiguous region. No complex e820 map required. MMIO ranges (APIC, IOAPIC) are excluded from the identity map and handled via EPT-absent entries (trap to handler or mark not-present).

**Example targets:** image parsers (libpng, libjpeg-turbo), crypto routines (OpenSSL primitives), protocol parsers (TLS record parsing, DNS packet parsing), file format parsers (ELF, PDF, ZIP headers).

### Class B: Kernel Module (Secondary, Paper Contribution)

The target is a Linux kernel subsystem. A minimal Linux kernel boots as the guest.

- Minimal bzImage (no initrd, no userspace, custom init that loads the harness module)
- Harness module uses nyx_api hypercalls to coordinate with Phantom
- Fuzz input injected via shared memory, harness calls target subsystem
- Snapshot taken after kernel boot + module init, before first iteration
- Dirty page footprint: typically 200–2000 pages (kernel heap, slabs, per-CPU data)
- Expected throughput: 30k–100k exec/sec

**EPT memory map (Class B):** Class B requires a realistic guest physical memory map. The guest kernel probes the memory layout via the boot_params e820 table during early boot. Requirements:

- EPT must present a **fake physical memory map** matching a plausible server configuration (e.g., one contiguous RAM region from 0–256MB, APIC/IOAPIC at standard MMIO addresses)
- Guest physical memory is allocated via **high-order `alloc_pages(GFP_KERNEL, order)`** or per-page with individual EPT mappings — explicitly **NOT** identity-mapped to host physical addresses
- The `boot_params` structure (including e820 map) must be populated by Phantom before VMLAUNCH:
  - e820 map entries: RAM region, reserved regions for APIC/IOAPIC/HPET, ACPI tables if needed
  - `e820_entries` count, `alt_mem_k`, `mem_upper`, `mem_lower` fields
- **GDT/IDT/TSS CoW note:** The guest TSS page is modified on every privilege-level switch (RSP0 update during syscall/interrupt). This page will appear in the dirty list on every iteration. Verify the TSS page is correctly captured in the dirty list and restored. Add explicit test cases:
  - Execute a function that performs a privilege-level switch → verify TSS page in dirty list
  - Restore snapshot → verify TSS contains original RSP0 value
  - GDT and IDT pages should be read-only (rarely modified after boot) — verify they are NOT in the dirty list under normal operation

**Determinism challenges (Class B):** Kernel fuzzing introduces non-determinism from multiple sources. Each must be explicitly addressed:

- **Timer interrupts:** Must suppress or virtualise APIC timer during execution window
- **TSC reads:** Guest TSC must return deterministic values (trap RDTSC or use TSC offsetting in VMCS)
- **Scheduler activity:** Minimal kernel config disabling preemption reduces this
- **KASLR:** Disable in guest kernel config (`CONFIG_RANDOMIZE_BASE=n`), or record layout at snapshot time
- **Slab allocator state:** Snapshot includes slab state; CoW handles mutations
- **`jiffies`:** The global kernel timer tick counter is incremented by the timer interrupt. Since we suppress timer interrupts during execution, `jiffies` is effectively frozen at snapshot value — this is correct and desirable. Verify that timer interrupt suppression is complete (LVTT masked, no spurious APIC timer VMexits during execution window).
- **`kstack_offset_randomize()`:** Kernel stack offset randomisation per-syscall. Disable via `CONFIG_RANDOMIZE_KSTACK_OFFSET=n` in guest defconfig.
- **Memory allocator randomisation:** Newer kernels (6.x) include slab freelist randomisation. Disable via `CONFIG_SLAB_FREELIST_RANDOM=n` and `CONFIG_SLAB_FREELIST_HARDENED=n` in guest defconfig for deterministic testing. Re-enable for production targets.
- **`get_random_bytes()` in kernel code paths:** Guest kernel's RNG may produce non-deterministic output if seeded from hardware (RDRAND) or entropy pool. Seed the guest RNG deterministically at snapshot time (inject fixed seed via hypercall before snapshot). Use `CONFIG_RANDOM_TRUST_CPU=n` to prevent hardware-seeded boot entropy.
- **RDRAND/RDSEED direct execution:** Seed injection covers the kernel's `get_random_bytes()` path but does NOT cover guest or kernel code that executes `RDRAND`/`RDSEED` instructions directly (these bypass the software RNG entirely). Mitigation: mask out `RDRAND` (CPUID leaf 1, ECX bit 30) and `RDSEED` (CPUID leaf 7, EBX bit 18) in the guest CPUID responses so that the guest kernel and guest code treat these instructions as absent and fall back to software RNG. Alternatively, trap and emulate `RDRAND`/`RDSEED` at the #UD exception handler and return a deterministic PRNG value seeded at snapshot time. The CPUID masking approach is simpler and sufficient for Class B targets (the Linux kernel checks CPUID before using RDRAND). **Note:** trapping via exception bitmap requires the guest to receive `#UD` on RDRAND/RDSEED; only works if the CPU actually raises #UD when the CPUID bit is clear (Linux ≥ 6.2 does `alternatives`-based patching at boot from CPUID, so masking at snapshot-time CPUID queries is sufficient).
- **`CONFIG_GCC_PLUGIN_RANDSTRUCT=n`:** Structure layout randomisation introduced in kernel 6.x. Disable for reproducible structure offsets during harness development and determinism testing.

Each source must be explicitly addressed. The determinism test (identical trace for identical input, 1000 repetitions) is a **gating criterion** for Phase 3, not just a nice-to-have.

**Example targets:** nf_tables (netfilter), eBPF verifier, ext4/btrfs filesystem parsers, Bluetooth L2CAP, USB driver interfaces.

### Class C: Full VM with Userland Binary — DEFERRED

Class C (fuzzing userland binaries like OpenSSH, curl, nginx) requires virtio device emulation, a userspace runtime, and filesystem state management. This scope is explicitly deferred to future work.

Including Class C would require re-implementing a subset of QEMU's device model, which contradicts Phantom's design goal of eliminating QEMU overhead. If the dirty page footprint from device emulation + userspace approaches QEMU's overhead anyway, the performance advantage vanishes.

**Future approach (when revisited):** Consider a hybrid where Phantom handles execution and snapshots, but delegates device emulation to a stripped QEMU instance (similar to how kAFL uses QEMU-Nyx for device models but overrides snapshot/coverage). This preserves the snapshot speed win without reimplementing device emulation.

---

## 4. Reuse Strategy

### 4.1 Components to Reuse

| Component | Source | License | Integration Notes |
|-----------|--------|---------|-------------------|
| VMX bootstrap primitives | Bareflank Hypervisor | MIT | Extract VMXON/VMCS setup. Reference only — our EPT CoW design differs significantly from Bareflank's default EPT. |
| Intel PT packet decoder | libipt (Intel) | BSD-3-Clause | Runs in userspace daemon. Drop-in. |
| Mutation engine | AFL++ | Apache-2.0 | Runs in userspace, communicates via shared memory. Zero kernel integration needed. |
| kAFL frontend | kAFL (Intel Labs) | MIT + GPL-2.0 | Runs in userspace. Modify to send ioctls to `/dev/phantom` instead of KVM. |
| Guest harness API | nyx_api.h | MIT | Use as-is. Our hypercall handler implements identical ABI. |
| Existing kAFL guest harnesses | kAFL targets repo | MIT | Binary compatible with Phantom if hypercall ABI matches. |
| Redqueen (magic byte solving) | kAFL/Nyx | MIT | Host-side logic reused. Introspection adapted to our EPT. |
| Coverage bitmap format | AFL shared memory convention | N/A | Standard 64KB bitmap. Same format, different transport. |
| Minimal Linux guest kernel | Custom defconfig | GPL-2.0 | Stripped kernel for Class B. Not bundled — built from upstream sources. |

### 4.2 Components to Write

| Component | Est. Lines | Complexity | Critical Path? |
|-----------|-----------|------------|---------------|
| `vmx_core.c` — VMXON, VMCS, entry/exit dispatch | ~1500 | High | Yes |
| `ept.c` — EPT construction + CoW fault handler | ~1200 | High | Yes — most performance-critical code |
| `ept_cow.c` — Page pool, dirty list, CoW logic | ~800 | High | Yes |
| `snapshot.c` — VMCS save/restore + CoW reset orchestration | ~600 | High | Yes |
| `hypercall.c` — nyx_api VMCALL handler | ~500 | Medium | No |
| `pt_config.c` — Intel PT MSR + ToPA setup | ~300 | Medium | No |
| `interface.c` — `/dev/phantom` chardev, ioctl, mmap | ~600 | Medium | No |
| `multicore.c` — Per-CPU instance management | ~400 | Medium | No (Phase 4) |
| `debug.c` — VMCS dump, EPT walker, observability tools | ~600 | Medium | No (but needed from Week 1) |
| `phantom-pt-decode` — Userspace PT decode daemon | ~800 | Medium | No |
| `phantom-ctl` — Userspace CLI + kAFL bridge | ~500 | Low | No |
| **Total new code** | **~7800** | | |

### 4.3 CoW Pool and ToPA Sizing

**CoW pool sizing:**

- Minimum pool size formula: `pool_size >= max_dirty_pages_per_iteration * 4KB`
- For Class A: 50 pages × 4KB = 200KB minimum; recommended default: 16MB (4096 pages, ample headroom)
- For Class B: 2000 pages × 4KB = 8MB minimum; recommended default: 64MB (16384 pages) to handle worst-case iteration plus some buffer

**Total per-instance memory:**

```
total_per_instance = guest_mem + cow_pool + topa_buffers + ept_tables + vmcs + xsave_area
```

- `guest_mem`: 16MB (Class A) or 256MB (Class B)
- `cow_pool`: 16MB (Class A) or 64MB (Class B)
- `topa_buffers`: 2 × 2MB (Class A) or 2 × 8MB (Class B) for double-buffering, allocated via multi-entry ToPA (NOT necessarily physically contiguous — see ToPA sizing section)
- `ept_tables`: ~2MB for 256MB guest (4-level EPT, 4KB pages throughout)
- `vmcs`: one 4KB page per vCPU
- `xsave_area`: ~4KB (rounded up from 2.5KB for AVX-512)

**16-core Class B example:**

```
16 × (256MB + 64MB + 16MB + 2MB + misc) ≈ 16 × 340MB ≈ 5.4GB
```

Plan for 8GB reserved exclusively for Phantom on a 64GB machine with 16 Class B instances.

**ToPA sizing:**

- **Class A default:** 2MB per buffer (double-buffering: 4MB total per instance). Class A targets have tight control flow, modest PT output.
- **Class B default:** 8MB per buffer (16MB total per instance). Kernel targets generate more PT packets per iteration.

**Multi-entry ToPA allocation:** ToPA is designed for scatter-gather output. A ToPA table is an array of ToPA entries, each pointing to an independent physically contiguous region. Intel PT writes sequentially through entries. Do NOT require a single large contiguous allocation — `alloc_pages(GFP_KERNEL, 11)` for an 8MB contiguous buffer will frequently fail on fragmented systems.

Allocation strategy for an 8MB Class B buffer:
- **First try:** 4 × 2MB (`alloc_pages(GFP_KERNEL, 9)`) — fewer ToPA entries, larger contiguous regions per entry
- **Fallback:** 2048 × 4KB (`alloc_pages(GFP_KERNEL, 0)`) — always succeeds on any system, more ToPA entries but functionally equivalent

Each ToPA entry holds: physical address, size (log2-encoded), END bit (last entry), INT bit (trigger PMI), STOP bit. ToPA entries are **8 bytes (64-bit)** each (Intel SDM Vol. 3C §36.2.4). A single 4KB ToPA table page therefore holds **512 entries** (511 usable output entries + 1 mandatory END entry pointing to the next ToPA table or wrapping back to the start). Chain multiple 4KB ToPA table pages for more than 511 output regions.

**ToPA overflow handling:** Implement a ToPA PMI (Performance Monitoring Interrupt) handler for overflow events. When the ToPA buffer fills:
1. Pause PT (clear `IA32_RTIT_CTL.TraceEn`)
2. Record that overflow occurred for this iteration
3. Mark iteration coverage as **non-scoring** (`PHANTOM_COVERAGE_DISCARDED` flag in status word) — incomplete bitmaps can show false "new edges" and must not be used for corpus-guided selection (see §5.5)
4. Resume without trace for remainder of iteration

**Health metric:** "ToPA overflow rate per 1000 iterations" exposed via debugfs. If >1%, the buffer is too small for the target — increase ToPA size. This metric must be monitored continuously during benchmark runs.

**Configuration:** Both pool size and ToPA size are configurable per instance via `PHANTOM_CREATE_VM` ioctl parameters, with per-target-class defaults. Module parameters (`cow_pool_pages`, `topa_size_mb`) set global defaults.

---

## 5. Development Phases

Detailed phase plans are in the [`phases/`](phases/) directory. Each phase has its own subdirectory with a `README.md` (phase overview, task table, exit criteria) and individual task files with implementation guidance.

| Phase | Weeks | Directory |
|-------|-------|-----------|
| Feasibility Spike | Week 0 | [phases/phase-0-spike/](phases/phase-0-spike/README.md) |
| Phase 1a: VMX Bootstrap + Basic EPT | Weeks 1–6 | [phases/phase-1a-vmx-bootstrap/](phases/phase-1a-vmx-bootstrap/README.md) |
| Phase 1b: CoW Engine + Snapshot/Restore | Weeks 7–12 | [phases/phase-1b-cow-snapshot/](phases/phase-1b-cow-snapshot/README.md) |
| Phase 2: Fuzzing Pipeline | Weeks 13–20 | [phases/phase-2-fuzzing-pipeline/](phases/phase-2-fuzzing-pipeline/README.md) |
| Phase 3: Kernel Fuzzing — Class B | Weeks 21–30 | [phases/phase-3-kernel-fuzzing/](phases/phase-3-kernel-fuzzing/README.md) |
| Phase 4: Campaigns + Publication + Release | Weeks 31–40 | [phases/phase-4-campaigns-publication/](phases/phase-4-campaigns-publication/README.md) |

Cross-cutting reference appendices (error handling §5.5 and debugging tooling §5.6) are in [`phases/appendices/`](phases/appendices/):

| Appendix | Topic |
|----------|-------|
| [appendix-a-error-handling.md](phases/appendices/appendix-a-error-handling.md) | §5.5 Error Handling and Recovery Strategy |
| [appendix-b-debugging-tooling.md](phases/appendices/appendix-b-debugging-tooling.md) | §5.6 Debugging and Observability Tooling |

---

## 6. Technical Risks and Mitigations

| # | Risk | Impact | Prob. | Mitigation |
|---|------|--------|-------|------------|
| 1 | **EPT CoW complexity** — subtle bugs in CoW fault handler corrupt guest state silently | Critical | High | Extensive validation: after every restore, optionally compare guest memory hash against snapshot hash. Add a "paranoid mode" toggle for development that does full memory verification. |
| 2 | **TLB invalidation overhead** — `INVEPT` after every EPT modification may dominate restore time | High | Medium | Batch EPT updates during restore, single INVEPT at end (per Section 2.3). No INVEPT for permission-only (4KB RO→RW) CoW faults — the EPT violation itself invalidates the faulting GPA. However, 2MB→4KB structural splits DO require a single-context INVEPT before VMRESUME. Profile to verify. |
| 3 | **Determinism failures in Class B** — kernel internal state (timers, RNG, allocators) introduces non-determinism despite mitigations | High | High | 4 weeks budgeted for determinism engineering (Phase 3). Explicit enumeration of all non-determinism sources in Section 3. Determinism test as automated CI gate. Accept that some subsystems may be non-deterministic; document which are validated. |
| 4 | **Host kernel panic from VMX bugs** — incorrect VMCS field, bad EPT entry, or unhandled VM exit crashes the host | Medium | High | Develop exclusively in nested KVM. VMCS field validator before every VMLAUNCH. Serial console + kdump from Week 1. Post-mortem script for crash dump analysis. |
| 5 | **Intel PT buffer overflow** — trace output exceeds ToPA buffer; most acute for Class B targets with deep kernel call paths (8MB buffer may still overflow) | Medium | Medium for Class A; High for Class B | Multi-entry ToPA with configurable sizing (2MB Class A, 8MB Class B). PMI overflow handler marks iteration as `PHANTOM_COVERAGE_DISCARDED` (non-scoring) — incomplete bitmaps must not guide corpus. Monitor overflow rate via debugfs; if >1%, increase buffer or switch to breakpoint-based coverage for overflow-prone targets. |
| 6 | **PML unavailability** — older CPUs lack Page Modification Logging | Low | Low | PML not required. CoW tracks dirty pages via EPT violations. PML is a potential optimisation only. |
| 7 | **kAFL ABI drift** — kAFL/Nyx hypercall interface changes in future versions | Low | Low | Pin to a specific nyx_api.h version. Document which kAFL version is compatible. |
| 8 | **Nested KVM hides real hardware behaviour** — development in nested VMs masks timing and performance issues | Medium | High | Accept during development; mandate bare-metal testing for all performance benchmarks. Keep bare-metal test machine available from Phase 2 onwards. |
| 9 | **GPL symbol dependency** — kernel module needs GPL-only symbols | Medium | Medium | License `phantom.ko` as GPL-2.0. Userspace components remain MIT/Apache-2.0. Document each GPL-only symbol dependency with justification. |
| 10 | **PT decode throughput bottleneck** — userspace decode cannot keep pace with kernel execution rate | Medium | Low | Double-buffered design + eventfd notification. Backpressure policy: default correctness-first, configurable skip mode for throughput benchmarks. Monitor decode lag events via debugfs. |
| 11 | **XSAVE state corruption** — guest SIMD state (XMM/YMM/ZMM registers) not correctly saved/restored, causing non-deterministic execution | High | Medium | XSAVE/XRSTOR in snapshot path (Section 2.3). Verify with SIMD-heavy test target: write distinctive XMM patterns before snapshot, verify restored values match 1000× in determinism test. |
| 12 | **MMIO CoW mishandling** — CoW handler allocates private page for MMIO GPA, causing emulation to read stale register values | Critical | Medium | GPA range classification during EPT construction (Section 2.3). CoW handler rejects MMIO GPAs. EPT walker highlights MMIO classification. Add explicit test: APIC read during execution must emulate, not CoW. |
| 13 | **NMI during VMX root** — NMI arrives during VM exit handler, corrupts handler state if not NMI-safe | High | High | NMI exiting enabled (Section 2.6). VM exit handler is NMI-safe (no spinlocks, no non-reentrant structures). `nmi_watchdog=0` on dedicated cores. NMI handling tested explicitly during Phase 1a. |
| 14 | *(merged into risk #5)* | | | |

### 6.5 Security Considerations / Threat Model

Phantom processes untrusted fuzz inputs in the guest. The trust boundary and security requirements:

**Trust boundary:** The guest is **untrusted**. No guest action may:
- Corrupt host (VMX-root) memory
- Read host memory outside the designated shared regions
- Cause a host kernel panic (aspirational for production; expected during development)
- Affect other Phantom instances (EPT isolation is the enforcement mechanism)

**`/dev/phantom` access control:**
- Restrict to `CAP_SYS_ADMIN` or a dedicated `phantom` group
- Implemented via chardev `open` permission check
- Document in setup guide: add fuzzer user to `phantom` group

**mmap bounds enforcement:**
- Every `mmap` request validated: offset and size must fall within the designated region for the requesting instance
- A process mapping instance N's regions cannot access instance M's regions
- Validated in the chardev `mmap` handler before calling `remap_pfn_range`

**Hypercall input validation:**
- Every VMCALL parameter validated in the hypercall handler (VMX-root)
- Payload buffer address: must be within guest EPT-mapped RAM (not MMIO, not host-physical)
- String arguments (PRINTF hypercall): length-bounded, no kernel pointer dereference
- Invalid parameters: abort iteration with `PHANTOM_RESULT_HYPERCALL_ERROR`, do not panic

**EPT isolation:**
- Each instance has an independent EPT pointer (EPTP in VMCS)
- One guest cannot access another guest's memory (different EPT hierarchies)
- Explicitly verified in the test suite: instance A cannot read a value written by instance B to its memory
- Tested during Phase 2 before multi-core work begins

**Fuzzing the fuzzer:**
- Use syzkaller to fuzz the `/dev/phantom` ioctl interface during Phase 4
- Target: all `PHANTOM_*` ioctls with malformed arguments (wrong sizes, NULL pointers, out-of-range values, mismatched instance IDs)
- Add ioctl input validation tests to the standard test suite

### 6.6 Design Alternatives Considered

Brief justification for why the standalone kernel module approach was chosen over alternatives:

**Modify KVM directly:**
KVM's abstraction overhead — QEMU communication via ioctl, KVM's general-purpose VM exit dispatch, and QEMU's device emulation layer — is precisely what Phantom eliminates. Modifying KVM to fuzz would require working within KVM's general-purpose abstraction model, re-introducing overhead that Phantom's design avoids. Additionally, upstream acceptance of fuzzing-specific optimisations into mainline KVM is unlikely, creating a long-term maintenance fork. KVM's codebase complexity (~100k lines) slows development velocity for a research prototype.

**Use Xen:**
Xen's scheduling model (Dom0/DomU separation) and domain management add unnecessary complexity for a single-purpose fuzzer. Xen's EPT management is capable but not optimised for high-frequency snapshot/restore. The Xen toolstack (QEMU, libxl) adds the same overhead Phantom avoids. Development effort to understand and modify Xen's internals exceeds the effort to build a minimal VMX module from scratch.

**eBPF-based coverage collection:**
eBPF can collect coverage events (via kprobes/uprobes/fentry) without a hypervisor. However, eBPF cannot provide snapshot/restore semantics — every iteration would require a full process restart (fork-exec model) or equivalent. eBPF coverage is a useful complement to Phantom (e.g., for comparing with AFL++ userspace baselines) but cannot replace the snapshot-based execution model. Phantom may optionally support eBPF-based coverage as a fallback for targets where Intel PT is impractical.

### 6.7 Rollback Plan

If EPT CoW performance targets are not met by end of Phase 1b, two fallback designs are available:

**Fallback A: PML dirty tracking + memcpy restore (kAFL/kvm-pt approach)**

- Use Page Modification Logging (PML) to identify dirty pages per iteration
- At restore: `memcpy` original page content back to each dirty page (in-place)
- Performance: slower for large dirty sets (memcpy cost per page), faster for very small dirty sets (no EPT fault overhead during execution)
- Advantage: simpler to implement correctly (no private page pool management)
- Disadvantage: memcpy cost during restore is proportional to dirty page size × count; for Class B with 1000 dirty pages × 4KB = 4MB memcpy ≈ 100–300μs

**Fallback B: Hybrid CoW + PML**

- CoW for pages dirtied in every iteration (hot pages) — EPT fault on first write, private page for remainder of iteration
- PML for pages dirtied occasionally (cold pages) — no EPT fault overhead during execution; memcpy restore on dirty detection
- Reduces both execution overhead (fewer EPT faults for hot pages already have private copy) and restore overhead (fewer memcpy operations for occasional pages)

**Decision point:** End of Phase 1b (Week 12). If CoW restore latency >100μs for 500 dirty pages (the target for Class B), evaluate Fallback A. Compare restore latency and execution overhead for a representative Class B target. Choose whichever meets the <50μs restore target for the expected dirty set.

**Note:** Fallback A requires PML hardware (Intel Broadwell and later), which is listed in hardware requirements. This is not a pure software fallback but is available on all target hardware.

### 6.8 Memory Accounting

**Module parameter:** `max_memory_mb` (default: 8192) — maximum total physical memory Phantom may allocate across all instances.

**Global allocation tracker:**
- Atomic counter `phantom_allocated_bytes` incremented on every allocation (pool pages, XSAVE areas, EPT tables, VMCS, ToPA buffers)
- New instance creation refused if `phantom_allocated_bytes + new_instance_size > max_memory_mb × 1MB`
- All Phantom allocations use `__GFP_ACCOUNT` flag for cgroup memory accounting visibility

**Memory breakdown per instance (Class B example):**
```
guest_mem:    256MB   (guest physical memory, alloc_pages_node)
cow_pool:      64MB   (pre-allocated private pages, alloc_pages_node)
topa_buffers:  16MB   (2 × 8MB via multi-entry ToPA, NOT necessarily contiguous)
ept_tables:     2MB   (~512 page tables for 256MB guest at 4KB granularity)
vmcs:           4KB   (one page per vCPU)
xsave_area:     4KB   (rounded up from 2.5KB for AVX-512)
────────────────────
Total:        ~338MB per Class B instance
```

**debugfs exposure:** `/sys/kernel/debug/phantom/memory`:
```
total_allocated_kb:   1234567
max_allowed_kb:       8388608
instances:            4
per_instance_breakdown: [instance 0: guest=262144, pool=65536, topa=16384, ept=2048, ...]
```

### 6.9 Kernel Version Compatibility

**Target kernel range:** Linux 6.8 through 6.14. *(LTS status as of March 2026: 6.12 is the active LTS in this range; 6.6 is the prior LTS below this range; 6.8/6.9/6.10/6.11/6.13/6.14 are standard releases. Check [kernel.org/releases.json](https://www.kernel.org/releases.json) for current LTS designations — this list drifts and must be re-verified before each major Phantom release.)*

**Testing:** Test against LTS kernel versions plus representative standard releases before each major release. CI matrix as of March 2026: kernels **6.8, 6.12** (LTS), **6.14** (latest stable), and HEAD. Re-evaluate CI matrix versions at each major release against the then-current kernel.org LTS list.

**Version-specific API handling:**
- Use `KERNEL_VERSION(major, minor, patch)` macros for all kernel-version-conditional code
- Centralise all version-specific workarounds in `kernel/compat.h`
- Document each version-specific case with a comment citing the kernel commit that changed the API

**GPL-only symbol dependencies (document each with justification):**

> **Warning:** This list must be verified against `EXPORT_SYMBOL_GPL` vs `EXPORT_SYMBOL` declarations in each target kernel version before publication or any legal claims. Export status can change between kernel releases. Verification procedure: `grep -rn 'EXPORT_SYMBOL[^(]*(<symbol>)' $(KERNEL_SRC)` or use `scripts/find-unused-symbols` on a built kernel tree. Do not rely on this document as the authoritative source.

- `alloc_percpu()` — required for per-CPU VMCS region allocation; **verify**: wraps `__alloc_percpu()` which is `EXPORT_SYMBOL_GPL` in 6.x
- `smp_call_function_single()` — required for per-CPU VMXON/VMXOFF; **verify**: `EXPORT_SYMBOL_GPL` in 6.x
- `__get_free_pages()` — used for page allocation; **note**: historically `EXPORT_SYMBOL` (not GPL-only) in many kernel versions — re-verify per target kernel; may not require GPL license for this symbol specifically
- `alloc_pages_node()` — required for NUMA-local allocation; **verify**: `EXPORT_SYMBOL_GPL` in 6.x (the `__alloc_pages_node()` form)
- Document all in `docs/gpl-symbols.md` with per-version verification results

**Allocator preferences:**
- Prefer `__get_free_pages()` / `alloc_pages()` over `kmalloc()` for performance-critical allocations (avoids slab overhead, ensures page alignment)
- Use `alloc_percpu()` for per-CPU data structures (VMCS regions, per-CPU state)
- Use `alloc_pages_node()` with the CPU's NUMA node ID for all instance memory (guest mem, CoW pool, ToPA buffers, EPT tables)
- Never use `vmalloc()` for memory that will be mapped into EPT (non-physically-contiguous)

---

## 7. Hardware Requirements

### Development Machine (per developer)

| Item | Spec | Required |
|------|------|----------|
| CPU | Intel Skylake (6th gen) or newer | Mandatory: VT-x, EPT, Intel PT |
| RAM | 64GB DDR4/DDR5 | Recommended (nested VMs are memory-hungry) |
| Storage | 1TB NVMe SSD | Recommended (corpus storage, VM images) |
| OS | Ubuntu 24.04 LTS | Tested platform |
| Outer host | KVM with `nested=1` | For safe development |
| Second machine | Serial console target | Hard requirement — not optional |

### Bare-Metal Benchmark Machine (shared)

| Item | Spec | Purpose |
|------|------|---------|
| CPU | Intel Ice Lake or newer (Xeon Scalable) | PML support, latest PT features, high core count |
| RAM | 256GB+ DDR5 | Parallel instance memory; NUMA topology for NUMA benchmarks |
| Cores | 16+ physical cores (2 NUMA nodes preferred) | Multi-core scaling + NUMA placement benchmarks |
| Storage | 2TB NVMe | Corpus, traces, results |
| Access | Dedicated, no other workloads | Clean benchmark environment |

### NUMA Allocation Strategy

All per-instance memory allocations must use `alloc_pages_node(cpu_to_node(pinned_cpu), ...)`:
- CoW page pool
- Guest physical memory
- ToPA trace buffers (A and B)
- EPT page table pages
- XSAVE areas
- VMCS regions

**Rationale:** NUMA-remote memory access adds ~40–80 ns per cache miss (depending on NUMA hop count) versus ~10 ns for local. With thousands of EPT table walks and CoW page accesses per iteration, NUMA-remote allocation can degrade exec/sec by 20–40% on 2-socket systems.

**Phase 3 benchmark deliverable:** Measure exec/sec with NUMA-local vs NUMA-remote allocation for a Class B target on the 2-socket benchmark machine. Report as "NUMA locality impact" figure in the paper.

### Optional Future Hardware (Phase 5+, not in current plan)

| Item | Purpose | Estimated Cost |
|------|---------|---------------|
| Xilinx Alveo U50 FPGA | PT decode offload (2–3x improvement on decode-bound workloads) | $2–3k |
| NVIDIA BlueField-3 SmartNIC | Line-rate packet injection for network target fuzzing | $2–4k |

---

## 8. Licensing

### Decision: GPL-2.0 for Kernel Module

The kernel module (`phantom.ko`) will be licensed under **GPL-2.0-only**. Rationale:

- Deep interaction with kernel internals (page tables, per-CPU data, interrupt handling) requires GPL-only symbols
- A proprietary or MIT kernel module would either be non-functional (can't use necessary kernel APIs) or legally questionable
- GPL-2.0 is standard for kernel modules in the security research community
- Does not restrict commercial use of the fuzzer, only redistribution of modified module source

### Userspace Components: MIT

All userspace tools (`phantom-pt-decode`, `phantom-ctl`, `afl-phantom`, `kafl-bridge`) are licensed under **MIT**. These tools are independent programs that communicate with the kernel module via ioctl/mmap, not derivative works.

### Bundled Dependencies

| Dependency | License | Compatibility |
|-----------|---------|---------------|
| libipt | BSD-3-Clause | Compatible with both GPL-2.0 and MIT |
| nyx_api.h | MIT | Compatible |
| Bareflank (extracted primitives) | MIT | Compatible |

---

## 9. Testing Strategy

### Automated Test Suite

| Test Category | What It Validates | When It Runs |
|--------------|-------------------|--------------|
| **Module lifecycle** | Load/unload 100x without leaks or panics | Every commit (CI) |
| **VMX operations** | VMXON/OFF, VMLAUNCH/VMRESUME, VMREAD/VMWRITE on all designated cores | Every commit (CI) |
| **EPT correctness** | Page table construction, GPA classification (RAM/MMIO/reserved), permission enforcement, CoW fault handling | Every commit (CI) |
| **CoW correctness** | Write triggers private copy (WB type preserved), original unchanged, restore resets mapping | Every commit (CI) |
| **MMIO classification** | APIC/IOAPIC GPA reads go to emulator, NOT CoW; reserved GPAs cause abort | Every commit (CI) |
| **Snapshot fidelity** | All VMCS fields from explicit enumeration match pre/post restore; XMM registers survive restore; guest memory hash matches | Every commit (CI) |
| **XSAVE/XRSTOR** | Write distinctive XMM0–XMM15 values before snapshot; verify all restored correctly after 1000 restore cycles | Every commit (CI) |
| **TSS dirty list** | Privilege-level switch causes TSS page to appear in dirty list; restore resets RSP0 | Every commit (CI) |
| **Determinism** | Identical input → identical trace, registers, dirty list (1000 reps) | Daily (CI), hard gate for Phase 3 |
| **Hypercall ABI** | "VMCALL communication" = 1000 different 64-bit values sent/received correctly, responses verified | Every commit (CI) |
| **End-to-end fuzz** | AFL++ drives trivial target, finds seeded crash within 60 seconds | Daily (CI) |
| **Performance regression** | Exec/sec above threshold for reference target | Weekly (bare-metal) |
| **Stability soak** | 24h continuous fuzzing, no panics, no memory leaks | Weekly (bare-metal) |
| **Multi-core scaling** | `exec_N_cores / (exec_1_core × N) >= 0.85` for N up to 8 | Pre-release (bare-metal) |
| **EPT isolation** | Instance A cannot read value written by instance B | Every commit (CI) |
| **Ioctl bounds** | mmap with out-of-range offset/size returns EINVAL | Every commit (CI) |

### Kernel Unit Tests

Use kselftest framework or dedicated test ioctls for in-kernel unit testing:
- `PHANTOM_TEST_COW_SINGLE_PAGE` — allocate private page, write pattern, verify CoW, release
- `PHANTOM_TEST_POOL_EXHAUSTION` — force pool exhaustion, verify graceful abort, verify pool recovered
- `PHANTOM_TEST_DIRTY_LIST_OVERFLOW` — fill dirty list to max, verify abort, verify cleanup
- `PHANTOM_TEST_MMIO_REJECT` — trigger CoW on MMIO GPA, verify rejection and emulation
- `PHANTOM_TEST_XSAVE_RESTORE` — write XMM patterns, snapshot, modify XMM, restore, verify

### Static Analysis

Run on every commit via CI:
- `sparse` (C99 semantic checks, endianness annotation, lock annotation)
- `smatch` (kernel-specific semantic checks, null pointer dereference, lock balance)
- Both must produce zero warnings on the `phantom.ko` source tree

### Runtime Analysis (Development Builds)

Host kernel compiled with (mandatory during Phase 1–2 development):
- `CONFIG_KASAN` — kernel address sanitiser (catches out-of-bounds, use-after-free)
- `CONFIG_KMEMLEAK` — memory leak detector
- `CONFIG_LOCKDEP` — lock dependency validator
- `CONFIG_DEBUG_ATOMIC_SLEEP` — catches sleeping in atomic context (invalid in VM exit handler)

### Bare-Metal VMCS Validation

All VMCS error handling tests (invalid guest state, VM-entry failure, bad control field combinations) must be validated on **bare metal**, not only in nested KVM. Nested KVM may mask invalid VMCS field values that would cause a real VM-entry failure on hardware. VMCS validation tests are explicitly marked as "requires bare metal" in the test suite.

### Quantified Exit Criteria

All exit criteria are quantitative (not qualitative):

| Criterion | Measurement |
|-----------|------------|
| "VMCALL communication works" | 1000 different 64-bit values sent from host, received correctly by guest, responses verified |
| "Bitmap correctly tracks execution" | 3 known branch points, all 2^3=8 input combinations produce distinct bitmap entries, cross-validated against manual trace inspection |
| "Real crash found" | Crash in unmodified real-world target binary/kernel, not pre-seeded with a known crash input |
| "Near-linear scaling" | `exec_N_cores / (exec_1_core × N) >= 0.85` for N ∈ {2, 4, 8} |
| "Deterministic execution" | Identical input produces byte-identical PT trace (with CYCEn=MTCEn=TSCEn=0; no timing packets) and identical register state 1000/1000 times |
| "Restore latency target" | p95 restore latency < 5μs for ≤50 dirty pages; p95 < 50μs for ≤500 dirty pages |
| "Stability test" | 24h continuous fuzzing with zero host panics, zero memory leak warnings (KMEMLEAK), exec/sec ≥ 90% of 1h average |

### CI Environment

- Self-hosted GitHub Actions runner on a machine with nested KVM enabled
- Test VM: Ubuntu 24.04 guest with Phantom module
- Tests run in nested KVM (outer host → KVM → test VM → Phantom → guest)
- Performance tests require bare-metal — run manually or via dedicated CI machine
- Static analysis (sparse + smatch) runs on every commit in the CI VM

---

## 10. Repository Structure

```
phantom/
├── README.md
├── LICENSE-GPL2 (kernel module)
├── LICENSE-MIT (userspace)
├── Makefile
│
├── docs/
│   ├── architecture.md          # Detailed design document
│   ├── setup-guide.md           # Build + install instructions
│   ├── writing-harnesses.md     # How to write Class A + B harnesses
│   ├── benchmarks.md            # How to reproduce benchmarks
│   ├── determinism.md           # Guide to achieving deterministic fuzzing
│   ├── troubleshooting.md       # Common issues and fixes
│   └── gpl-symbols.md           # GPL-only symbol dependencies with justification
│
├── kernel/                       # phantom.ko — GPL-2.0
│   ├── Kbuild
│   ├── compat.h                 # Kernel version compatibility abstractions
│   ├── phantom_main.c           # Module init/cleanup, chardev
│   ├── vmx_core.c / .h          # VMXON, VMCS, VM entry/exit
│   ├── ept.c / .h               # EPT page table management + GPA classification
│   ├── ept_cow.c / .h           # CoW fault handler, page pool, dirty list
│   ├── snapshot.c / .h          # VMCS save/restore, XSAVE/XRSTOR, CoW reset
│   ├── hypercall.c / .h         # nyx_api VMCALL handler + input validation
│   ├── pt_config.c / .h         # Intel PT MSR + ToPA setup, double-buffer mgmt
│   ├── watchdog.c / .h          # VMX preemption timer management
│   ├── nmi.c / .h               # NMI-exiting handler, NMI-safe infrastructure
│   ├── interface.c / .h         # /dev/phantom ioctl + mmap + bounds enforcement
│   ├── multicore.c / .h         # Per-CPU instance management, NUMA allocation
│   ├── memory.c / .h            # Global memory accounting, max_memory_mb
│   └── debug.c / .h             # VMCS dump, EPT walker, dirty list inspector,
│                                #   trace ring buffer, VMCS field validator
│
├── userspace/                    # MIT licensed
│   ├── phantom-pt-decode/        # PT trace → AFL bitmap daemon
│   │   ├── main.c               # eventfd/epoll loop, double-buffer management
│   │   ├── decode.c             # libipt wrapper
│   │   └── bitmap.c             # AFL bitmap generation
│   ├── phantom-ctl/              # CLI tool for /dev/phantom
│   ├── afl-phantom/              # AFL++ fork-server replacement
│   └── kafl-bridge/              # kAFL frontend adapter (Python)
│
├── guest/                        # Harness code (MIT)
│   ├── nyx_api.h                 # Standard kAFL harness header
│   ├── harness_template_a.c      # Class A template
│   ├── harness_template_b.c      # Class B template (kernel module)
│   ├── examples/
│   │   ├── parser_xml.c          # libxml2 parser harness
│   │   ├── parser_png.c          # libpng harness
│   │   └── kernel_nftables.c     # nf_tables kernel harness
│   └── guest_kernel/
│       ├── defconfig             # Minimal kernel config for Class B
│       └── init_harness.c        # Custom kernel init for fuzzing
│
├── tests/
│   ├── unit/
│   │   ├── test_vmx.c
│   │   ├── test_ept.c
│   │   ├── test_cow.c
│   │   ├── test_snapshot.c
│   │   ├── test_xsave.c          # SIMD register save/restore verification
│   │   ├── test_mmio.c           # MMIO GPA classification and reject
│   │   ├── test_hypercall.c
│   │   └── test_security.c       # EPT isolation, ioctl bounds, access control
│   ├── integration/
│   │   ├── test_fuzz_loop.sh
│   │   ├── test_determinism.sh
│   │   ├── test_stability.sh
│   │   └── test_multicore_isolation.sh
│   └── performance/
│       ├── bench_restore_latency.sh
│       ├── bench_execsec.sh
│       ├── bench_scaling.sh
│       └── bench_numa.sh          # NUMA-local vs NUMA-remote comparison
│
├── benchmarks/
│   ├── scripts/                  # Automated benchmark runners
│   ├── reproduce.sh              # End-to-end reproduction with expected ranges
│   ├── results/                  # Published results
│   └── comparison/               # kAFL/Nyx comparison scripts
│
├── tools/
│   ├── guest-builder/            # Scripts to build minimal guest kernels
│   ├── vmcs-dump/                # VMCS state inspector (parses debug.c output)
│   ├── cow-stats/                # CoW page pool utilisation monitor
│   └── crash-scripts/            # kdump post-mortem scripts
│       └── phantom-state.py      # Extract Phantom state from crash dump
│
└── docker/
    ├── Dockerfile.build          # Build environment
    └── Dockerfile.test           # Test environment (nested KVM)
```

---

## 11. Team Roles

| Role | Count | Focus | Key Skills |
|------|-------|-------|------------|
| **VMX / Hypervisor Engineer** | 1–2 | VMX core, EPT CoW engine, snapshot/restore, VMCS handling, XSAVE, NMI/watchdog | x86 virtualisation, Intel SDM familiarity, kernel module development |
| **Systems / Tooling Engineer** | 1 | Userspace tools, PT decode daemon, AFL++/kAFL integration, CI, testing infrastructure | Systems programming (C + Python), Linux internals, fuzzer frontends |
| **Security Researcher** | 1 | Guest harness development, target selection, bug triage, CVE reporting, paper writing | Kernel security research, fuzzing methodology, academic writing |

**Minimum viable team:** 2 people (1 VMX-focused, 1 systems-focused). The security researcher role can be shared.

**Recommended:** 3 people. Having a dedicated researcher writing harnesses and triaging bugs while engineers focus on the platform significantly accelerates the path to paper-worthy results.

---

## 12. Milestones and Review Points

| Week | Milestone | Review Criteria | Go/No-Go Gate |
|------|-----------|----------------|---------------|
| 0 | **Feasibility spike complete** | VMX entry, trivial guest, VMCALL, EPT violation handled; kdump and serial console verified | — |
| 2 | VMX operational | Module loads, VMXON/VMXOFF clean on all cores; partial VMXON recovery tested | — |
| 4 | Guest execution | Guest runs, VMCALL returns data to host; VMCS validator works | — |
| 5 | Basic R/W EPT | EPT walker confirms correct GPA classification; MMIO ranges correctly absent | — |
| 6 | **First CoW fault** | CoW handler allocates private page; dirty list populated; MMIO rejected | Gate: CoW correctness tests pass 100% |
| 9 | **100+ CoW faults** | 200 sequential writes handled; no corruption over 100 iterations | Gate: no pool exhaustion, no leaks |
| 12 | **Phase 1 complete** | Snapshot/restore via CoW, XSAVE/XRSTOR integrated, <5μs for 50 dirty pages | Gate: 10k restore cycles, no corruption, SIMD registers verified |
| 13 | Buffer week | — | — |
| 15 | Hypercall ABI | 1000 VMCALL values sent/received correctly; input validation tested | — |
| 17 | PT coverage | 2^3=8 input combinations produce distinct bitmaps; double-buffer + eventfd working | — |
| 19 | Frontend integration | AFL++ and kAFL drive end-to-end fuzz loop | — |
| 20 | **Phase 2 complete** | Class A fuzzing, first real crash, >50k exec/sec, 24h stability | Gate: >50k exec/sec, real crash, 24h stability |
| 21 | Buffer week | — | — |
| 23 | Kernel guest boots | Minimal Linux runs inside Phantom, reaches custom init | — |
| 27 | **Determinism validated** | Identical input → identical trace 1000/1000 times; all non-determinism sources addressed | Gate: determinism test passes (hard gate — do not proceed until met) |
| 29 | Multi-core operational | ≥0.85× scaling per core up to 8 cores; NUMA benchmark complete | — |
| 30 | **Phase 3 complete** | Class B working, real kernel bugs found, 30-run benchmarks done, 72h stability | Gate: 72h stability, reproducible benchmark data |
| 31–32 | Buffer | — | — |
| 35 | Bug campaigns complete | ≥5 bugs in real kernel targets | — |
| 38 | Paper draft complete | All sections written, figures done, results tables complete | — |
| 40 | **Phase 4 complete** | Paper submitted, GitHub repo public, CI green, artifact evaluation badges targeted | — |

---

## 13. Known Limitations (to be stated in paper)

1. **No Class C support:** Userland binary fuzzing requires device emulation, which is explicitly out of scope. Phantom targets in-kernel and standalone function fuzzing.
2. **Dedicated hardware:** Phantom requires exclusive VMX-root ownership. It cannot coexist with KVM or other hypervisors on the same machine.
3. **Intel-only:** Depends on Intel VT-x, EPT, and Intel PT. AMD SEV/SVM support is future work.
4. **Dirty page sensitivity:** Performance advantage scales inversely with dirty page footprint. Targets that modify thousands of pages per iteration will see smaller speedups.
5. **Determinism is target-dependent:** Some kernel subsystems may have inherent non-determinism that cannot be fully suppressed without guest kernel modification.
6. **No live migration or checkpointing:** Snapshots are in-memory only. Machine reboot loses all state.
7. **XSAVE/XRSTOR overhead in restore path:** Restoring extended register state (AVX-512) adds ~200–400 cycles per restore. For Class A targets with sub-microsecond restore targets, this is a meaningful fraction of the restore budget. Mitigated by skipping AVX-512 context save if the guest target does not use AVX-512 instructions (detectable via CPUID probing).

---

## 14. Future Work (Post-Publication)

1. **Class C support** via hybrid architecture (Phantom snapshots + minimal QEMU device model)
2. **AMD SVM support** (analogous architecture using AMD-V nested page tables)
3. **FPGA-accelerated PT decoding** for decode-throughput-bound workloads
4. **SmartNIC integration** for line-rate network packet fuzzing (especially valuable for netfilter targets)
5. **Distributed mode** — multiple Phantom machines coordinated by a central corpus manager
6. **Incremental snapshots** — nested checkpoints for stateful protocol fuzzing
7. **Windows guest support** — kernel driver fuzzing on Windows (requires different boot protocol, different harness)
8. **CXL memory integration** — hardware-assisted snapshot/restore via CXL memory controllers
9. **PML-based hybrid dirty tracking** — Fallback B from Section 6.7 as a first-class mode for targets with pathological dirty sets

---

*End of document. — v2.1*
