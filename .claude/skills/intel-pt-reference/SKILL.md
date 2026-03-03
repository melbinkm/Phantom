---
name: intel-pt-reference
description: Intel Processor Trace reference for Phantom. Auto-load when writing PT configuration, ToPA setup, decode daemon, or coverage bitmap code.
user-invocable: false
disable-model-invocation: false
---

# Intel PT Reference for Phantom

## IA32_RTIT_CTL Configuration

```c
#define RTIT_CTL_TRACEEN   BIT(0)   /* Enable tracing */
#define RTIT_CTL_CYCEN     BIT(1)   /* CYC packets — MUST be 0 for determinism */
#define RTIT_CTL_OS        BIT(2)   /* Trace CPL=0 (kernel mode) */
#define RTIT_CTL_USER      BIT(3)   /* Trace CPL>0 (user mode) */
#define RTIT_CTL_PWR_EVT   BIT(4)   /* PTWRITE packets — disable */
#define RTIT_CTL_MTCEN     BIT(9)   /* MTC packets — MUST be 0 for determinism */
#define RTIT_CTL_TSCEN     BIT(10)  /* TSC packets — MUST be 0 for determinism */
#define RTIT_CTL_ADDR0     BIT(32)  /* Enable ADDR0 IP filtering */

/* For determinism: CYCEn=MTCEn=TSCEn=PTWEn=0 — set at instance creation, NEVER changed */

/* Class A: trace user mode only */
u64 rtit_ctl_class_a = RTIT_CTL_TRACEEN | RTIT_CTL_USER | RTIT_CTL_ADDR0;

/* Class B: trace CPL=0 (kernel) only */
u64 rtit_ctl_class_b = RTIT_CTL_TRACEEN | RTIT_CTL_OS | RTIT_CTL_ADDR0;
```

**Determinism requirement:** With timing packets disabled (CYCEn=MTCEn=TSCEn=PTWEn=0), the PT packet stream contains only control-flow packets (TNT, TIP, FUP, MODE, PSB, PSBEND, CBR). Identical control flow produces byte-identical traces — this is required for the 1000/1000 determinism gate.

**Verify:** Decoded traces must contain no CYC/MTC/TSC/PTWRITE packets.

## PT Enable/Disable Strategy

### Preferred: VMCS Entry/Exit PT Controls (PT-in-VMX)

Check at module init:
```c
u64 entry_ctls = rdmsr(MSR_IA32_VMX_TRUE_ENTRY_CTLS);
u64 exit_ctls  = rdmsr(MSR_IA32_VMX_TRUE_EXIT_CTLS);
bool pt_in_vmx = (entry_ctls & BIT(18)) && (exit_ctls & BIT(25));
```

If supported:
- VM-entry control bit 18: "load IA32_RTIT_CTL" → PT auto-enabled on VM entry
- VM-exit control bit 25: "clear IA32_RTIT_CTL" → PT auto-disabled on VM exit

**Result:** PT traces only guest execution. Exit handler code is NOT traced. Verify during integration testing.

### Fallback: VMCS MSR Load/Store Lists

If PT-in-VMX unavailable: add `IA32_RTIT_CTL` to VM-entry MSR-load list (enable on entry) and VM-exit MSR-store/load lists (save on exit, restore host state).

**Avoid:** Manual MSR writes in the VM exit handler — creates ambiguous tracing window.

## ToPA Registers

- `IA32_RTIT_OUTPUT_BASE` (MSR 0x560): physical address of ToPA table — set ONCE at instance creation, NEVER modified during fuzzing
- `IA32_RTIT_OUTPUT_MASK_PTRS` (MSR 0x561): current write pointer — reset to 0 at each iteration boundary

## Per-Iteration ToPA Reset: 6-Step MSR Sequence

Executed in VMX-root after VM exit, before signalling userspace:

```c
static void phantom_pt_iteration_reset(struct phantom_instance *inst)
{
    /* Step 1: PT already stopped (VM-exit control cleared IA32_RTIT_CTL) */
    /* Verify in debug builds: rdmsr(MSR_IA32_RTIT_CTL) & RTIT_CTL_TRACEEN == 0 */

    /* Step 2: Read byte count from IA32_RTIT_STATUS (MSR 0x571) */
    u64 status     = rdmsr(MSR_IA32_RTIT_STATUS);
    u64 byte_count = (status >> 32) & 0x1FFFF;  /* PacketByteCnt field [48:32] */

    /* Step 3: Signal userspace via eventfd */
    inst->pt_status->byte_count   = byte_count;
    inst->pt_status->buffer_index = inst->pt_buf_active;
    eventfd_signal(inst->pt_eventfd, 1);

    /* Step 4: Reset write pointer */
    wrmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, 0, 0);

    /* Step 5: Clear status register */
    wrmsr(MSR_IA32_RTIT_STATUS, 0, 0);

    /* Step 6: IA32_RTIT_OUTPUT_BASE — NOT written (constant) */

    /* Swap double-buffer for next iteration */
    inst->pt_buf_active ^= 1;
}
```

## Double-Buffer Pipeline

```
Core (kernel):   [run iter N] [restore] [run iter N+1] [restore] [run iter N+2]
                      │                      │
                      ▼                      ▼
Decode (user):   [decode N-1] [bitmap]  [decode N]  [bitmap]  [decode N+1]
```

Decode of iteration N happens in parallel with execution of iteration N+1. Decode latency is off the hot path as long as throughput keeps up.

## ToPA Buffer Sizing

| Target Class | Per-Buffer Size | Double-Buffer Total |
|-------------|-----------------|---------------------|
| Class A | 2MB | 4MB per instance |
| Class B | 8MB | 16MB per instance |

**Multi-entry ToPA allocation:** For 8MB Class B buffer, try 4 × 2MB first (fewer ToPA entries); fall back to 2048 × 4KB on fragmented systems.

## ToPA Entry Format (Intel SDM Vol. 3C §36.2.4)

Each ToPA entry: 8 bytes (64-bit)
- Bits [63:12]: Physical address of output region
- Bit 4: INT — trigger PMI on this entry
- Bit 2: STOP — stop tracing on this entry
- Bit 0: END — last entry in ToPA table (wrap or link to next table)

## ToPA PMI Overflow Handler

On ToPA buffer overflow:
1. Stop PT: clear RTIT_CTL_TRACEEN
2. Set `PHANTOM_COVERAGE_DISCARDED` flag in status word — do NOT use bitmap for corpus decisions
3. Increment `topa_overflow_count` health metric
4. Resume execution until RELEASE hypercall or timeout

**Health metric:** "ToPA overflow rate per 1000 iterations" via debugfs. If >1%, increase buffer size.

## Backpressure Policy

**Default (correctness-first):** If decode daemon has not finished decoding buffer B when kernel needs to write buffer B again, kernel **blocks in IOCTL** — no coverage data lost.

**`skip_coverage_on_lag=true`:** Kernel skips coverage for lagging iterations instead of blocking. Use for throughput benchmarks only. Default: false.

**Health counter:** "decode lag events per 1000 iterations" via debugfs. If lag rate >1%, consider increasing buffer size or enabling skip mode.

**Notification:** Use `eventfd` + `epoll`. eventfd for kernel→userspace signalling, epoll to wait on multiple eventfds (one per instance) in a single daemon thread.

## Userspace Decode Daemon Architecture

```c
/* phantom-pt-decode/main.c */
int main(void) {
    int epfd = epoll_create1(0);
    /* mmap both ToPA buffers from /dev/phantom */
    void *buf_a = mmap(NULL, TOPA_BUF_SIZE, PROT_READ, MAP_SHARED, fd, PHANTOM_MMAP_TOPA_A);
    void *buf_b = mmap(NULL, TOPA_BUF_SIZE, PROT_READ, MAP_SHARED, fd, PHANTOM_MMAP_TOPA_B);
    /* epoll on eventfd for iteration-complete notifications */
    while (1) {
        epoll_wait(epfd, events, MAX_INSTANCES, -1);
        /* decode PT packets → (src, dst) edge pairs → AFL 64KB edge bitmap */
        phantom_decode_buffer(ctx);
    }
}

/* decode.c — libipt wrapper */
static void phantom_decode_buffer(struct phantom_pt_ctx *ctx) {
    struct pt_insn_decoder *dec = pt_insn_alloc_decoder(&ctx->config);
    while (pt_insn_sync_forward(dec) == 0) {
        struct pt_insn insn;
        while (pt_insn_next(dec, &insn, sizeof(insn)) == 0) {
            if (insn.iclass == ptic_call || insn.iclass == ptic_jump ||
                insn.iclass == ptic_cond_jump) {
                u32 edge = hash_src_dst(insn.ip, insn.ip + insn.size) % (64 * 1024);
                ctx->bitmap[edge / 8] |= (1 << (edge % 8));
            }
        }
    }
}
```

## IP Filtering

Configure ADDR0 range to trace only the guest target code range:
- Set `IA32_RTIT_ADDR0_A` to target start address
- Set `IA32_RTIT_ADDR0_B` to target end address
- Enable ADDR0 filtering via `RTIT_CTL_ADDR0` bit

For Class B: trace CPL=0 only (RTIT_CTL_OS=1, RTIT_CTL_USER=0).

## Source Files

- `kernel/pt_config.c` — IA32_RTIT_CTL, ToPA setup, double-buffer, PMI handler
- `userspace/phantom-pt-decode/main.c` — eventfd/epoll loop
- `userspace/phantom-pt-decode/decode.c` — libipt → AFL bitmap
