# Task 2.2: Intel PT Coverage

> **Phase:** Fuzzing Pipeline | **Week(s):** 15–16 | **Depends on:** [Task 2.1](task-2.1-hypercall-interface.md)

## Objective

Configure Intel PT in the kernel module for per-iteration tracing of guest execution, implement double-buffered ToPA output with eventfd notification, and deliver a userspace decode daemon that produces an AFL-compatible coverage bitmap.

## What to Build

- Kernel-side PT configuration: `IA32_RTIT_CTL` (enable PT, configure filtering using VMCS controls preferred or MSR load/store lists as fallback per Section 2.4), `IA32_RTIT_OUTPUT_BASE` + `IA32_RTIT_OUTPUT_MASK` pointing to ToPA (double-buffered, two regions per instance), ToPA buffer allocation via multi-entry ToPA (not necessarily contiguous; 2MB per buffer for Class A, 8MB per buffer for Class B per §4.3), IP filtering via `ADDR0_START`/`ADDR0_END` set to guest target code range, CPL filtering for CPL=0 only for Class B targets, ToPA PMI overflow handler
- Timing packet suppression (CYCEn=MTCEn=TSCEn=0), per-iteration MSR reset, eventfd notification
- Double-buffer setup per Section 2.4: after each iteration signal eventfd indicating which buffer has new data and byte count; expose PT trace buffers to userspace via `mmap` on `/dev/phantom`; on ToPA overflow, mark iteration as `PHANTOM_COVERAGE_DISCARDED` (do not abort execution, but do not use bitmap for corpus decisions)
- Userspace PT decode daemon (`phantom-pt-decode`): `mmap` both ToPA buffers from `/dev/phantom`, wait for eventfd notification (epoll-based for multi-instance support), decode PT packets using `libipt`, hash (src_addr, dst_addr) pairs to AFL-compatible 64KB edge bitmap, write bitmap to shared memory region
- **PT decode backpressure policy:** if the decode daemon has not finished decoding buffer B by the time the kernel needs to write buffer B again, the kernel **blocks in the IOCTL** rather than overwriting un-decoded data (correctness-first, default); a per-instance flag `skip_coverage_on_lag` (default: false) allows the kernel to skip coverage recording for that iteration instead of blocking — enables higher throughput at the cost of missing some coverage edges, for use during throughput benchmarks; expose a "decode lag events per 1000 iterations" health counter via debugfs; if the lag rate exceeds 1%, consider increasing ToPA buffer size or switching to `skip_coverage_on_lag` mode

## Implementation Guidance

### PT Enable/Disable Strategy

Two approaches in priority order:

**Preferred: VMCS entry/exit PT controls**

```c
/* Check PT-in-VMX support at module init */
u64 entry_ctls = rdmsr(MSR_IA32_VMX_TRUE_ENTRY_CTLS);
u64 exit_ctls  = rdmsr(MSR_IA32_VMX_TRUE_EXIT_CTLS);

bool pt_in_vmx = (entry_ctls & BIT(18)) && (exit_ctls & BIT(25));

if (pt_in_vmx) {
    /* VM-entry control bit 18: "load IA32_RTIT_CTL" — auto-enables PT on entry */
    /* VM-exit control bit 25: "clear IA32_RTIT_CTL" — auto-disables PT on exit */
    vmcs_set_bits(VM_ENTRY_CONTROLS, VM_ENTRY_LOAD_IA32_RTIT_CTL);
    vmcs_set_bits(VM_EXIT_CONTROLS, VM_EXIT_CLEAR_IA32_RTIT_CTL);
    /* IA32_RTIT_CTL is loaded from VMCS VM-entry MSR-load area at entry */
    /* IA32_RTIT_CTL is stored to VMCS VM-exit MSR-store area at exit */
}
```

**Fallback: VMCS MSR load/store lists**

If PT-in-VMX controls are unavailable, add `IA32_RTIT_CTL` to:
- VM-entry MSR-load list (to enable PT on entry)
- VM-exit MSR-store/load lists (to save PT state on exit and restore host PT state)

**Avoid:** Manual MSR writes in the VM exit handler — creates ambiguous tracing window and adds latency.

**Verification:** Host code in the VM exit handler must NOT be traced. Verify during PT integration testing.

### PT Configuration: Timing Packet Suppression

For determinism, configure `IA32_RTIT_CTL` with these bits **cleared at instance creation and never changed**:

```c
#define RTIT_CTL_TRACEEN   BIT(0)   /* Enable tracing */
#define RTIT_CTL_OS        BIT(2)   /* Trace CPL=0 (kernel mode) */
#define RTIT_CTL_USER      BIT(3)   /* Trace CPL>0 (user mode) */
#define RTIT_CTL_PWR_EVT   BIT(4)   /* PTWRITE packets — disable */
#define RTIT_CTL_CYCEN     BIT(1)   /* CYC packets — MUST be 0 for determinism */
#define RTIT_CTL_MTCEN     BIT(9)   /* MTC packets — MUST be 0 for determinism */
#define RTIT_CTL_TSCEN     BIT(10)  /* TSC packets — MUST be 0 for determinism */

/* Class A configuration */
u64 rtit_ctl_class_a =
    RTIT_CTL_TRACEEN |
    RTIT_CTL_USER    |     /* Trace user mode only for Class A */
    RTIT_CTL_ADDR0   |     /* Enable ADDR0 IP filtering */
    0;                     /* CYCEn=MTCEn=TSCEn=PTWEn=0 */

/* Class B configuration */
u64 rtit_ctl_class_b =
    RTIT_CTL_TRACEEN |
    RTIT_CTL_OS      |     /* Trace CPL=0 (kernel mode) for Class B */
    RTIT_CTL_ADDR0   |     /* Enable ADDR0 IP filtering */
    0;                     /* CYCEn=MTCEn=TSCEn=PTWEn=0 */
```

### Per-Iteration ToPA Reset: 6-Step Procedure

Exact MSR sequence at each iteration boundary (in VMX-root after VM exit, before signalling userspace):

```c
static void phantom_pt_iteration_reset(struct phantom_instance *inst)
{
    /* Step 1: PT already stopped — verify in debug builds */
    WARN_ON_ONCE(rdmsr(MSR_IA32_RTIT_CTL) & RTIT_CTL_TRACEEN);

    /* Step 2: Read byte count from IA32_RTIT_STATUS (MSR 0x571) */
    u64 status = rdmsr(MSR_IA32_RTIT_STATUS);
    u64 byte_count = (status >> 32) & 0x1FFFF;  /* PacketByteCnt field [48:32] */

    /* Step 3: Signal userspace via eventfd */
    inst->pt_buf_current->byte_count = byte_count;
    inst->pt_buf_current->buffer_index = inst->pt_buf_active;
    eventfd_signal(inst->pt_eventfd, 1);

    /* Step 4: Reset write pointer — WRMSR(IA32_RTIT_OUTPUT_MASK_PTRS, 0) */
    wrmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, 0, 0);

    /* Step 5: Clear status register */
    wrmsr(MSR_IA32_RTIT_STATUS, 0, 0);

    /* Step 6: IA32_RTIT_OUTPUT_BASE — NOT written; always points to ToPA table */
    /* (pt_output_base is set once at instance creation and never modified) */

    /* Swap double-buffer for next iteration */
    inst->pt_buf_active ^= 1;
}
```

### ToPA Sizing and Multi-Entry Allocation

From §4.3:

| Target Class | Buffer Size | Double-Buffer Total |
|-------------|-------------|---------------------|
| Class A | 2MB per buffer | 4MB per instance |
| Class B | 8MB per buffer | 16MB per instance |

**Multi-entry ToPA allocation strategy for 8MB Class B buffer:**

```c
static int phantom_topa_alloc(struct phantom_pt_buffer *buf, size_t target_size)
{
    /* First try: 4 × 2MB — fewer ToPA entries, larger contiguous chunks */
    for (int i = 0; i < 4; i++) {
        buf->chunks[i] = alloc_pages(GFP_KERNEL, 9);  /* 2^9 = 512 pages = 2MB */
        if (!buf->chunks[i]) goto fallback;
    }
    buf->chunk_count = 4;
    buf->chunk_order = 9;
    return phantom_topa_build(buf);

fallback:
    /* Free any partially allocated chunks */
    for (int i = 0; i < buf->chunk_count; i++)
        if (buf->chunks[i]) __free_pages(buf->chunks[i], 9);

    /* Fallback: 2048 × 4KB — always succeeds on fragmented systems */
    buf->chunk_count = target_size / PAGE_SIZE;
    for (int i = 0; i < buf->chunk_count; i++) {
        buf->chunks[i] = alloc_page(GFP_KERNEL);
        if (!buf->chunks[i]) return -ENOMEM;
    }
    buf->chunk_order = 0;
    return phantom_topa_build(buf);
}
```

**ToPA entry format (Intel SDM Vol. 3C §36.2.4):**
- Each ToPA entry: 8 bytes (64-bit)
- Bits [63:12]: Physical address of output region
- Bit 4: INT — trigger PMI on this entry
- Bit 2: STOP — stop tracing on this entry
- Bit 0: END — last entry in ToPA table (wrap or link to next table)

### Double-Buffer Swap and Pipeline

```
Core (kernel):   [run iter N] [restore] [run iter N+1] [restore] [run iter N+2]
                      │                      │
                      ▼                      ▼
Decode (user):   [decode N-1] [bitmap]  [decode N]  [bitmap]  [decode N+1]
```

Decode of iteration N happens in parallel with execution of iteration N+1. Decode latency does not directly impact exec/sec as long as decode throughput keeps up.

### ToPA PMI Overflow Handler

When ToPA buffer fills:

```c
static void phantom_topa_pmi_handler(void)
{
    struct phantom_instance *inst = get_current_instance();

    /* 1. Pause PT */
    u64 ctl = rdmsr(MSR_IA32_RTIT_CTL);
    wrmsr(MSR_IA32_RTIT_CTL, ctl & ~RTIT_CTL_TRACEEN, 0);

    /* 2. Mark iteration coverage as non-scoring */
    inst->coverage_flags |= PHANTOM_COVERAGE_DISCARDED;

    /* 3. Increment health counter */
    inst->topa_overflow_count++;

    /* 4. Resume without trace for remainder of iteration */
    /* (execution continues until RELEASE hypercall or timeout) */
}
```

**Health metric:** "ToPA overflow rate per 1000 iterations" via debugfs. If >1%, the buffer is too small.

### Userspace Decode Daemon Architecture

```c
/* phantom-pt-decode/main.c */
int main(void)
{
    int epfd = epoll_create1(0);

    /* mmap both ToPA buffers from /dev/phantom */
    void *buf_a = mmap(NULL, TOPA_BUF_SIZE, PROT_READ, MAP_SHARED, phantom_fd,
                       PHANTOM_MMAP_TOPA_A);
    void *buf_b = mmap(NULL, TOPA_BUF_SIZE, PROT_READ, MAP_SHARED, phantom_fd,
                       PHANTOM_MMAP_TOPA_B);

    /* Wait for eventfd notifications via epoll */
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = inst->eventfd };
    epoll_ctl(epfd, EPOLL_CTL_ADD, inst->eventfd, &ev);

    while (1) {
        struct epoll_event events[MAX_INSTANCES];
        int n = epoll_wait(epfd, events, MAX_INSTANCES, -1);
        for (int i = 0; i < n; i++) {
            /* Read which buffer is ready and byte count */
            phantom_decode_buffer(events[i].data.ptr);
        }
    }
}

/* decode.c — libipt wrapper → AFL bitmap */
static void phantom_decode_buffer(struct phantom_pt_ctx *ctx)
{
    struct pt_image *image = pt_image_alloc(NULL);
    struct pt_insn_decoder *dec = pt_insn_alloc_decoder(&ctx->config);

    /* Decode PT packets → (src, dst) edge pairs → AFL bitmap */
    while (pt_insn_sync_forward(dec) == 0) {
        struct pt_insn insn;
        while (pt_insn_next(dec, &insn, sizeof(insn)) == 0) {
            if (insn.iclass == ptic_call || insn.iclass == ptic_jump ||
                insn.iclass == ptic_cond_jump) {
                u64 src = insn.ip;
                u64 dst = insn.ip + insn.size;  /* or branch target */
                /* Hash to AFL 64KB bitmap */
                u32 edge = hash_src_dst(src, dst) % (64 * 1024);
                ctx->bitmap[edge / 8] |= (1 << (edge % 8));
            }
        }
    }
}
```

## Key Data Structures

```c
/* Per-instance PT state */
struct phantom_pt_state {
    u64              rtit_ctl;          /* Configured IA32_RTIT_CTL value   */
    u64              output_base;       /* IA32_RTIT_OUTPUT_BASE (constant)  */
    struct phantom_pt_buffer bufs[2];   /* Double-buffer A and B            */
    int              active_buf;        /* Index of currently-writing buffer */
    struct eventfd_ctx *eventfd;        /* Notification to userspace        */
    u64              topa_overflow_count; /* Health metric via debugfs      */
    u32              coverage_flags;    /* PHANTOM_COVERAGE_DISCARDED, etc. */
};

#define PHANTOM_COVERAGE_DISCARDED  (1 << 0)  /* ToPA overflowed, bitmap invalid */
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/pt_config.c` | Intel PT MSR + ToPA setup, double-buffer management, PMI handler |
| `userspace/phantom-pt-decode/main.c` | eventfd/epoll loop, double-buffer management |
| `userspace/phantom-pt-decode/decode.c` | libipt wrapper → AFL bitmap |

## Reference Sections

- §2.4: Intel PT full section — PT enable strategy, MSR sequence, ToPA reset 6-step procedure, double-buffer, pipeline diagram, backpressure policy
- §4.3: ToPA sizing — 2MB Class A, 8MB Class B, multi-entry allocation strategy

## Tests to Run

- 3 known branch points × 8 input combinations → 8 distinct bitmap entries (pass = all 8 combinations produce a unique bitmap, cross-validated against manual trace inspection)
- Zero timing packets in any decoded trace with CYCEn=MTCEn=TSCEn=0 (pass = libipt decoder finds no CYC/MTC/TSC packets across 100 decoded traces)
- Double-buffer swap works correctly: fill buffer A, swap to buffer B, verify A is decoded while B fills (pass = no data loss across 100 consecutive swaps)
- ToPA overflow → coverage marked `PHANTOM_COVERAGE_DISCARDED`, iteration continues to RELEASE hypercall (pass = status word contains discarded flag, guest completes)
- eventfd notification latency measured and documented (pass = measurement recorded in benchmark notes)
- Backpressure correctness-first: when decode lag is induced (daemon artificially slowed), the kernel blocks rather than overwriting the un-decoded buffer (pass = no coverage data lost, lag counter increments in debugfs)
- `skip_coverage_on_lag=true`: when lag is induced with flag enabled, the kernel skips coverage for lagging iterations rather than blocking, and exec/sec is not degraded (pass = exec/sec unchanged vs no-lag baseline, lag counter increments)

## Deliverables

Coverage-guided feedback working; bitmap correctly reflects guest control flow.
