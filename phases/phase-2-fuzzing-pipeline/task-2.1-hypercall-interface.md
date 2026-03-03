# Task 2.1: Hypercall Interface (kAFL/Nyx ABI)

> **Phase:** Fuzzing Pipeline | **Week(s):** 14–15 | **Depends on:** [Task 1.8](../phase-1b-cow-snapshot/task-1.8-performance-measurement.md)

## Objective

Implement the full kAFL/Nyx `nyx_api` hypercall set so that existing kAFL guest harnesses run on Phantom without modification, with shared memory payload/status regions exposed via mmap.

## What to Build

- Full `nyx_api` hypercall set: `HYPERCALL_KAFL_GET_PAYLOAD` (register guest payload buffer address; Phantom maps this as shared memory between guest and host), `HYPERCALL_KAFL_SUBMIT_CR3` (register guest CR3 for Intel PT IP filtering), `HYPERCALL_KAFL_ACQUIRE` (mark start of traced execution; trigger PT enable), `HYPERCALL_KAFL_RELEASE` (mark end of traced execution; trigger PT disable + snapshot restore), `HYPERCALL_KAFL_PANIC` (guest reports crash with crash address), `HYPERCALL_KAFL_KASAN` (guest reports KASAN violation), `HYPERCALL_KAFL_PRINTF` (guest debug output forwarded to host log), `HYPERCALL_KAFL_SUBMIT_PANIC` (register panic handler address for auto-detection)
- Hypercall input validation: every VMCALL parameter validated — payload buffer address must be within guest EPT-mapped RAM, not MMIO or reserved; invalid parameters → abort iteration, return error, do NOT panic host
- Shared memory setup: payload buffer (host writes fuzz input, guest reads via pre-registered address), status word (iteration result: ok/crash/timeout/kasan), both regions mmap'd to userspace via `/dev/phantom`; payload buffer and guest EPT mapping both typed WB (Write-Back); under same-core pinning, program order provides the payload-visible-before-VMRESUME guarantee — no explicit barrier (SFENCE/MFENCE) is needed on the hot path (see Section 2.7); affinity enforcement: ioctl handler calls `get_cpu()`, verifies current CPU matches the instance's pinned core, returns `-EINVAL` on mismatch, calls `put_cpu()` after VMRESUME returns

## Implementation Guidance

### Shared Memory Coherency Model

From §2.7:

**Payload buffer (host writes, guest reads):**
- Host userspace writes the fuzz payload into the payload buffer via the mmap'd region
- **Correctness invariant:** The host's payload store must be globally visible before the guest's first load from the payload buffer.
- **Implementation (same-core pinning):** Phantom pins each instance's ioctl execution to the same physical core that executes VMRESUME. On x86, a core's stores are visible to its own subsequent loads in program order (TSO guarantee). **No explicit memory barrier (SFENCE/MFENCE) is needed on the hot path** — program order suffices.
- **Map the payload buffer as WB (Write-Back)** in both host virtual mapping and guest EPT mapping. WC or UC mappings add unnecessary latency.

**Affinity enforcement pseudocode:**

```c
static long phantom_ioctl_run_iteration(struct phantom_instance *inst,
                                         struct phantom_run_args __user *uargs)
{
    int cpu;

    /*
     * Enforce same-core pinning: ioctl must execute on the same
     * physical core as VMRESUME. get_cpu() disables preemption.
     */
    cpu = get_cpu();
    if (cpu != inst->pinned_cpu) {
        put_cpu();
        return -EINVAL;  /* Wrong core — userspace must pin thread */
    }

    /* Write payload to shared buffer (WB mapping, program order sufficient) */
    /* ... copy payload ... */

    /* Execute iteration on this core — VMRESUME happens here */
    phantom_run_one_iteration(inst);

    put_cpu();  /* Re-enable preemption after VMRESUME returns */
    return 0;
}
```

**Cross-core case (not currently used):** If a future design allows ioctl on a different core than VMRESUME, the payload write must use `smp_store_release()` before VMRESUME. Not implemented in the per-CPU pinning model.

### Hypercall Dispatch Table

```c
/* nyx_api hypercall numbers (from nyx_api.h) */
#define HYPERCALL_KAFL_RAX_ID           0x01f /* RAX value for VMCALL */
#define HYPERCALL_KAFL_GET_PAYLOAD      0x11a
#define HYPERCALL_KAFL_SUBMIT_CR3       0x11b
#define HYPERCALL_KAFL_ACQUIRE          0x11c
#define HYPERCALL_KAFL_RELEASE          0x11d
#define HYPERCALL_KAFL_PANIC            0x11e
#define HYPERCALL_KAFL_KASAN            0x11f
#define HYPERCALL_KAFL_PRINTF           0x120
#define HYPERCALL_KAFL_SUBMIT_PANIC     0x121

static int phantom_hypercall_dispatch(struct phantom_instance *inst, struct vcpu *vcpu)
{
    u64 hcall_id = vcpu->regs[VCPU_REG_RAX];
    u64 arg0     = vcpu->regs[VCPU_REG_RBX];

    switch (hcall_id) {
    case HYPERCALL_KAFL_GET_PAYLOAD:
        return hcall_get_payload(inst, vcpu, arg0);
    case HYPERCALL_KAFL_ACQUIRE:
        return hcall_acquire(inst, vcpu);
    case HYPERCALL_KAFL_RELEASE:
        return hcall_release(inst, vcpu);
    case HYPERCALL_KAFL_PANIC:
        inst->run_result = PHANTOM_RESULT_CRASH;
        inst->crash_addr = arg0;
        return phantom_abort_and_restore(inst);
    case HYPERCALL_KAFL_KASAN:
        inst->run_result = PHANTOM_RESULT_KASAN;
        return phantom_abort_and_restore(inst);
    case HYPERCALL_KAFL_PRINTF:
        return hcall_printf(inst, vcpu, arg0);
    default:
        pr_warn_ratelimited("phantom: unknown hypercall 0x%llx\n", hcall_id);
        inst->run_result = PHANTOM_RESULT_HYPERCALL_ERROR;
        return phantom_abort_and_restore(inst);
    }
}
```

### Hypercall Input Validation (§6.5)

Every VMCALL parameter must be validated before use:

```c
static int hcall_get_payload(struct phantom_instance *inst,
                              struct vcpu *vcpu, u64 guest_buf_addr)
{
    /*
     * Validate: payload buffer address must be within guest EPT-mapped RAM.
     * NOT MMIO, NOT reserved, NOT host-physical address space.
     */
    enum gpa_type type = classify_gpa(inst, guest_buf_addr);
    if (type != GPA_TYPE_RAM) {
        pr_warn("phantom: GET_PAYLOAD: invalid GPA 0x%llx (type=%d)\n",
                guest_buf_addr, type);
        inst->run_result = PHANTOM_RESULT_HYPERCALL_ERROR;
        return phantom_abort_and_restore(inst);
    }

    /* Bounds check: entire payload buffer must fit within RAM range */
    if (guest_buf_addr + PHANTOM_PAYLOAD_SIZE > classify_gpa_end(inst, guest_buf_addr)) {
        pr_warn("phantom: GET_PAYLOAD: buffer overflows RAM region\n");
        return phantom_abort_and_restore(inst);
    }

    /* Register the payload buffer GPA for this instance */
    inst->payload_gpa = guest_buf_addr;
    return 0;  /* Guest receives 0 in RAX = success */
}
```

**String arguments (PRINTF hypercall):** length-bounded, no kernel pointer dereference:

```c
static int hcall_printf(struct phantom_instance *inst, struct vcpu *vcpu, u64 str_gpa)
{
    char buf[256];  /* Fixed max length — no unbounded copy */
    u64  gpa = str_gpa;
    u32  len = 0;

    /* Copy guest string with explicit length limit */
    while (len < sizeof(buf) - 1) {
        u8 c = phantom_read_guest_byte(inst, gpa + len);
        if (c == '\0') break;
        buf[len++] = c;
    }
    buf[len] = '\0';

    pr_info("phantom[inst%d]: guest: %s\n", inst->id, buf);
    return 0;
}
```

### Error Handling for Hardware and Guest Errors (§5.5 — Appendix A)

**Hardware errors (VMLAUNCH fail, VMCS consistency check failures):**
- Log full VMCS dump via `debug.c`
- Mark instance as `PHANTOM_STATE_FAILED`
- Return `PHANTOM_ERROR_HARDWARE` to userspace
- **Do NOT re-run.** Instance must be destroyed and recreated.

**Guest errors (triple fault, timeout, KASAN, unexpected exception):**
- Abort the current iteration immediately
- Perform snapshot restore
- Set iteration result: `PHANTOM_RESULT_CRASH`, `PHANTOM_RESULT_TIMEOUT`, or `PHANTOM_RESULT_KASAN`
- Return to userspace — instance is fully usable for next iteration

## Key Data Structures

```c
/* Iteration result codes */
#define PHANTOM_RESULT_OK                 0
#define PHANTOM_RESULT_CRASH              1  /* Guest crashed (triple fault, etc.) */
#define PHANTOM_RESULT_TIMEOUT            2  /* VMX preemption timer fired */
#define PHANTOM_RESULT_KASAN              3  /* KASAN violation reported */
#define PHANTOM_RESULT_HYPERCALL_ERROR    4  /* Invalid hypercall parameter */

/* Error codes */
#define PHANTOM_ERROR_HARDWARE           -1  /* Instance must be destroyed */
#define PHANTOM_ERROR_POOL_EXHAUSTED     -2  /* Instance still usable */
#define PHANTOM_ERROR_DIRTY_OVERFLOW     -3  /* Instance still usable */

/* Shared memory layout for /dev/phantom mmap */
struct phantom_shared_mem {
    u8   payload[PHANTOM_PAYLOAD_MAX];  /* Host writes, guest reads (WB) */
    u32  status;                         /* PHANTOM_RESULT_* from last iter */
    u32  coverage_flags;                 /* PHANTOM_COVERAGE_DISCARDED, etc. */
    u64  crash_addr;                     /* Valid when status == CRASH */
};
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/hypercall.c` | Full nyx_api VMCALL handler + input validation |
| `kernel/interface.c` | mmap regions for payload/status/coverage bitmap |
| `kernel/snapshot.c` | ACQUIRE triggers snapshot create; RELEASE triggers restore |

## Reference Sections

- §2.7: Coherency model full — same-core pinning, TSO, affinity enforcement pseudocode, WB mapping requirement
- §6.5: Hypercall validation rules — payload buffer GPA check, PRINTF string bounds, abort on invalid params
- §5.5 Appendix A §1–2: Hardware and guest errors — VMCS dump, PHANTOM_STATE_FAILED, snapshot restore on guest error

## Tests to Run

- 1000 VMCALL round-trips with distinct 64-bit values: host sends value via payload buffer, guest reads and returns it, host verifies (pass = all 1000 values match, zero mismatches)
- Invalid payload address (MMIO GPA, reserved GPA, out-of-range address): all cases abort cleanly without host panic (pass = `PHANTOM_ERROR` returned, no kernel oops)
- Shared memory payload buffer readable by guest via pre-registered address (pass = guest reads correct bytes written by host)
- Status word reflects correct iteration outcome for ok/crash/timeout/kasan cases (pass = status word matches injected condition in all 4 cases)

## Deliverables

Existing kAFL guest harnesses work on Phantom without modification (kAFL/Nyx ABI fully implemented).
