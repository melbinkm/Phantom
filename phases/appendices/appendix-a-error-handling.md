# Appendix A: §5.5 Error Handling and Recovery Strategy

> Part of [Project Phantom Development Plan](../../project-phantom-dev-plan-v2.md)
>
> This appendix is cross-referenced by multiple tasks. See also [Appendix B: Debugging Tooling](appendix-b-debugging-tooling.md).

Phantom must handle errors gracefully without corrupting host state or requiring machine reboot. Four error categories:

## 1. Hardware Errors (VMLAUNCH fail, VMCS consistency check failures)

**Examples:** VMLAUNCH returns with VM-instruction error (CF=1), VMCS validation fails before entry, unexpected #GP in VMX-root mode.

**Response:**
- Log a full VMCS dump via `debug.c` (all fields, structured output)
- Mark the affected instance as `PHANTOM_STATE_FAILED`
- Return `PHANTOM_ERROR_HARDWARE` to userspace via ioctl
- **Do NOT re-run.** The instance must be destroyed (`PHANTOM_DESTROY_VM`) and recreated by userspace.
- Other instances on other cores are unaffected.

## 2. Guest Errors (Triple fault, timeout, KASAN, unexpected exception)

**Examples:** Guest triple-faults (e.g., stack overflow, null pointer deref), VMX preemption timer fires (timeout), guest reports KASAN violation via hypercall.

**Response:**
- Abort the current iteration immediately
- Perform snapshot restore to reset guest state (the guest error does not corrupt snapshot state)
- Set iteration result: `PHANTOM_RESULT_CRASH`, `PHANTOM_RESULT_TIMEOUT`, or `PHANTOM_RESULT_KASAN`
- Return to userspace via ioctl — instance is fully usable for next iteration
- Log crash address, exit reason, and truncated VMCS dump to ring buffer

## 3. Resource Errors (Pool exhaustion, ToPA overflow, dirty list overflow)

**Examples:** CoW page pool runs out before iteration completes, dirty list hits maximum entries, ToPA buffer overflow detected via PMI.

**Response:**
- **Pool exhaustion:** Abort iteration. Walk dirty list, return all private pages to pool, reset EPT mappings to read-only originals. Return `PHANTOM_ERROR_POOL_EXHAUSTED` to userspace. Instance remains usable. Consider auto-resize (double pool size, reallocate) as a future enhancement.
- **Dirty list overflow:** Abort iteration. Same cleanup as pool exhaustion. Return `PHANTOM_ERROR_DIRTY_OVERFLOW`. Increase `max_dirty_pages` parameter for this instance.
- **ToPA overflow:** Do not abort execution. However, mark the iteration's coverage as **non-scoring for corpus decisions** (`PHANTOM_COVERAGE_DISCARDED` flag in status word) — an incomplete bitmap can show apparent "new" edges simply because previously-seen edges are missing from the truncated trace, poisoning the corpus with false positives. The iteration still executes (crash/timeout/kasan results are still recorded), but the bitmap is NOT used for coverage-guided corpus selection. The input is queued for re-execution when possible. Continue execution until RELEASE hypercall or timeout. Increment "ToPA overflow" health counter. A per-instance flag `accept_approximate_coverage` (default: false) allows users to opt in to using truncated traces for corpus decisions — useful for initial exploration where coverage accuracy is less critical than throughput.

## 4. Host Errors (NMI during handler, unexpected interrupt, corrupted VMX state)

**Examples:** NMI during VM exit handler, unexpected host kernel panic from unrelated cause, VMXOFF fails.

**Response:**
- **NMI during exit handler:** Handle via NMI-exiting + NMI-safe handler per Section 2.6. Re-deliver to host via APIC self-NMI (recommended) or virtual-NMI IRET unblocking — see Section 2.6 for details. No instance state affected.
- **If VMX state is corrupted** (detected via VMREAD failure or VMRESUME returning unexpected error): mark all instances on that core as `PHANTOM_STATE_FAILED`. Do not attempt further VM operations on that core. Return errors to userspace for all subsequent ioctls on those instances.
- **Host kernel panic:** kdump fires, crash dump available for post-mortem via `crash` utility. See [Appendix B](appendix-b-debugging-tooling.md) for documented procedure.

**PT Daemon Crash Recovery:**

If the userspace PT decode daemon crashes, the kernel detects the fd close event via the chardev `release` handler. Response:
1. Stop copying PT trace data to userspace mapping (kernel-side: stop signalling eventfd)
2. Continue fuzzing without coverage feedback (exec/sec maintained, corpus guidance degraded)
3. Log warning: "PT daemon disconnected for instance N"
4. A new daemon can attach by re-opening `/dev/phantom` and re-registering via ioctl

## Error Code Reference

```c
/* Instance state */
#define PHANTOM_STATE_OK      0   /* Normal operation                      */
#define PHANTOM_STATE_FAILED  1   /* Unrecoverable — destroy and recreate  */

/* Iteration result codes */
#define PHANTOM_RESULT_OK              0
#define PHANTOM_RESULT_CRASH           1  /* Guest crashed                 */
#define PHANTOM_RESULT_TIMEOUT         2  /* Preemption timer fired        */
#define PHANTOM_RESULT_KASAN           3  /* KASAN violation               */
#define PHANTOM_RESULT_HYPERCALL_ERROR 4  /* Invalid hypercall parameter   */

/* Error codes (ioctl return values) */
#define PHANTOM_ERROR_HARDWARE       -1   /* Instance in FAILED state      */
#define PHANTOM_ERROR_POOL_EXHAUSTED -2   /* Instance still usable         */
#define PHANTOM_ERROR_DIRTY_OVERFLOW -3   /* Instance still usable         */

/* Coverage flags */
#define PHANTOM_COVERAGE_DISCARDED (1 << 0)  /* ToPA overflow — don't use bitmap */
```

## Cross-Task References

- **Task 1.4** (First CoW fault): Pool exhaustion recovery — abort, restore, return error
- **Task 2.1** (Hypercall interface): Guest error handling — KASAN/PANIC hypercalls
- **Task 2.2** (Intel PT): ToPA overflow → PHANTOM_COVERAGE_DISCARDED
- **Task 2.4** (Hardening): Complete error classification, PT daemon recovery
- **Task 1.2** (VMCS + NMI): NMI-safe exit handler, APIC self-NMI re-delivery
