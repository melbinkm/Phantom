# Task 2.3: Userspace Interface + Frontend Integration

> **Phase:** Fuzzing Pipeline | **Week(s):** 17–18 | **Depends on:** [Task 2.2](task-2.2-intel-pt-coverage.md)

## Objective

Finalize the `/dev/phantom` ioctl API with mmap bounds enforcement, integrate AFL++ and kAFL frontends, and validate end-to-end fuzzing on a real Class A parser target for 24 hours.

## What to Build

- Final `/dev/phantom` ioctl API: `PHANTOM_CREATE_VM` (allocate VM instance on specified core, return instance ID), `PHANTOM_LOAD_TARGET` (load guest binary/kernel into VM memory), `PHANTOM_SET_SNAPSHOT` (trigger snapshot at current state), `PHANTOM_RUN_ITERATION` (inject payload + execute one iteration + restore), `PHANTOM_GET_STATUS` (retrieve last iteration result: ok/crash/timeout/kasan), `PHANTOM_DESTROY_VM` (teardown VM, free resources); debug ioctls compiled in only with `PHANTOM_DEBUG`: `PHANTOM_DEBUG_DUMP_VMCS`, `PHANTOM_DEBUG_DUMP_EPT`, `PHANTOM_DEBUG_DUMP_DIRTY_LIST`
- `mmap` regions with bounds enforcement: every mmap request validated — offset and size must be within the designated region for that instance; regions: payload buffer (read-write by userspace), coverage bitmap (read-only by userspace), PT trace buffers A and B (read-only by userspace), status/control structure (read-only by userspace)
- AFL++ integration (`afl-phantom`): fork-server shim replacement; AFL++ calls `PHANTOM_RUN_ITERATION` instead of `fork()`; reads bitmap from mmap'd region instead of shared memory pipe; handles crash/timeout signals via status word
- kAFL frontend bridge (`kafl-bridge`): thin Python adapter translating kAFL's interface expectations to Phantom ioctls
- End-to-end Class A test: target libxml2 `xmlParseMemory` or similar parser function; AFL++ drives mutation, Phantom executes iterations, coverage bitmap guides evolution; run for 24 hours, measure exec/sec, corpus size, coverage over time

## Implementation Guidance

### mmap Bounds Enforcement (§6.5)

Every mmap request must be validated before calling `remap_pfn_range`:

```c
static int phantom_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct phantom_instance *inst = filp->private_data;
    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
    unsigned long size   = vma->vm_end - vma->vm_start;

    /* Determine which region this offset maps to */
    struct phantom_mmap_region *region = phantom_find_mmap_region(inst, offset);
    if (!region) {
        pr_warn("phantom: mmap: unknown offset 0x%lx\n", offset);
        return -EINVAL;
    }

    /* Bounds check: request must fit entirely within the designated region */
    if (offset + size > region->offset + region->size) {
        pr_warn("phantom: mmap: request exceeds region bounds\n");
        return -EINVAL;
    }

    /* Instance isolation: verify this fd belongs to the correct instance */
    if (inst->id != region->instance_id) {
        pr_warn("phantom: mmap: cross-instance access attempt\n");
        return -EACCES;
    }

    /* Apply correct protections per region type */
    if (region->type == MMAP_REGION_PAYLOAD)
        vma->vm_flags |= VM_READ | VM_WRITE;
    else
        vma->vm_flags &= ~VM_WRITE;  /* Coverage bitmap, PT buffers: read-only */

    return remap_pfn_range(vma, vma->vm_start,
                           region->phys_start >> PAGE_SHIFT,
                           size, vma->vm_page_prot);
}
```

### Per-Instance Memory Formula (from §4.3)

```
total_per_instance = guest_mem + cow_pool + topa_buffers + ept_tables + vmcs + xsave_area

Class A example:
  guest_mem:    16MB   (flat GPA space)
  cow_pool:     16MB   (4096 × 4KB pages)
  topa_buffers:  4MB   (2 × 2MB double-buffer)
  ept_tables:    ~2MB  (4-level EPT, minimal)
  vmcs:          4KB
  xsave_area:    4KB
  Total:        ~38MB per Class A instance

Class B example:
  guest_mem:   256MB
  cow_pool:     64MB
  topa_buffers: 16MB   (2 × 8MB double-buffer)
  ept_tables:    ~2MB
  vmcs:          4KB
  xsave_area:    4KB
  Total:        ~338MB per Class B instance
```

**Memory accounting:** Track via `atomic64_t phantom_allocated_bytes`. Enforce `max_memory_mb` limit. Use `__GFP_ACCOUNT` flag on all allocations for cgroup visibility.

### Final Ioctl API Reference

```c
/* /dev/phantom ioctl numbers */
#define PHANTOM_IOC_MAGIC  'P'
#define PHANTOM_CREATE_VM         _IOWR(PHANTOM_IOC_MAGIC, 0x01, struct phantom_create_args)
#define PHANTOM_LOAD_TARGET       _IOW (PHANTOM_IOC_MAGIC, 0x02, struct phantom_load_args)
#define PHANTOM_SET_SNAPSHOT      _IO  (PHANTOM_IOC_MAGIC, 0x03)
#define PHANTOM_RUN_ITERATION     _IOWR(PHANTOM_IOC_MAGIC, 0x04, struct phantom_run_args)
#define PHANTOM_GET_STATUS        _IOR (PHANTOM_IOC_MAGIC, 0x05, struct phantom_status)
#define PHANTOM_DESTROY_VM        _IO  (PHANTOM_IOC_MAGIC, 0x06)

/* Debug ioctls — only with PHANTOM_DEBUG */
#ifdef PHANTOM_DEBUG
#define PHANTOM_DEBUG_DUMP_VMCS      _IO(PHANTOM_IOC_MAGIC, 0x10)
#define PHANTOM_DEBUG_DUMP_EPT       _IO(PHANTOM_IOC_MAGIC, 0x11)
#define PHANTOM_DEBUG_DUMP_DIRTY_LIST _IO(PHANTOM_IOC_MAGIC, 0x12)
#endif
```

### Userspace Repository Layout (from §10)

```
userspace/
├── phantom-pt-decode/        # PT trace → AFL bitmap daemon
│   ├── main.c               # eventfd/epoll loop, double-buffer management
│   ├── decode.c             # libipt wrapper
│   └── bitmap.c             # AFL bitmap generation
├── phantom-ctl/              # CLI tool for /dev/phantom
├── afl-phantom/              # AFL++ fork-server replacement
└── kafl-bridge/              # kAFL frontend adapter (Python)
```

### Access Control (§6.5)

```c
/* chardev open: restrict to CAP_SYS_ADMIN or phantom group */
static int phantom_open(struct inode *inode, struct file *filp)
{
    if (!capable(CAP_SYS_ADMIN) && !in_group_p(phantom_gid)) {
        return -EPERM;
    }
    /* Allocate per-fd state */
    filp->private_data = phantom_alloc_fd_state();
    return filp->private_data ? 0 : -ENOMEM;
}
```

## Key Data Structures

```c
/* PHANTOM_CREATE_VM arguments */
struct phantom_create_args {
    u32  pinned_cpu;          /* Physical CPU to pin this instance to   */
    u32  cow_pool_pages;      /* CoW pool size (0 = use class default)  */
    u32  topa_size_mb;        /* ToPA buffer size (0 = use class default) */
    u32  guest_mem_mb;        /* Guest physical memory size             */
    u32  instance_id;         /* Output: assigned instance ID           */
};

/* mmap region types */
#define PHANTOM_MMAP_PAYLOAD    0x00000  /* Payload buffer — RW            */
#define PHANTOM_MMAP_BITMAP     0x10000  /* Coverage bitmap — RO, 64KB     */
#define PHANTOM_MMAP_TOPA_A     0x20000  /* PT trace buffer A — RO         */
#define PHANTOM_MMAP_TOPA_B     0x30000  /* PT trace buffer B — RO         */
#define PHANTOM_MMAP_STATUS     0x40000  /* Status/control struct — RO     */
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/interface.c` | Final ioctl API, mmap bounds enforcement, access control |
| `userspace/afl-phantom/` | AFL++ fork-server shim |
| `userspace/kafl-bridge/` | kAFL Python adapter |

## Reference Sections

- §6.5: mmap bounds enforcement — per-instance region validation, cross-instance access check
- §6.8: Memory accounting per-instance — atomic counter, cgroup visibility, Class A/B formulas
- §4.3: Per-instance memory formula — Class A ~38MB, Class B ~338MB
- §10: Userspace repo layout — directory structure for phantom-pt-decode, afl-phantom, kafl-bridge

## Tests to Run

- End-to-end fuzzing with AFL++ and kAFL on a real parser target runs without errors (pass = no panics, no resource leaks over a 1-hour initial run)
- 24-hour stability run: no host panics, no memory leaks, exec/sec at hour 24 ≥ 90% of exec/sec at hour 1 (pass = both conditions met)
- Out-of-range mmap request returns EINVAL (pass = kernel rejects request, no crash)
- exec/sec measured and documented for the 24-hour run (pass = value recorded)

## Deliverables

End-to-end fuzzing loop working with both AFL++ and kAFL frontends on a real Class A target.
