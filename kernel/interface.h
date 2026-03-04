// SPDX-License-Identifier: GPL-2.0-only
/*
 * interface.h — /dev/phantom chardev declarations
 *
 * Exposes the chardev file operations and the ioctl registration
 * entry points.  The ioctl command numbers are defined here so that
 * both kernel (interface.c) and userspace test binaries can include
 * a single authoritative header.
 *
 * Version history:
 *   0x00010100  task 1.1 — GET_VERSION only
 *   0x00010200  task 1.2 — RUN_GUEST added
 *   0x00010800  task 1.8 — PERF_RESTORE_LATENCY added
 */
#ifndef PHANTOM_INTERFACE_H
#define PHANTOM_INTERFACE_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* ------------------------------------------------------------------
 * Version encoding: 0xMMmmpp  (Major . minor . patch)
 * Task 1.2 baseline: version 1.2.0 = 0x00010200
 * Task 1.3 baseline: version 1.3.0 = 0x00010300
 * Task 1.4 baseline: version 1.4.0 = 0x00010400
 * Task 1.5 baseline: version 1.5.0 = 0x00010500
 * Task 1.6 baseline: version 1.6.0 = 0x00010600
 * Task 1.8 baseline: version 1.8.0 = 0x00010800
 * Task 2.1 baseline: version 2.1.0 = 0x00020100
 * Task 2.2 baseline: version 2.2.0 = 0x00020200
 * Task 2.3 baseline: version 2.3.0 = 0x00020300
 * ------------------------------------------------------------------ */
#define PHANTOM_VERSION		0x00020300U

/* ------------------------------------------------------------------
 * ioctl command numbers
 *
 * Magic byte 'P' (0x50).
 * ------------------------------------------------------------------ */
#define PHANTOM_IOCTL_MAGIC		'P'

/* _IOR: read-only from userspace perspective (kernel writes the result) */
#define PHANTOM_IOCTL_GET_VERSION	_IOR(PHANTOM_IOCTL_MAGIC, 0, __u32)

/*
 * PHANTOM_IOCTL_RUN_GUEST — load guest binary, run it, return result.
 *
 * Userspace fills in:
 *   cpu      — target CPU index (0 = first VMX CPU)
 *   reserved — test_id: 0 = R/W checksum test, 1 = absent-GPA test
 *
 * Kernel fills in on return:
 *   result      — checksum value returned by guest via SUBMIT_RESULT
 *   exit_reason — final VM exit reason code
 *
 * For test_id=1 (absent-GPA test):
 *   result      = 0 (no checksum)
 *   exit_reason = 48 (EPT violation, VMX_EXIT_EPT_VIOLATION)
 */
struct phantom_run_args {
	__u32 cpu;          /* IN: CPU index (0 = default)            */
	__u32 reserved;     /* IN: test_id (0=RW test, 1=absent-GPA)  */
	__u64 result;       /* OUT: checksum from guest SUBMIT_RESULT */
	__u32 exit_reason;  /* OUT: final VM exit reason              */
	__u32 padding;      /* struct alignment padding               */
};

#define PHANTOM_IOCTL_RUN_GUEST		_IOWR(PHANTOM_IOCTL_MAGIC, 1, \
					      struct phantom_run_args)

/*
 * PHANTOM_IOCTL_DEBUG_DUMP_EPT — walk the EPT and emit trace_printk output.
 *
 * No arguments.  Output goes to /sys/kernel/debug/tracing/trace.
 * Returns 0 on success, -EINVAL if pages not allocated.
 */
#define PHANTOM_IOCTL_DEBUG_DUMP_EPT	_IO(PHANTOM_IOCTL_MAGIC, 6)

/*
 * PHANTOM_IOCTL_DEBUG_DUMP_DIRTY_LIST — dump CoW dirty list entries.
 *
 * No arguments.  Emits DIRTY_ENTRY lines via trace_printk.
 * Also emits DIRTY_OVERFLOW line if dirty_overflow_count > 0.
 * Output goes to /sys/kernel/debug/tracing/trace.
 * Returns 0 on success, -EINVAL if dirty_list not allocated.
 */
#define PHANTOM_IOCTL_DEBUG_DUMP_DIRTY_LIST	_IO(PHANTOM_IOCTL_MAGIC, 7)

/*
 * PHANTOM_IOCTL_DEBUG_DUMP_DIRTY_OVERFLOW — report dirty list overflow count.
 *
 * No arguments.  Emits one trace_printk line:
 *   "DIRTY_OVERFLOW count=N"
 * Returns 0 on success.  Also returns 0 if no overflows have occurred.
 */
#define PHANTOM_IOCTL_DEBUG_DUMP_DIRTY_OVERFLOW	_IO(PHANTOM_IOCTL_MAGIC, 8)

/*
 * PHANTOM_IOCTL_SNAPSHOT_CREATE — capture current guest state as snapshot.
 *
 * No arguments.  Takes a full snapshot of the current guest architectural
 * state: GPRs, VMCS fields (CRs, segments, MSRs), and XSAVE area.
 * Also marks all EPT RAM pages read-only (CoW protection enabled).
 *
 * Workflow:
 *   1. RUN_GUEST (with test_id=7) — guest runs to VMCALL snapshot point
 *   2. SNAPSHOT_CREATE — save state, mark EPT RO
 *   3. RUN_GUEST — guest runs from the snapshot point (CoW tracks writes)
 *   4. SNAPSHOT_RESTORE — reset to snapshot for next iteration
 *   5. Repeat 3-4 in tight loop
 *
 * Returns 0 on success, -ENXIO if device not initialised.
 */
#define PHANTOM_IOCTL_SNAPSHOT_CREATE	_IO(PHANTOM_IOCTL_MAGIC, 9)

/*
 * PHANTOM_IOCTL_SNAPSHOT_RESTORE — restore guest to last snapshot.
 *
 * No arguments.  Resets dirty EPT PTEs, returns private pages to pool,
 * restores all VMCS guest-state fields, GPRs, and XSAVE area.
 * Issues one batched single-context INVEPT.
 *
 * Returns 0 on success, -EINVAL if no snapshot has been taken,
 * -ENXIO if device not initialised.
 */
#define PHANTOM_IOCTL_SNAPSHOT_RESTORE	_IO(PHANTOM_IOCTL_MAGIC, 10)

/*
 * PHANTOM_IOCTL_PERF_RESTORE_LATENCY — read rdtsc cycle counts from
 *   the last SNAPSHOT_RESTORE call.
 *
 * Returns a struct phantom_perf_result containing per-phase cycle deltas
 * measured during the most recent phantom_snapshot_restore() execution.
 * All counters are zero until the first SNAPSHOT_RESTORE has run.
 *
 * Fields:
 *   dirty_page_count  — number of dirty list entries processed
 *   dirty_walk_cycles — rdtsc delta: dirty list walk + EPT PTE resets
 *                       + private page pool returns
 *   invept_cycles     — rdtsc delta: single batched INVEPT instruction
 *   vmcs_cycles       — rdtsc delta: all VMCS field writes (CRs, segs,
 *                       descriptor tables, MSRs, interrupt state, GPRs)
 *   xrstor_cycles     — rdtsc delta: kernel_fpu_begin + XRSTOR + kernel_fpu_end
 *   total_cycles      — rdtsc delta: full restore path (t5 - t0)
 *
 * Returns 0 on success, -EINVAL if no snapshot has been created,
 * -EFAULT on copy_to_user failure.
 */
struct phantom_perf_result {
	__u64 dirty_page_count;
	__u64 dirty_walk_cycles;
	__u64 invept_cycles;
	__u64 vmcs_cycles;
	__u64 xrstor_cycles;
	__u64 total_cycles;
};

#define PHANTOM_IOCTL_PERF_RESTORE_LATENCY \
	_IOR(PHANTOM_IOCTL_MAGIC, 12, struct phantom_perf_result)

/* ------------------------------------------------------------------
 * Task 2.1: kAFL/Nyx ABI — shared memory, RUN_ITERATION, GET_RESULT
 * ------------------------------------------------------------------ */

/*
 * Maximum fuzz payload size: 64KB.
 *
 * This matches the kAFL/Nyx payload buffer convention.  The payload is
 * written into shared_mem->payload by the host before each iteration,
 * and the guest reads it via GET_PAYLOAD hypercall (which registers the
 * GPA and causes the host to memcpy on the next injection).
 */
#define PHANTOM_PAYLOAD_MAX		(1 << 16)  /* 64KB */

/*
 * struct phantom_shared_mem — kernel↔userspace shared memory region.
 *
 * This structure occupies the first mmap region of /dev/phantom.
 * Userspace writes payload[] before calling RUN_ITERATION; kernel
 * copies payload to the guest GPA registered via GET_PAYLOAD.
 * After each iteration the kernel writes status and crash_addr.
 *
 * Layout is ABI-stable: fields must not be reordered.
 *
 * Mapped via PHANTOM_IOCTL_MMAP_SHARED_MEM or standard mmap with
 * offset=0 on the /dev/phantom fd.
 */
struct phantom_shared_mem {
	__u8	payload[PHANTOM_PAYLOAD_MAX];	/* fuzz input for next iter  */
	__u32	payload_len;			/* valid bytes in payload[]  */
	__u32	status;				/* PHANTOM_RESULT_* last iter */
	__u64	crash_addr;			/* guest crash address       */
};

/*
 * struct phantom_iter_params — parameters for PHANTOM_IOCTL_RUN_ITERATION.
 *
 * payload_len: number of valid bytes in shared_mem->payload[].
 *              Must be <= PHANTOM_PAYLOAD_MAX.
 * timeout_ms:  VMX preemption timer budget in milliseconds.
 *              0 = use module default (no timeout).
 *              Non-zero values are converted to VMX preemption timer
 *              ticks at IOCTL time.
 */
struct phantom_iter_params {
	__u32 payload_len;	/* length of payload in shared_mem->payload */
	__u32 timeout_ms;	/* preemption timer timeout (0 = default)   */
};

/*
 * struct phantom_iter_result — result from PHANTOM_IOCTL_GET_RESULT.
 *
 * status:     PHANTOM_RESULT_* code from the last iteration.
 * crash_addr: Guest address at time of PANIC hypercall (if status==CRASH).
 *             0 if not a PANIC result.
 */
struct phantom_iter_result {
	__u32 status;		/* PHANTOM_RESULT_* */
	__u32 _pad;
	__u64 crash_addr;
};

/*
 * PHANTOM_IOCTL_RUN_ITERATION — run one fuzzing iteration.
 *
 * Userspace must have written the payload into shared_mem->payload[]
 * (via mmap) before calling this ioctl.  The ioctl:
 *   1. Copies payload from shared_mem into guest RAM at payload_gpa.
 *   2. Signals the vCPU thread to VMRESUME from the snapshot point.
 *   3. Blocks until the iteration completes (RELEASE/PANIC/KASAN/timeout).
 *   4. Writes status and crash_addr back to shared_mem.
 *   5. Returns 0; status is available via GET_RESULT or shared_mem.
 *
 * Requires: ACQUIRE hypercall must have fired at least once (snapshot
 * must be taken) before calling RUN_ITERATION.
 *
 * Returns 0 on success (check status for iteration result).
 * Returns -EINVAL if no snapshot has been taken.
 * Returns -ENXIO if device not initialised.
 */
#define PHANTOM_IOCTL_RUN_ITERATION \
	_IOWR(PHANTOM_IOCTL_MAGIC, 20, struct phantom_iter_params)

/*
 * PHANTOM_IOCTL_GET_RESULT — retrieve result of last iteration.
 *
 * Returns a snapshot of status and crash_addr from state.
 * Safe to call after RUN_ITERATION completes.
 */
#define PHANTOM_IOCTL_GET_RESULT \
	_IOR(PHANTOM_IOCTL_MAGIC, 21, struct phantom_iter_result)

/*
 * ------------------------------------------------------------------
 * Task 2.2: Intel PT coverage — mmap offsets and PT eventfd ioctl
 * ------------------------------------------------------------------
 *
 * /dev/phantom mmap offset constants.
 *
 * mmap() uses the page offset (vma->vm_pgoff << PAGE_SHIFT) to select
 * which region to map:
 *
 *   PHANTOM_MMAP_SHARED_MEM (0x00000): struct phantom_shared_mem
 *     Payload[64KB] + status u32 + crash_addr u64.
 *     Size: sizeof(struct phantom_shared_mem) rounded to page order.
 *
 *   PHANTOM_MMAP_TOPA_BUF_A (0x10000): PT output buffer slot 0
 *     PHANTOM_PT_PAGES_PER_SLOT × 4KB of PT packet data.
 *     Written by hardware during guest execution.
 *     Valid byte count available after PT_GET_EVENTFD notification.
 *
 *   PHANTOM_MMAP_TOPA_BUF_B (0x20000): PT output buffer slot 1
 *     Same layout as slot 0 — the double-buffer alternate.
 *
 * The mmap offset must match one of these constants exactly (not a
 * range).  Any other offset returns -EINVAL.
 *
 * Note: PHANTOM_MMAP_TOPA_BUF_A and PHANTOM_MMAP_TOPA_BUF_B are
 * defined in the Task 2.3 section below with updated offset values.
 * The Task 2.2 legacy offsets (0x10000, 0x20000) are also supported
 * for backwards compatibility.
 */
#define PHANTOM_MMAP_SHARED_MEM		0x00000UL

/*
 * PHANTOM_IOCTL_PT_GET_EVENTFD — get eventfd for PT iteration notification.
 *
 * Creates an eventfd in the calling process's file descriptor table and
 * stores a reference to it in state->pt.eventfd.  After each fuzzing
 * iteration, the kernel writes 1 to the eventfd to notify the userspace
 * PT decoder that a new trace buffer is ready.
 *
 * Userspace should epoll() on this fd for EPOLLIN events.
 *
 * Returns the eventfd file descriptor number on success (non-negative).
 * Returns -ENXIO if device not initialised.
 * Returns -EINVAL if PT is not available on this system.
 * Returns -EEXIST if an eventfd is already registered (call again after
 *   module reload to replace it).
 *
 * The eventfd is automatically released when the /dev/phantom fd is
 * closed or the module is unloaded.
 */
#define PHANTOM_IOCTL_PT_GET_EVENTFD	_IO(PHANTOM_IOCTL_MAGIC, 13)

/*
 * struct phantom_pt_status — written to eventfd notification data area.
 *
 * After each iteration, the kernel signals the eventfd.  Userspace
 * reads which buffer is ready and the byte count from this struct,
 * which is stored in the shared_mem region at a fixed offset.
 *
 * byte_count:    Number of PT bytes written in the completed iteration.
 *               0 if PT is disabled or iteration produced no trace.
 * buffer_index:  Index of the buffer containing the completed trace.
 *               0 = TOPA_BUF_A, 1 = TOPA_BUF_B.
 *               The next iteration will write to the other buffer.
 */
struct phantom_pt_status {
	__u64 byte_count;
	__u32 buffer_index;
	__u32 _pad;
};

/* ------------------------------------------------------------------
 * Task 2.3: Production ioctl API
 *
 * Uses PHANTOM_IOC_MAGIC 'P' (same as PHANTOM_IOCTL_MAGIC above).
 * New command numbers start at 0x01 and do not conflict with the
 * legacy ioctl numbers (0–21) because _IOWR encodes the type, size,
 * and direction bits into the 32-bit cmd value alongside the number.
 *
 * The legacy ioctl numbers remain fully functional.
 * ------------------------------------------------------------------ */

/* Re-export magic for new API name */
#define PHANTOM_IOC_MAGIC		PHANTOM_IOCTL_MAGIC

/*
 * struct phantom_create_args — arguments for PHANTOM_CREATE_VM.
 *
 * pinned_cpu:    Physical CPU to pin this instance to.
 *               Must be present in the VMX cpumask.
 * cow_pool_pages: CoW pool size in pages (0 = use module default).
 * topa_size_mb:  ToPA buffer size in MB (0 = use module default).
 * guest_mem_mb:  Guest physical memory in MB (0 = use module default).
 * instance_id:  Output: assigned instance ID (currently always 0).
 */
struct phantom_create_args {
	__u32 pinned_cpu;
	__u32 cow_pool_pages;
	__u32 topa_size_mb;
	__u32 guest_mem_mb;
	__u32 instance_id;   /* OUT */
	__u32 _pad;
};

/*
 * struct phantom_load_args — arguments for PHANTOM_LOAD_TARGET.
 *
 * gpa:           Guest physical address to load binary at.
 * userspace_ptr: Userspace pointer to binary data.
 * size:          Size in bytes (must be <= PHANTOM_PAYLOAD_MAX).
 */
struct phantom_load_args {
	__u64 gpa;
	__u64 userspace_ptr;
	__u64 size;
};

/*
 * struct phantom_run_args2 — arguments for PHANTOM_RUN_ITERATION.
 *
 * Named phantom_run_args2 to avoid conflict with the legacy
 * struct phantom_run_args defined above (task 1.2 style).
 *
 * payload_ptr:   Userspace pointer to fuzz input data.
 * payload_size:  Payload size in bytes (must be <= PHANTOM_PAYLOAD_MAX).
 * timeout_ms:    VMX preemption timer timeout in ms (0 = default 1000ms).
 * result:        Output: PHANTOM_RESULT_* code.
 * exit_reason:   Output: last VM exit reason code.
 * checksum:      Output: guest execution checksum (run_result_data).
 */
struct phantom_run_args2 {
	__u64 payload_ptr;    /* IN  */
	__u32 payload_size;   /* IN  */
	__u32 timeout_ms;     /* IN  */
	__u32 result;         /* OUT */
	__u32 exit_reason;    /* OUT */
	__u64 checksum;       /* OUT */
};

/*
 * struct phantom_status — result for PHANTOM_GET_STATUS.
 *
 * result:      PHANTOM_RESULT_* from the last iteration.
 * exit_reason: Last VM exit reason.
 * crash_addr:  Guest crash address (if result == PHANTOM_RESULT_CRASH).
 * checksum:    Last iteration checksum (run_result_data).
 * iterations:  Total iterations executed (currently not tracked; always 0).
 */
struct phantom_status {
	__u32 result;
	__u32 exit_reason;
	__u64 crash_addr;
	__u64 checksum;
	__u64 iterations;
};

/*
 * VM lifecycle ioctls — command numbers start at 0x30 to avoid
 * collisions with legacy ioctl numbers (0x00–0x0D, 0x14, 0x15).
 *
 * The full 32-bit ioctl cmd is:
 *   (dir << 30) | (size << 16) | (magic << 8) | nr
 * Two ioctls collide only when dir, size, magic, AND nr all match.
 * Using nr >= 0x30 guarantees no overlap with any legacy nr.
 */
#define PHANTOM_CREATE_VM \
	_IOWR(PHANTOM_IOC_MAGIC, 0x30, struct phantom_create_args)
#define PHANTOM_LOAD_TARGET \
	_IOW(PHANTOM_IOC_MAGIC,  0x31, struct phantom_load_args)
#define PHANTOM_SET_SNAPSHOT \
	_IO(PHANTOM_IOC_MAGIC,   0x32)
#define PHANTOM_RUN_ITERATION \
	_IOWR(PHANTOM_IOC_MAGIC, 0x33, struct phantom_run_args2)
#define PHANTOM_GET_STATUS \
	_IOR(PHANTOM_IOC_MAGIC,  0x34, struct phantom_status)
#define PHANTOM_DESTROY_VM \
	_IO(PHANTOM_IOC_MAGIC,   0x35)

/* Debug ioctls — only compiled when PHANTOM_DEBUG is defined */
#ifdef PHANTOM_DEBUG
#define PHANTOM_DEBUG_DUMP_VMCS \
	_IO(PHANTOM_IOC_MAGIC, 0x40)
#define PHANTOM_DEBUG_DUMP_EPT_NEW \
	_IO(PHANTOM_IOC_MAGIC, 0x41)
#define PHANTOM_DEBUG_DUMP_DIRTY_LIST_NEW \
	_IO(PHANTOM_IOC_MAGIC, 0x42)
#endif /* PHANTOM_DEBUG */

/* ------------------------------------------------------------------
 * Task 2.3: Final mmap region layout
 *
 * The five supported mmap offsets are:
 *
 *   PHANTOM_MMAP_PAYLOAD    (0x00000): Payload buffer, RW, 64KB
 *     Alias for PHANTOM_MMAP_SHARED_MEM — same backing pages,
 *     but future code should use PHANTOM_MMAP_PAYLOAD.
 *
 *   PHANTOM_MMAP_BITMAP     (0x10000): Coverage bitmap, RO, 64KB
 *     AFL++ edge bitmap (Phase 3; stub/placeholder for now).
 *     Maps the shared_mem region for backwards-compatibility until
 *     the bitmap has its own allocation.
 *
 *   PHANTOM_MMAP_TOPA_BUF_A (0x20000): PT trace buffer A, RO
 *     Maps PHANTOM_PT_PAGES_PER_SLOT pages of PT output data.
 *     Offset was 0x10000 in task 2.2; updated for final layout.
 *     The old 0x10000 offset still works (PHANTOM_MMAP_TOPA_BUF_A_LEGACY).
 *
 *   PHANTOM_MMAP_TOPA_BUF_B (0x30000): PT trace buffer B, RO
 *     Maps the alternate PT double-buffer slot.
 *     Old offset was 0x20000 (PHANTOM_MMAP_TOPA_BUF_B_LEGACY).
 *
 *   PHANTOM_MMAP_STATUS     (0x40000): Status struct, RO, 4KB
 *     Read-only view of current phantom_status.  Populated after
 *     each iteration.  Mapped from shared_mem header area.
 *
 * Note: PHANTOM_MMAP_SHARED_MEM (0x00000) remains valid as the
 * legacy alias for PHANTOM_MMAP_PAYLOAD.
 * ------------------------------------------------------------------ */
#define PHANTOM_MMAP_PAYLOAD		0x00000UL  /* RW  — payload buffer   */
#define PHANTOM_MMAP_BITMAP		0x10000UL  /* RO  — coverage bitmap  */
#define PHANTOM_MMAP_TOPA_BUF_A		0x20000UL  /* RO  — PT buffer A      */
#define PHANTOM_MMAP_TOPA_BUF_B		0x30000UL  /* RO  — PT buffer B      */
#define PHANTOM_MMAP_STATUS		0x40000UL  /* RO  — status struct    */

/*
 * Legacy aliases for mmap offsets from task 2.2.
 * Old TOPA offsets (0x10000 and 0x20000) overlap the new BITMAP and
 * TOPA_BUF_A constants.  Code that used the old constants must be
 * updated to use the new ones.  The kernel mmap handler supports
 * both to maintain backwards compatibility with compiled test binaries.
 */
#define PHANTOM_MMAP_TOPA_BUF_A_LEGACY	0x10000UL
#define PHANTOM_MMAP_TOPA_BUF_B_LEGACY	0x20000UL

/* ------------------------------------------------------------------
 * Forward declaration — struct phantom_dev is defined in phantom.h
 * ------------------------------------------------------------------ */
struct phantom_dev;

/**
 * phantom_chardev_register - Allocate device number and register cdev.
 * @pdev: Device context; cdev, class, and devno are populated on success.
 *
 * Creates /dev/phantom via udev/mdev notification.
 * Returns 0 on success, negative errno on failure.
 */
int phantom_chardev_register(struct phantom_dev *pdev);

/**
 * phantom_chardev_unregister - Remove cdev and release device number.
 * @pdev: Device context.
 *
 * Safe to call if phantom_chardev_register() partially succeeded.
 */
void phantom_chardev_unregister(struct phantom_dev *pdev);

#endif /* PHANTOM_INTERFACE_H */
