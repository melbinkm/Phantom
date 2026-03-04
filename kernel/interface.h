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
 * ------------------------------------------------------------------ */
#define PHANTOM_VERSION		0x00010800U

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

/*
 * Reserved for future phases:
 *
 * PHANTOM_IOCTL_CREATE_INSTANCE	_IOW(PHANTOM_IOCTL_MAGIC, 2, ...)
 * PHANTOM_IOCTL_DESTROY_INSTANCE	_IOW(PHANTOM_IOCTL_MAGIC, 3, __u32)
 * PHANTOM_IOCTL_RUN_ITERATION		_IOWR(PHANTOM_IOCTL_MAGIC, 4, ...)
 * PHANTOM_IOCTL_GET_STATUS		_IOR(PHANTOM_IOCTL_MAGIC, 5, ...)
 */

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
