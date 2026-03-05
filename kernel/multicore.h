// SPDX-License-Identifier: GPL-2.0-only
/*
 * multicore.h — per-CPU Phantom instance management for Class B fuzzing
 *
 * Public API for kernel/multicore.c.  Provides multi-core init/teardown,
 * lock-free global bitmap merging, and per-core exec/sec statistics.
 */
#ifndef PHANTOM_MULTICORE_H
#define PHANTOM_MULTICORE_H

#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/atomic.h>

/*
 * Maximum number of CPUs Phantom will ever fuzz on.
 * Matches nr_cpu_ids upper bound for the i7-6700 (8 logical CPUs).
 * CLAUDE.md constraint #8: never use all 8; max fuzzing cores = 7.
 */
#define PHANTOM_MAX_CORES		8

/*
 * Coverage bitmap size: 64KB, matching AFL++ edge bitmap convention.
 * Each byte encodes hit count for one edge (GPA → GPA transition bucket).
 */
#define PHANTOM_BITMAP_SIZE		(64 * 1024)

/*
 * struct phantom_multicore_stats — aggregate and per-core exec statistics.
 *
 * active_cores:       Number of currently running vCPU threads.
 * total_exec_per_sec: Sum of per-core exec/sec across all active cores.
 * per_core_exec:      Per-core exec/sec (0 for inactive cores).
 *
 * Retrieved via PHANTOM_IOCTL_GET_MULTICORE_STATS ioctl.
 */
struct phantom_multicore_stats {
	__u32 active_cores;
	__u32 _pad;
	__u64 total_exec_per_sec;
	__u64 per_core_exec[PHANTOM_MAX_CORES];
};

/* ------------------------------------------------------------------
 * ioctl — PHANTOM_IOCTL_GET_MULTICORE_STATS
 *
 * Number 24, _IOR, returns struct phantom_multicore_stats.
 * Compatible with interface.h magic byte 'P' (0x50).
 * ------------------------------------------------------------------ */
#define PHANTOM_IOCTL_GET_MULTICORE_STATS \
	_IOR('P', 24, struct phantom_multicore_stats)

/* ------------------------------------------------------------------
 * Public functions
 * ------------------------------------------------------------------ */

/**
 * phantom_multicore_init - Initialise per-CPU Phantom instances.
 * @cpus: Set of CPUs to initialise.
 *
 * For each CPU in @cpus:
 *   - Allocates struct phantom_vmx_cpu_state from the NUMA node of @cpu.
 *   - Calls phantom_vmcs_setup() then starts the vCPU kthread.
 *   - Waits for the vCPU thread to complete VMXON + VMCS load.
 *
 * Must be called from process context (GFP_KERNEL allocation).
 * Returns 0 on success, negative errno with full rollback on failure.
 */
int phantom_multicore_init(const cpumask_t *cpus);

/**
 * phantom_multicore_teardown - Stop all per-CPU vCPU threads and free state.
 *
 * Stops all vCPU threads, executes VMXOFF, and frees all per-instance
 * memory.  Safe to call even if phantom_multicore_init() partially failed.
 */
void phantom_multicore_teardown(void);

/**
 * phantom_multicore_start_fuzzing - Boot Class B guest on all active cores.
 * @cpus:    Set of CPUs to start fuzzing on (must be a subset of init cpus).
 * @bzimage: Kernel virtual address of the bzImage to load.
 * @size:    Size of the bzImage in bytes.
 *
 * Each core boots its own independent Class B guest instance.
 * Returns 0 if all cores booted successfully, first negative errno
 * encountered if any core fails.
 */
int phantom_multicore_start_fuzzing(const cpumask_t *cpus,
				    const u8 *bzimage, size_t size);

/**
 * phantom_merge_coverage_to_global - Merge local bitmap into global bitmap.
 * @state: Per-CPU state whose coverage_bitmap is to be merged.
 *
 * Performs a lock-free atomic OR of state->coverage_bitmap into
 * phantom_global_bitmap[], then clears state->coverage_bitmap.
 *
 * Hot-path safe: no allocation, no sleeping, no printk.
 * Called from the HC_RELEASE handler every PHANTOM_MERGE_INTERVAL iters.
 */
void phantom_merge_coverage_to_global(struct phantom_vmx_cpu_state *state);

/**
 * phantom_multicore_get_stats - Collect aggregate exec/sec statistics.
 * @stats: Output structure populated with per-core and total exec/sec.
 *
 * Reads per-CPU rdtsc-based iter counters and computes exec/sec.
 * Returns 0 on success, -ENXIO if multicore subsystem not initialised.
 */
int phantom_multicore_get_stats(struct phantom_multicore_stats *stats);

/**
 * phantom_global_bitmap - Shared 64KB AFL++ edge bitmap (all cores OR'd in).
 *
 * Exported so interface.c can mmap it via PHANTOM_MMAP_BITMAP.
 * Aligned to a cache line to prevent false sharing between the
 * per-core atomic writers and the userspace reader.
 */
extern u8 phantom_global_bitmap[PHANTOM_BITMAP_SIZE];

#endif /* PHANTOM_MULTICORE_H */
