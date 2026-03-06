// SPDX-License-Identifier: GPL-2.0-only
/*
 * multicore.c — per-CPU Phantom instance management for Class B kernel fuzzing
 *
 * Responsibilities:
 *   - phantom_multicore_init():        allocate + start per-CPU vCPU instances
 *   - phantom_multicore_teardown():    stop vCPU threads, VMXOFF, free memory
 *   - phantom_multicore_start_fuzzing(): boot Class B guest on all cores
 *   - phantom_merge_coverage_to_global(): lock-free atomic OR bitmap merge
 *   - phantom_multicore_get_stats():   aggregate exec/sec across all cores
 *
 * NUMA note: The Intel i7-6700 is a single-socket CPU with a single NUMA
 * node (node 0).  All cpu_to_node() calls return 0 on this hardware, so
 * NUMA-local and NUMA-remote allocations are identical.  The alloc_pages_node()
 * calls are kept for correctness on multi-socket machines.
 *
 * EPT isolation: each per-CPU instance has its own independently allocated
 * class_b_ept_pml4/pdpt/pd, class_b_pt_pages[], and class_b_ram_pages[].
 * These are allocated by phantom_ept_alloc_class_b() which is called once
 * per CPU inside phantom_multicore_start_fuzzing().  No EPT pages are shared
 * between any two cores — verified by the fact that phantom_ept_alloc_class_b()
 * allocates fresh pages for each state pointer it receives.
 *
 * Hot-path rules (phantom_merge_coverage_to_global):
 *   - No printk, no kmalloc, no schedule(), no mutex.
 *   - Uses atomic64_or() for lock-free OR merge.
 *   - Called from HC_RELEASE handler every PHANTOM_MERGE_INTERVAL iterations.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>

#include "phantom.h"
#include "vmx_core.h"
#include "multicore.h"
#include "guest_boot.h"

/* ------------------------------------------------------------------
 * Global coverage bitmap — all per-core bitmaps are OR'd into this.
 *
 * Aligned to a cache line (64 bytes) to avoid false sharing between
 * the per-core atomic writers and the userspace reader via mmap.
 * Exported so interface.c can map it via PHANTOM_MMAP_BITMAP.
 * ------------------------------------------------------------------ */
u8 phantom_global_bitmap[PHANTOM_BITMAP_SIZE] __cacheline_aligned;
EXPORT_SYMBOL_GPL(phantom_global_bitmap);

/*
 * How often to merge local coverage into the global bitmap.
 * Every 1000 iterations: low overhead, fast convergence.
 */
#define PHANTOM_MERGE_INTERVAL		1000

/*
 * Per-CPU exec/sec measurement window: ~1 second worth of TSC ticks.
 * Updated lazily in phantom_multicore_get_stats() — not on the hot path.
 */
#define PHANTOM_TSC_WINDOW_CYCLES	(2400000000ULL)  /* ~1 s at 2.4 GHz */

/* ------------------------------------------------------------------
 * Module-level multicore state
 *
 * mc_cpumask:    CPUs initialised by phantom_multicore_init().
 * mc_active:     True after a successful phantom_multicore_init() call.
 * ------------------------------------------------------------------ */
static cpumask_t mc_cpumask;
static bool mc_active;

/* ------------------------------------------------------------------
 * phantom_multicore_init - Initialise per-CPU Phantom instances.
 *
 * For each CPU in @cpus:
 *   1. The backing phantom_vmx_cpu_state lives in the DEFINE_PER_CPU
 *      array (phantom_vmx_state in vmx_core.c).  phantom_vmxon_all()
 *      has already zeroed and partially initialised it (vmxon_region
 *      allocated, cpu/vmx_revision_id set).
 *   2. We call phantom_vmcs_setup() to allocate EPT + guest pages.
 *   3. We call phantom_vcpu_thread_start() to launch the kthread and
 *      wait for VMXON + VMCS load to complete on the target CPU.
 *
 * Rollback on failure: tear down all cores started so far in reverse.
 * ------------------------------------------------------------------ */
int phantom_multicore_init(const cpumask_t *cpus)
{
	struct phantom_vmx_cpu_state *state;
	int cpu, ret = 0;
	int started[PHANTOM_MAX_CORES];
	int n_started = 0;

	cpumask_clear(&mc_cpumask);

	for_each_cpu(cpu, cpus) {
		if (n_started >= PHANTOM_MAX_CORES) {
			pr_err("phantom: multicore_init: too many CPUs\n");
			ret = -EINVAL;
			goto fail;
		}

		state = per_cpu_ptr(&phantom_vmx_state, cpu);

		/* Allocate 64KB coverage bitmap (too large for percpu static embed). */
		state->coverage_bitmap = vzalloc_node(PHANTOM_BITMAP_SIZE,
						      cpu_to_node(cpu));
		if (!state->coverage_bitmap) {
			pr_err("phantom: CPU%d: coverage_bitmap alloc failed\n",
			       cpu);
			ret = -ENOMEM;
			goto fail;
		}
		state->iter_count        = 0;
		state->iter_tsc_window   = 0;
		state->iter_count_window = 0;

		/*
		 * Allocate VMCS backing pages, EPT, guest memory, MSR bitmap,
		 * CoW pool, xsave area.  GFP_KERNEL — process context required.
		 */
		ret = phantom_vmcs_setup(state);
		if (ret) {
			pr_err("phantom: CPU%d: vmcs_setup failed: %d\n",
			       cpu, ret);
			vfree(state->coverage_bitmap);
			state->coverage_bitmap = NULL;
			goto fail;
		}

		/*
		 * Start the vCPU kthread pinned to @cpu.  The thread performs
		 * VMXON + VMCS alloc + VMPTRLD on its own CPU (IPI-free), then
		 * signals vcpu_init_done.
		 */
		ret = phantom_vcpu_thread_start(state);
		if (ret) {
			pr_err("phantom: CPU%d: vcpu_thread_start failed: %d\n",
			       cpu, ret);
			phantom_vmcs_teardown(state);
			vfree(state->coverage_bitmap);
			state->coverage_bitmap = NULL;
			goto fail;
		}

		started[n_started++] = cpu;
		cpumask_set_cpu(cpu, &mc_cpumask);
	}

	/*
	 * Wait for every vCPU thread to complete per-CPU init (VMXON done).
	 * Waiting after all threads are started lets them run concurrently.
	 */
	for_each_cpu(cpu, cpus) {
		state = per_cpu_ptr(&phantom_vmx_state, cpu);
		ret = phantom_vcpu_thread_wait_init(state);
		if (ret) {
			pr_err("phantom: CPU%d: vcpu init failed: %d\n",
			       cpu, ret);
			goto fail;
		}
	}

	mc_active = true;
	pr_info("phantom: multicore_init: %d cores active\n",
		cpumask_weight(&mc_cpumask));
	return 0;

fail:
	/* Tear down cores that were started in reverse order */
	while (n_started > 0) {
		int fcpu = started[--n_started];

		state = per_cpu_ptr(&phantom_vmx_state, fcpu);
		phantom_vcpu_thread_stop(state);
		phantom_vmcs_teardown(state);
		vfree(state->coverage_bitmap);
		state->coverage_bitmap = NULL;
		cpumask_clear_cpu(fcpu, &mc_cpumask);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(phantom_multicore_init);

/* ------------------------------------------------------------------
 * phantom_multicore_teardown - Stop all per-CPU vCPU threads and free state.
 * ------------------------------------------------------------------ */
void phantom_multicore_teardown(void)
{
	struct phantom_vmx_cpu_state *state;
	int cpu;

	if (!mc_active)
		return;

	for_each_cpu(cpu, &mc_cpumask) {
		state = per_cpu_ptr(&phantom_vmx_state, cpu);
		phantom_vcpu_thread_stop(state);
		phantom_vmcs_teardown(state);
		vfree(state->coverage_bitmap);
		state->coverage_bitmap = NULL;
	}

	cpumask_clear(&mc_cpumask);
	mc_active = false;
	pr_info("phantom: multicore_teardown: all cores stopped\n");
}
EXPORT_SYMBOL_GPL(phantom_multicore_teardown);

/* ------------------------------------------------------------------
 * phantom_multicore_start_fuzzing - Boot Class B guest on all active cores.
 *
 * Each core gets its own independent EPT + RAM (phantom_ept_alloc_class_b
 * allocates fresh pages per call).  The bzImage is loaded into each
 * instance separately via phantom_load_kernel_image().
 *
 * The actual VMCS guest-state write (phantom_vmcs_setup_linux64) must
 * happen in VMX-root context on the target CPU; it is scheduled via the
 * vcpu_run_request mechanism (test_id = PHANTOM_TEST_BOOT_KERNEL).
 * ------------------------------------------------------------------ */
int phantom_multicore_start_fuzzing(const cpumask_t *cpus,
				    const u8 *bzimage, size_t size)
{
	struct phantom_vmx_cpu_state *state;
	int cpu, ret = 0;

	for_each_cpu(cpu, cpus) {
		if (!cpumask_test_cpu(cpu, &mc_cpumask)) {
			pr_err("phantom: CPU%d not in mc_cpumask\n", cpu);
			return -EINVAL;
		}

		state = per_cpu_ptr(&phantom_vmx_state, cpu);

		/*
		 * Allocate a fresh 256MB EPT for this core.
		 * EPT isolation: each core has its own class_b_ept_pml4,
		 * class_b_ept_pdpt, class_b_ept_pd, class_b_pt_pages[128],
		 * and class_b_ram_pages[65536].  No pages are shared.
		 */
		ret = phantom_ept_alloc_class_b(state);
		if (ret) {
			pr_err("phantom: CPU%d: ept_alloc_class_b failed: %d\n",
			       cpu, ret);
			return ret;
		}

		/*
		 * Parse bzImage, copy PM kernel into guest RAM, build GDT,
		 * guest page tables, boot_params, and command line.
		 */
		ret = phantom_load_kernel_image(state, bzimage, size);
		if (ret) {
			pr_err("phantom: CPU%d: load_kernel_image failed: %d\n",
			       cpu, ret);
			phantom_ept_free_class_b(state);
			return ret;
		}

		state->class_b = true;

		pr_info("phantom: CPU%d: Class B guest loaded, entry GPA=0x%llx\n",
			cpu, state->kernel_entry_gpa);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(phantom_multicore_start_fuzzing);

/* ------------------------------------------------------------------
 * phantom_merge_coverage_to_global - Lock-free OR merge of local bitmap.
 *
 * Hot-path: called from HC_RELEASE handler.  No allocation, no sleeping,
 * no printk.  Uses atomic64_or() so that concurrent merges from different
 * cores never lose bits.
 *
 * The local bitmap is cleared after the merge so the next iteration
 * starts accumulating from zero.
 * ------------------------------------------------------------------ */
void phantom_merge_coverage_to_global(struct phantom_vmx_cpu_state *state)
{
	u64 *local;

	if (!state->coverage_bitmap)
		return;
	local  = (u64 *)state->coverage_bitmap;
	u64 *global = (u64 *)phantom_global_bitmap;
	int i;

	BUILD_BUG_ON(PHANTOM_BITMAP_SIZE % sizeof(u64) != 0);

	for (i = 0; i < PHANTOM_BITMAP_SIZE / (int)sizeof(u64); i++) {
		if (local[i])
			atomic64_or(local[i], (atomic64_t *)&global[i]);
	}
	memset(state->coverage_bitmap, 0, PHANTOM_BITMAP_SIZE);
}
EXPORT_SYMBOL_GPL(phantom_merge_coverage_to_global);

/* ------------------------------------------------------------------
 * phantom_multicore_get_stats - Collect aggregate exec/sec statistics.
 *
 * Reads rdtsc-based iter counters for each active core and computes
 * exec/sec over a ~1-second window.  Not hot-path — called from ioctl.
 * ------------------------------------------------------------------ */
int phantom_multicore_get_stats(struct phantom_multicore_stats *stats)
{
	struct phantom_vmx_cpu_state *state;
	u64 now_tsc, delta_tsc, delta_iters, hz;
	int cpu;

	if (!mc_active)
		return -ENXIO;

	memset(stats, 0, sizeof(*stats));

	/*
	 * rdtsc_ordered() gives a serialised TSC read.
	 * tsc_khz is the host TSC frequency in kHz (set by the kernel).
	 * hz = tsc_khz * 1000 = TSC ticks per second.
	 */
	now_tsc = rdtsc_ordered();
	hz = (u64)tsc_khz * 1000;

	for_each_cpu(cpu, &mc_cpumask) {
		state = per_cpu_ptr(&phantom_vmx_state, cpu);

		stats->active_cores++;

		delta_tsc   = now_tsc - READ_ONCE(state->iter_tsc_window);
		delta_iters = READ_ONCE(state->iter_count) -
			      READ_ONCE(state->iter_count_window);

		if (delta_tsc > 0 && hz > 0) {
			/*
			 * exec/sec = delta_iters * hz / delta_tsc
			 * Use 64-bit arithmetic; no floating point in kernel.
			 */
			if (delta_iters > 0)
				stats->per_core_exec[cpu] =
					(delta_iters * hz) / delta_tsc;
		}

		stats->total_exec_per_sec += stats->per_core_exec[cpu];

		/* Advance measurement window */
		WRITE_ONCE(state->iter_tsc_window,   now_tsc);
		WRITE_ONCE(state->iter_count_window,
			   READ_ONCE(state->iter_count));
	}

	return 0;
}
EXPORT_SYMBOL_GPL(phantom_multicore_get_stats);
