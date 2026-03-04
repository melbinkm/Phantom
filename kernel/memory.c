// SPDX-License-Identifier: GPL-2.0-only
/*
 * memory.c — global memory accounting for phantom.ko
 *
 * Tracks all page-level allocations across phantom instances.
 * Enforces the phantom_max_memory_mb module parameter limit so that
 * a misconfigured multi-instance run cannot OOM the host.
 *
 * Implementation: single atomic64_t counter.  Operations are O(1)
 * and contention-free at the scale of phantom's allocation rate
 * (pool init is slow-path; no accounting in the hot path).
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/atomic.h>

#include "memory.h"

/* Global allocation counter (bytes) */
static atomic64_t phantom_allocated_bytes = ATOMIC64_INIT(0);

/* Forward declaration — defined in phantom_main.c */
extern int phantom_max_memory_mb;

/**
 * phantom_memory_reserve - Reserve bytes, enforcing the global limit.
 * @bytes: Number of bytes to reserve.
 *
 * Returns 0 if the reservation fits within the configured limit,
 * -ENOMEM otherwise (counter not changed).
 */
int phantom_memory_reserve(u64 bytes)
{
	u64 limit = (u64)phantom_max_memory_mb * 1024 * 1024;
	u64 current_val;
	u64 new_val;

	/*
	 * Read-then-compare-and-add.  We use atomic64_add and then check;
	 * if it exceeded the limit we subtract back.  This is safe for the
	 * pool-init (slow) path where races are benign — the limit is
	 * approximate (soft cap), not a hard security boundary.
	 */
	atomic64_add((s64)bytes, &phantom_allocated_bytes);
	new_val = (u64)atomic64_read(&phantom_allocated_bytes);

	if (new_val > limit) {
		atomic64_sub((s64)bytes, &phantom_allocated_bytes);
		current_val = (u64)atomic64_read(&phantom_allocated_bytes);
		pr_err("phantom: memory limit exceeded: "
		       "current=%lluMB limit=%dMB request=%lluMB\n",
		       current_val >> 20,
		       phantom_max_memory_mb,
		       bytes >> 20);
		return -ENOMEM;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(phantom_memory_reserve);

/**
 * phantom_memory_release - Release a previously reserved byte count.
 * @bytes: Number of bytes to release.
 */
void phantom_memory_release(u64 bytes)
{
	atomic64_sub((s64)bytes, &phantom_allocated_bytes);
}
EXPORT_SYMBOL_GPL(phantom_memory_release);

/**
 * phantom_memory_allocated - Return current total allocated bytes.
 */
u64 phantom_memory_allocated(void)
{
	return (u64)atomic64_read(&phantom_allocated_bytes);
}
EXPORT_SYMBOL_GPL(phantom_memory_allocated);
