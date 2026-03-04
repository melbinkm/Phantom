// SPDX-License-Identifier: GPL-2.0-only
/*
 * memory.h — global memory accounting for phantom.ko
 *
 * Tracks total bytes allocated across all phantom instances.
 * Enforces the phantom_max_memory_mb module parameter limit.
 *
 * All functions are thread-safe (atomic64 operations).
 */
#ifndef PHANTOM_MEMORY_H
#define PHANTOM_MEMORY_H

#include <linux/types.h>

/**
 * phantom_memory_reserve - Reserve bytes and check the global limit.
 * @bytes: Number of bytes to reserve.
 *
 * Adds @bytes to the global counter.  If the resulting total exceeds
 * phantom_max_memory_mb * 1MB, the reservation is rejected and the
 * counter is not incremented.
 *
 * Returns 0 if reservation succeeded, -ENOMEM if limit exceeded.
 */
int phantom_memory_reserve(u64 bytes);

/**
 * phantom_memory_release - Release a previously reserved byte count.
 * @bytes: Number of bytes to release (must match a prior reserve call).
 */
void phantom_memory_release(u64 bytes);

/**
 * phantom_memory_allocated - Return current allocated byte count.
 */
u64 phantom_memory_allocated(void);

#endif /* PHANTOM_MEMORY_H */
