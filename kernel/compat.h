// SPDX-License-Identifier: GPL-2.0-only
/*
 * compat.h — kernel version compatibility shims for phantom.ko
 *
 * Supports Linux 6.8 through 6.14.  All version-specific differences
 * are isolated here so the rest of the module never calls version checks
 * inline.
 */
#ifndef PHANTOM_COMPAT_H
#define PHANTOM_COMPAT_H

#include <linux/version.h>
#include <linux/device.h>

/*
 * class_create() API change: prior to 6.4 it takes (owner, name);
 * from 6.4 onwards it takes only (name).
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
#define phantom_class_create(name)	class_create(THIS_MODULE, (name))
#else
#define phantom_class_create(name)	class_create(name)
#endif

/*
 * In 6.8 the __counted_by() attribute was stabilised for flex-array
 * members.  Provide a no-op fallback for older compilers that ship with
 * earlier kernels.
 */
#ifndef __counted_by
#define __counted_by(f)
#endif

/*
 * alloc_pages_node() has been present across the entire 6.x series;
 * no shim required.  Document for reference only.
 *
 * smp_call_function_single() likewise stable since 2.6.
 */

#endif /* PHANTOM_COMPAT_H */
