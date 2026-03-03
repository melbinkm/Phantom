// SPDX-License-Identifier: GPL-2.0-only
/*
 * phantom.h — master header for phantom.ko
 *
 * Defines the top-level device context, module parameters, and the
 * result/error code namespaces used throughout the module.
 *
 * Sub-system headers (vmx_core.h, interface.h, debug.h) are included
 * here for convenience; individual .c files may also include them
 * directly to keep dependency graphs explicit.
 */
#ifndef PHANTOM_H
#define PHANTOM_H

#include <linux/cdev.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/types.h>

#include "compat.h"
#include "vmx_core.h"
#include "interface.h"
#include "debug.h"

/* ------------------------------------------------------------------
 * Module metadata
 * ------------------------------------------------------------------ */
#define PHANTOM_MODULE_NAME	"phantom"
#define PHANTOM_DEVICE_NAME	"phantom"
#define PHANTOM_CLASS_NAME	"phantom"

/* ------------------------------------------------------------------
 * Iteration result codes (non-negative — returned to userspace)
 *
 * PHANTOM_RESULT_OK        — iteration completed normally via RELEASE hypercall
 * PHANTOM_RESULT_CRASH     — guest fault / triple fault detected
 * PHANTOM_RESULT_TIMEOUT   — VMX preemption timer expired
 * PHANTOM_RESULT_KASAN     — guest KASAN violation
 * PHANTOM_RESULT_PANIC     — guest panic hypercall received
 * ------------------------------------------------------------------ */
#define PHANTOM_RESULT_OK		0
#define PHANTOM_RESULT_CRASH		1
#define PHANTOM_RESULT_TIMEOUT		2
#define PHANTOM_RESULT_KASAN		3
#define PHANTOM_RESULT_PANIC		4

/* ------------------------------------------------------------------
 * Error codes (negative — returned from ioctl or internal functions)
 *
 * Standard POSIX errno values are used where they map cleanly.
 * PHANTOM_ERROR_* codes distinguish phantom-specific failure modes.
 * ------------------------------------------------------------------ */
#define PHANTOM_ERROR_HARDWARE		(-EIO)
#define PHANTOM_ERROR_POOL_EXHAUSTED	(-ENOSPC)
#define PHANTOM_ERROR_DIRTY_OVERFLOW	(-EOVERFLOW)
#define PHANTOM_ERROR_NOT_INITIALIZED	(-ENXIO)

/* ------------------------------------------------------------------
 * Module parameters (declared in phantom_main.c, extern here)
 * ------------------------------------------------------------------ */

/**
 * phantom_cores — comma-separated list of physical CPUs to use.
 * Default: "0" (CPU 0 only, safe for development).
 * Example: "2,3,4,5" for a 4-core fuzzing configuration.
 */
extern char *phantom_cores;

/**
 * phantom_max_memory_mb — maximum aggregate guest memory in MB.
 * Default: 512.  Prevents OOM on over-provisioned multi-instance runs.
 */
extern int phantom_max_memory_mb;

/* ------------------------------------------------------------------
 * Top-level device context
 *
 * One global instance per module load.  All per-CPU state is in
 * phantom_vmx_state (DEFINE_PER_CPU in vmx_core.c).
 * ------------------------------------------------------------------ */
struct phantom_dev {
	struct cdev		 cdev;
	struct class		*class;
	dev_t			 devno;

	/* CPUs currently running in VMX-root */
	cpumask_var_t		 vmx_cpumask;
	int			 nr_vmx_cores;

	/* CPU feature snapshot taken at module init */
	struct phantom_cpu_features features;

	/* Set true only after all subsystems are up */
	bool			 initialized;
};

/* Single global device context, defined in phantom_main.c */
extern struct phantom_dev phantom_global_dev;

/* ------------------------------------------------------------------
 * Module init/cleanup helpers (called from phantom_main.c)
 * ------------------------------------------------------------------ */

/**
 * phantom_parse_cores_param - Parse "phantom_cores" string into cpumask.
 * @mask: Output cpumask; caller must have allocated it.
 *
 * Parses comma-separated CPU numbers.  Validates each CPU is online and
 * not the boot CPU (CPU 0 is allowed but logged as a warning in
 * production).
 *
 * Returns 0 on success, -EINVAL if the string is malformed, -ENODEV
 * if any specified CPU is offline.
 */
int phantom_parse_cores_param(cpumask_var_t mask);

/**
 * phantom_kvm_intel_check - Advisory check for kvm_intel conflict.
 *
 * Logs a pr_warn if kvm_intel appears to be in use (detected via
 * CR4.VMXE on any target core).  Does NOT block module load.
 * The definitive check is the VMXON attempt itself.
 */
void phantom_kvm_intel_check(const struct cpumask *cpumask);

#endif /* PHANTOM_H */
