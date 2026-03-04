// SPDX-License-Identifier: GPL-2.0-only
/*
 * hypercall.h — VMCALL hypercall dispatch for phantom.ko
 *
 * Guest code uses VMCALL with RAX = hypercall number.
 * The host exit handler reads RAX from the saved guest register file
 * and dispatches to the appropriate handler.
 *
 * For task 1.2 only two hypercalls are needed:
 *   0 = GET_HOST_DATA  — host returns data GPA in guest RBX
 *   1 = SUBMIT_RESULT  — guest RBX = checksum result
 */
#ifndef PHANTOM_HYPERCALL_H
#define PHANTOM_HYPERCALL_H

#include <linux/types.h>

/* Hypercall numbers */
#define PHANTOM_HC_GET_HOST_DATA	0   /* returns data GPA in guest RBX */
#define PHANTOM_HC_SUBMIT_RESULT	1   /* guest RBX = result value       */

/* Forward declaration */
struct phantom_vmx_cpu_state;

/**
 * phantom_handle_vmcall - Dispatch a VMCALL exit.
 * @state: Per-CPU VMX state; guest_regs.rax = hypercall number.
 *
 * Called from the VM exit handler on exit reason VMX_EXIT_VMCALL (18).
 * Modifies state->guest_regs to return values to guest.
 * Advances guest RIP by the VMCALL instruction length (3 bytes).
 *
 * Returns 0 to continue guest execution, negative errno to abort.
 */
int phantom_handle_vmcall(struct phantom_vmx_cpu_state *state);

#endif /* PHANTOM_HYPERCALL_H */
