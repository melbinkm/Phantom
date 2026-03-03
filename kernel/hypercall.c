// SPDX-License-Identifier: GPL-2.0-only
/*
 * hypercall.c — VMCALL hypercall dispatch for phantom.ko
 *
 * Handles the two hypercalls used by trivial_guest.S:
 *   PHANTOM_HC_GET_HOST_DATA  (0): return GUEST_DATA_GPA in guest RBX
 *   PHANTOM_HC_SUBMIT_RESULT  (1): read checksum from guest RBX,
 *                                  store in state->run_result_data
 *
 * Hot-path rules: no printk, no sleeping, no dynamic allocation.
 * trace_printk used inside PHANTOM_DEBUG guards only.
 */

#include <linux/types.h>
#include <linux/errno.h>

#include "vmx_core.h"
#include "hypercall.h"
#include "debug.h"

/**
 * phantom_handle_vmcall - Dispatch a VMCALL VM exit.
 * @state: Per-CPU VMX state; guest_regs.rax holds the hypercall number.
 *
 * Returns 0 on success (guest should continue or iteration is done),
 * -EINVAL on unknown hypercall number.
 */
int phantom_handle_vmcall(struct phantom_vmx_cpu_state *state)
{
	u64 nr = state->guest_regs.rax;
	u64 guest_rip;
	u32 instr_len;

	PHANTOM_TRACE_HYPERCALL(state->cpu, nr);

	switch (nr) {
	case PHANTOM_HC_GET_HOST_DATA:
		/*
		 * Tell the guest where its data buffer is.
		 * We return GUEST_DATA_GPA in guest RBX.
		 */
		state->guest_regs.rbx = GUEST_DATA_GPA;
		break;

	case PHANTOM_HC_SUBMIT_RESULT:
		/*
		 * Guest has computed a result and placed it in RBX.
		 * Save it and mark the run as complete.
		 */
		state->run_result_data = state->guest_regs.rbx;
		state->run_result = 0; /* PHANTOM_RESULT_OK */
		break;

	default:
		/*
		 * Unknown hypercall — treat as a guest error.
		 * Do not advance RIP; the guest will fault on re-entry
		 * and the exit handler will catch it.
		 */
		state->run_result = 1; /* PHANTOM_RESULT_CRASH */
		return -EINVAL;
	}

	/*
	 * Advance guest RIP past the VMCALL instruction.
	 * VMCALL is always 3 bytes (0F 01 C1).
	 * We read the exit instruction length from the VMCS to be safe.
	 */
	instr_len = phantom_vmcs_read32(VMCS_RO_EXIT_INSTR_LEN);
	if (instr_len == 0)
		instr_len = 3; /* fallback: VMCALL is always 3 bytes */

	guest_rip = phantom_vmcs_read64(VMCS_GUEST_RIP);
	phantom_vmcs_write64(VMCS_GUEST_RIP, guest_rip + instr_len);

	return 0;
}
