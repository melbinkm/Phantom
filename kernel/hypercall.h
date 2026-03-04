// SPDX-License-Identifier: GPL-2.0-only
/*
 * hypercall.h — VMCALL hypercall dispatch for phantom.ko
 *
 * Guest code uses VMCALL with RAX = hypercall number.
 * The host exit handler reads RAX from the saved guest register file
 * and dispatches to the appropriate handler.
 *
 * Two hypercall namespaces are supported:
 *
 *   1. Legacy Phantom hypercalls (task 1.x era):
 *        0 = PHANTOM_HC_GET_HOST_DATA — host returns data GPA in RBX
 *        1 = PHANTOM_HC_SUBMIT_RESULT — guest RBX = result value
 *
 *   2. kAFL/Nyx ABI (task 2.1+):
 *        0x11a = HYPERCALL_KAFL_GET_PAYLOAD
 *        0x11b = HYPERCALL_KAFL_SUBMIT_CR3
 *        0x11c = HYPERCALL_KAFL_ACQUIRE
 *        0x11d = HYPERCALL_KAFL_RELEASE
 *        0x11e = HYPERCALL_KAFL_PANIC
 *        0x11f = HYPERCALL_KAFL_KASAN
 *        0x120 = HYPERCALL_KAFL_PRINTF
 *        0x121 = HYPERCALL_KAFL_SUBMIT_PANIC
 *
 * The dispatcher in phantom_handle_vmcall() routes to the nyx_api path
 * when RAX is in the range 0x11a–0x121; otherwise it uses the legacy path.
 */
#ifndef PHANTOM_HYPERCALL_H
#define PHANTOM_HYPERCALL_H

#include <linux/types.h>

/* ------------------------------------------------------------------
 * Legacy Phantom hypercall numbers (task 1.x)
 * ------------------------------------------------------------------ */
#define PHANTOM_HC_GET_HOST_DATA	0   /* returns data GPA in guest RBX */
#define PHANTOM_HC_SUBMIT_RESULT	1   /* guest RBX = result value       */

/* ------------------------------------------------------------------
 * kAFL/Nyx ABI hypercall numbers (task 2.1+)
 * ------------------------------------------------------------------ */
#define HYPERCALL_KAFL_GET_PAYLOAD	0x11a
#define HYPERCALL_KAFL_SUBMIT_CR3	0x11b
#define HYPERCALL_KAFL_ACQUIRE		0x11c
#define HYPERCALL_KAFL_RELEASE		0x11d
#define HYPERCALL_KAFL_PANIC		0x11e
#define HYPERCALL_KAFL_KASAN		0x11f
#define HYPERCALL_KAFL_PRINTF		0x120
#define HYPERCALL_KAFL_SUBMIT_PANIC	0x121

/* Range check for nyx_api hypercalls */
#define HYPERCALL_KAFL_FIRST		HYPERCALL_KAFL_GET_PAYLOAD
#define HYPERCALL_KAFL_LAST		HYPERCALL_KAFL_SUBMIT_PANIC

/* Maximum length for PRINTF guest string read */
#define PHANTOM_PRINTF_MAX_LEN		256U

/* Forward declaration */
struct phantom_vmx_cpu_state;

/* ------------------------------------------------------------------
 * EPT guest memory access helpers
 *
 * These walk the 4-level EPT to find the HPA for a given GPA, then
 * perform the required memory operation using the kernel VA obtained
 * via phys_to_virt(hpa).
 *
 * Hot-path safe: no allocation, no sleeping.
 * ------------------------------------------------------------------ */

/**
 * phantom_gpa_to_kva - Walk EPT to find host kernel VA for a GPA.
 * @state: Per-CPU VMX state.
 * @gpa:   Guest physical address to translate.
 *
 * Returns a kernel virtual address on success, NULL if the GPA is
 * not covered by the EPT (absent / not RAM).
 */
void *phantom_gpa_to_kva(struct phantom_vmx_cpu_state *state, u64 gpa);

/**
 * phantom_copy_from_guest - Copy len bytes from guest physical memory.
 * @state: Per-CPU VMX state.
 * @gpa:   Guest physical address of source (start of region).
 * @dst:   Host kernel buffer to copy into.
 * @len:   Number of bytes to copy.
 *
 * Walks the EPT to resolve each page that @gpa..@gpa+@len spans.
 * Copies page-by-page for multi-page spans.
 *
 * Returns 0 on success, -EFAULT if any page in the range is not backed
 * by RAM in the EPT.
 */
int phantom_copy_from_guest(struct phantom_vmx_cpu_state *state,
			    u64 gpa, void *dst, size_t len);

/**
 * phantom_copy_to_guest - Copy len bytes from kernel buffer to guest RAM.
 * @state: Per-CPU VMX state.
 * @gpa:   Guest physical address of destination.
 * @src:   Host kernel buffer to copy from.
 * @len:   Number of bytes to copy.
 *
 * Returns 0 on success, -EFAULT if any page in the range is not backed
 * by RAM in the EPT.
 */
int phantom_copy_to_guest(struct phantom_vmx_cpu_state *state,
			  u64 gpa, const void *src, size_t len);

/* ------------------------------------------------------------------
 * Hypercall dispatch
 * ------------------------------------------------------------------ */

/**
 * phantom_handle_vmcall - Dispatch a VMCALL exit.
 * @state: Per-CPU VMX state; guest_regs.rax = hypercall number.
 *
 * Called from the VM exit handler on exit reason VMX_EXIT_VMCALL (18).
 * Modifies state->guest_regs to return values to guest.
 * Advances guest RIP by the VMCALL instruction length (3 bytes) for
 * hypercalls that resume guest execution.
 *
 * For RELEASE/PANIC/KASAN: calls phantom_snapshot_restore() which sets
 * up the guest state for the next iteration.  The caller must check
 * state->run_result to determine whether to continue or terminate.
 *
 * Returns:
 *   0   — guest should continue (VMRESUME), or iteration ended normally
 *  -EINVAL — unknown hypercall; guest RIP NOT advanced (will re-fault)
 */
int phantom_handle_vmcall(struct phantom_vmx_cpu_state *state);

#endif /* PHANTOM_HYPERCALL_H */
