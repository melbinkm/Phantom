/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * guest_code.S — Trivial guest executed inside the VMX non-root (guest) context.
 *
 * Execution flow:
 *   1. VMCALL — causes VM exit with reason 18; host logs and advances RIP.
 *   2. mov $0xdead000, %rax; mov (%rax), %rbx — access unmapped GPA 0xdead000,
 *      which is NOT mapped in the EPT.  This produces an EPT violation
 *      (exit reason 48); host handler logs GPA + qualification and aborts guest.
 *   3. hlt loop — unreachable in normal execution, present as safety net.
 *
 * The symbols guest_code_start and guest_code_end are referenced from
 * spike_ept.c to determine the physical address range to identity-map in the
 * EPT, and from spike_main.c to populate the guest RIP VMCS field.
 *
 * NOTE: This code runs in VMX non-root mode with the same privilege level and
 * paging state as the host kernel (CR0/CR3/CR4 copied from host).  The guest
 * is therefore running in 64-bit ring-0 with the host's page tables active —
 * virtual addresses resolve normally via the host CR3 + EPT two-level walk.
 * The VMCALL and the deliberate unmapped-GPA access are the only two events
 * the spike needs to observe.
 */

#include <linux/linkage.h>

	.section .text, "ax"

SYM_FUNC_START(guest_code_start)
	/*
	 * Step 1: VMCALL — exit reason 18.
	 * Host advances RIP by 3 bytes (the length of the VMCALL encoding)
	 * and resumes the guest, so execution continues at the next instruction.
	 */
	vmcall

	/*
	 * Step 2: access unmapped GPA 0xdead000.
	 * This virtual address is NOT mapped in the host page tables that the
	 * guest is using, so the EPT walk fails → EPT violation, exit reason 48.
	 * The host handler logs GPA=0xdead000 and sets should_exit=true.
	 */
	movq	$0xdead000, %rax
	movq	(%rax), %rbx         /* EPT violation — not reached further */

	/*
	 * Step 3: HLT safety loop — should never be reached in normal spike
	 * execution.  Present so the assembler does not fall off the end of
	 * the function.
	 */
.Lhlt_loop:
	hlt
	jmp	.Lhlt_loop
SYM_FUNC_END(guest_code_start)

/*
 * guest_code_end — label marking the byte after the last instruction.
 * Referenced from C as: extern char guest_code_end[];
 */
.global guest_code_end
guest_code_end:
