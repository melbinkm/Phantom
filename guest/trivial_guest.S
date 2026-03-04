/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * trivial_guest.S — minimal 64-bit guest binary for phantom.ko task 1.2
 *
 * This flat binary is loaded into the guest code page at GPA 0x10000.
 * It runs in IA-32e (64-bit) mode with a minimal page-table identity
 * mapping set up by the host (GVA 0-2MB → GPA 0-2MB via 2MB large page).
 *
 * Protocol:
 *   1. VMCALL nr=0 (GET_HOST_DATA) — host returns data GPA in RBX
 *   2. Read 512 u64 values from the data buffer, XOR-fold into RDX
 *   3. VMCALL nr=1 (SUBMIT_RESULT) — RBX = checksum, host records it
 *   4. HLT loop (host stops guest on HLT exit)
 *
 * Build:
 *   as --64 -o trivial_guest.o trivial_guest.S
 *   ld -Ttext=0x0 --oformat=binary -o trivial_guest.bin trivial_guest.o
 *
 * The binary is assembled relative to address 0x0 and loaded by the
 * host at GPA 0x10000.  All branches are PC-relative so the load
 * address does not matter.
 */

	.code64
	.section .text
	.org 0

	.global _start
_start:
	/*
	 * Hypercall 0: GET_HOST_DATA
	 * Host returns the data buffer GPA in RBX.
	 */
	xor	%rax, %rax		/* RAX = 0 (GET_HOST_DATA) */
	vmcall				/* VM exit reason 18; host sets RBX */

	/*
	 * Compute checksum: XOR-fold 512 u64 values from data buffer.
	 * RBX = data_gpa (set by host in GET_HOST_DATA)
	 * RCX = loop counter (0..511)
	 * RDX = XOR accumulator
	 */
	xor	%rcx, %rcx		/* counter = 0 */
	xor	%rdx, %rdx		/* checksum = 0 */

.Lloop:
	mov	(%rbx, %rcx, 8), %rax	/* rax = data_buf[rcx] */
	xor	%rax, %rdx		/* checksum ^= rax */
	inc	%rcx
	cmp	$512, %rcx		/* 512 * 8 = 4096 = PAGE_SIZE */
	jl	.Lloop

	/*
	 * Hypercall 1: SUBMIT_RESULT
	 * Host reads RBX = checksum and stores it.
	 */
	mov	%rdx, %rbx		/* RBX = checksum */
	mov	$1, %rax		/* RAX = 1 (SUBMIT_RESULT) */
	vmcall

	/*
	 * HLT loop — host configured HLT exiting so this causes a
	 * VM exit.  The exit handler will terminate the run loop.
	 */
.Lhlt:
	hlt
	jmp	.Lhlt
