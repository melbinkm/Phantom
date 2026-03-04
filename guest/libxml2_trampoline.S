/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * guest/libxml2_trampoline.S — 4KB stub loaded at GUEST_CODE_GPA (0x10000).
 *
 * The Phantom VMCS sets guest RIP = GUEST_CODE_GPA = 0x10000.
 * The libxml2 binary is loaded at GPA 0x400000 (4MB mark), safely above
 * all reserved kernel-managed pages (PML4 at 0x13000, etc.).
 *
 * This stub fits in one 4KB page and simply performs an absolute jump to
 * the libxml2_harness _start entry point.
 *
 * Build: assembled as part of the libxml2_harness target in Makefile.
 */

	.code64
	.section .text
	.org 0

	.global _trampoline_start
_trampoline_start:
	/* Absolute jump to _start at 0x400000 (libxml2_harness load GPA) */
	movabs	$0x400000, %rax
	jmp	*%rax
