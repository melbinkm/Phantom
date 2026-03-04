/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * guest/libxml2_entry.S — Tiny assembly entry point for libxml2_harness.
 *
 * Placed first in the link order so it lands at the start of .text
 * (GPA 0x400000 when compiled with -Ttext=0x400000).  The trampoline
 * at GUEST_CODE_GPA (0x10000) jumps to 0x400000, which runs this stub,
 * which calls the C _start function.
 *
 * We cannot use _start directly in C as the first symbol at 0x400000
 * because the linker places cold-path libxml2 stubs before it.
 */

	.code64
	.section .text
	.org 0

	.global phantom_entry
phantom_entry:
	/* Forward to the C entry point */
	call	_start
	/* If _start somehow returns, loop on HLT */
.Lhlt:
	hlt
	jmp	.Lhlt
