/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * libxml2_harness.ld — linker script for the Phantom libxml2 guest harness.
 *
 * Places the entry stub (libxml2_entry.o .text) at the very start of .text
 * so that the trampoline's "jmp 0x400000" lands in phantom_entry.
 * All other .text sections follow.
 */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(phantom_entry)

SECTIONS
{
    .text 0x400000 : {
        /* Entry stub first — guarantees phantom_entry is at 0x400000 */
        libxml2_entry.o(.text)
        /* All remaining text sections */
        *(.text .text.*)
    }
    .rodata : { *(.rodata .rodata.*) }
    .eh_frame : { *(.eh_frame) }
    .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) }
    .got : { *(.got) }
    .got.plt : { *(.got.plt) }
    .data : { *(.data .data.*) }
    .bss : { *(.bss .bss.*) *(COMMON) }

    /DISCARD/ : {
        *(.note*)
        *(.comment)
        *(.eh_frame_hdr)
        *(.dynamic)
        *(.interp)
    }
}
