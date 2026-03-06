// SPDX-License-Identifier: GPL-2.0-only
/*
 * guest_boot.h - Linux kernel image loading for Phantom Class B guests
 *
 * Provides:
 *   - Class B guest memory layout constants (256MB RAM)
 *   - bzImage parsing (Linux boot protocol §4.1)
 *   - EPT allocation for 256MB flat RAM (Class B)
 *   - Kernel image copy + boot_params construction
 *   - VMCS guest state setup for 64-bit Linux boot
 *
 * Class B guests run a real Linux kernel image.  The host loads the
 * kernel, builds a minimal GDT + guest page tables, fills boot_params
 * per the Linux x86 boot protocol, and sets VMCS guest state so the
 * kernel starts executing directly at its entry point with RSI pointing
 * to the boot_params structure.
 *
 * IMPORTANT: phantom_vmcs_setup_linux64() MUST be called from the vCPU
 * thread (VMX-root context, VMCS current via VMPTRLD).  Do NOT call it
 * from the ioctl handler.  The caller in interface.c must schedule the
 * VMCS writes via the vCPU thread mechanism.
 */
#ifndef PHANTOM_GUEST_BOOT_H
#define PHANTOM_GUEST_BOOT_H

#include <linux/types.h>
#include "vmx_core.h"

/* ------------------------------------------------------------------
 * Class B guest memory layout (256MB flat RAM)
 *
 * GPA map:
 *   0x0000_0000 – 0x0FFF_FFFF  256MB guest RAM (EPT-backed)
 *   0xFEC0_0000                IOAPIC (absent from EPT → violation)
 *   0xFEE0_0000                LAPIC  (absent from EPT → violation)
 *
 * Fixed structures placed within the 256MB RAM window:
 *   0x6000  GDT  (6 descriptors × 8 bytes = 48 bytes; limit=0x27)
 *   0x7000  boot_params (struct boot_params, 4KB page)
 *   0x8000  kernel command line (128 bytes)
 *   0x70000 Guest PML4   (1 × 4KB page)
 *   0x71000 Guest PDPT   (1 × 4KB page)
 *   0x72000 Guest PD     (1 × 4KB page, 128 entries for 256MB)
 *   0x73000 Guest PT[0]  (first of 128 PT pages; [1..127] follow)
 *   0x80000 Guest stack top (RSP initial value)
 *   0x100_0000 Default kernel load address (16MB mark)
 * ------------------------------------------------------------------ */
#define PHANTOM_CLASS_B_RAM_MB		256
#define PHANTOM_CLASS_B_RAM_PAGES	65536	/* 256MB / 4KB */
#define PHANTOM_CLASS_B_NR_PT_PAGES	128	/* 128 × 512 × 4KB = 256MB */

#define PHANTOM_BOOT_PARAMS_GPA		0x7000ULL
#define PHANTOM_CMDLINE_GPA		0x8000ULL
#define PHANTOM_GDT_GPA			0x6000ULL

/* Guest page table GPAs (separate from EPT) */
#define PHANTOM_PML4_GPA		0x70000ULL
#define PHANTOM_PDPT_GPA		0x71000ULL
#define PHANTOM_PD_GPA			0x72000ULL
#define PHANTOM_PT_BASE_GPA		0x73000ULL	/* [1..127] follow */

#define PHANTOM_GUEST_STACK_TOP		0x80000ULL
#define PHANTOM_KERNEL_LOAD_GPA		0x1000000ULL	/* 16MB */

/* E820 memory type constants (Linux boot protocol) */
#define E820_TYPE_RAM			1
#define E820_TYPE_RESERVED		2

/* ------------------------------------------------------------------
 * struct phantom_e820_entry - E820 memory map entry.
 *
 * Laid out directly in boot_params at offset 0x2D0.
 * Must be __packed to match the Linux boot protocol layout exactly.
 * ------------------------------------------------------------------ */
struct phantom_e820_entry {
	__u64 addr;
	__u64 size;
	__u32 type;
} __packed;

/* ------------------------------------------------------------------
 * struct phantom_bzimage_info - Parsed bzImage metadata.
 *
 * Populated by phantom_parse_bzimage() from the setup header.
 * Used by phantom_load_kernel_image() to locate the protected-mode
 * kernel blob and determine the load address.
 * ------------------------------------------------------------------ */
struct phantom_bzimage_info {
	u32 setup_sects;	/* setup sectors (from hdr.setup_sects) */
	u64 pref_address;	/* preferred load address (from hdr.pref_address) */
	u32 code32_start;	/* 32-bit kernel entry (hdr.code32_start) */
	u32 pm_offset;		/* byte offset of PM kernel in bzImage */
	u32 pm_size;		/* byte size of PM kernel blob */
	u32 init_size;		/* kernel init area size (from hdr.init_size) */
};

/* ------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------ */

/**
 * phantom_parse_bzimage - Parse a bzImage file and extract load metadata.
 * @data:  Pointer to bzImage data in host kernel memory.
 * @size:  Size of the bzImage data in bytes.
 * @info:  Output: filled with parsed setup header fields.
 *
 * Validates the bzImage magic ("HdrS" at offset 0x202) and extracts
 * the fields needed to load the protected-mode kernel blob.
 *
 * Returns 0 on success, -EINVAL if the magic is wrong or the image
 * is too small, -ERANGE if pm_offset >= size.
 */
int phantom_parse_bzimage(const void *data, size_t size,
			  struct phantom_bzimage_info *info);

/**
 * phantom_ept_alloc_class_b - Allocate EPT + RAM pages for a 256MB guest.
 * @state: Per-CPU VMX state.
 *
 * Allocates:
 *   - 1 PML4, 1 PDPT, 1 PD (EPT structure pages)
 *   - 128 PT pages (EPT leaf level for 4KB granularity over 256MB)
 *   - 65536 backing RAM pages (PHANTOM_CLASS_B_RAM_PAGES)
 *
 * All pages are allocated with alloc_page(GFP_KERNEL | __GFP_ZERO).
 * On failure, all previously allocated pages are freed (goto-cleanup).
 *
 * Builds the EPT entries after allocation:
 *   PML4[0] = phys(PDPT) | RWX
 *   PDPT[0] = phys(PD)   | RWX
 *   PD[i]   = phys(PT[i])| RWX   for i=0..127
 *   PT[i][j]= phys(ram[i*512+j]) | R+W+X+WB   for j=0..511
 *
 * The EPT EPTP is stored in state->ept.eptp on success.
 *
 * MUST be called from process context (GFP_KERNEL allocation).
 * Returns 0 on success, -ENOMEM on failure.
 */
int phantom_ept_alloc_class_b(struct phantom_vmx_cpu_state *state);

/**
 * phantom_ept_free_class_b - Free all pages allocated by phantom_ept_alloc_class_b.
 * @state: Per-CPU VMX state.
 *
 * Frees in reverse allocation order.  NULL-safe (skips NULL pointers).
 * Called from phantom_vmcs_teardown() for Class B instances.
 */
void phantom_ept_free_class_b(struct phantom_vmx_cpu_state *state);

/**
 * phantom_load_kernel_image - Load a bzImage into guest RAM and build boot structures.
 * @state:       Per-CPU VMX state (EPT must be allocated via phantom_ept_alloc_class_b).
 * @bzimage:     Pointer to bzImage data in host kernel memory.
 * @bzimage_size: Size of the bzImage data in bytes.
 *
 * Performs the full Linux boot protocol setup:
 *   1. Parses bzImage header to locate the PM kernel blob.
 *   2. Copies the PM kernel to load_gpa (pref_address or 16MB default).
 *   3. Builds a minimal 6-entry GDT at PHANTOM_GDT_GPA.
 *   4. Builds 4-level guest page tables at PHANTOM_PML4_GPA.
 *   5. Fills boot_params at PHANTOM_BOOT_PARAMS_GPA with E820 map.
 *   6. Writes kernel command line at PHANTOM_CMDLINE_GPA.
 *   7. Sets state->kernel_entry_gpa = load_gpa.
 *
 * Returns 0 on success, negative errno on failure.
 */
int phantom_load_kernel_image(struct phantom_vmx_cpu_state *state,
			      const void *bzimage, size_t bzimage_size);

/**
 * phantom_vmcs_setup_linux64 - Configure VMCS guest state for 64-bit Linux boot.
 * @state: Per-CPU VMX state (kernel_entry_gpa must be set by phantom_load_kernel_image).
 *
 * Writes all guest-state VMCS fields required to start a 64-bit Linux
 * kernel directly (bypassing the 16-bit real-mode setup stub):
 *   - CR0, CR3, CR4, EFER in IA-32e mode
 *   - CS/SS/DS/ES/FS/GS/TR/LDTR segments
 *   - GDTR/IDTR
 *   - RIP = kernel_entry_gpa, RSP = PHANTOM_GUEST_STACK_TOP
 *   - RSI = PHANTOM_BOOT_PARAMS_GPA (Linux boot protocol)
 *   - RFLAGS = 0x202
 *
 * MUST be called from the vCPU thread (VMX-root context, current VMCS
 * active).  Do NOT call from the ioctl handler.
 *
 * Returns 0 on success, negative errno on failure.
 */
int phantom_vmcs_setup_linux64(struct phantom_vmx_cpu_state *state);

/**
 * phantom_ept_lookup_pte_class_b - Look up the 4KB EPT PTE for a Class B GPA.
 * @state: Per-CPU VMX state (Class B EPT allocated).
 * @gpa:   Guest physical address within the 256MB RAM window.
 *
 * Returns pointer to the leaf PTE, or NULL if the GPA is outside the
 * Class B PT page range or the PT page is not allocated.
 */
u64 *phantom_ept_lookup_pte_class_b(struct phantom_vmx_cpu_state *state,
				     u64 gpa);

/**
 * phantom_ept_mark_all_ro_class_b - Write-protect all Class B EPT RAM pages.
 * @state: Per-CPU VMX state (Class B EPT allocated).
 *
 * Walks all 128 PT pages × 512 entries and clears EPT_PTE_WRITE on every
 * present entry (those with EPT_PTE_READ set).  This is the snapshot point
 * for Class B: subsequent guest writes trigger CoW faults.
 */
void phantom_ept_mark_all_ro_class_b(struct phantom_vmx_cpu_state *state);

#endif /* PHANTOM_GUEST_BOOT_H */
