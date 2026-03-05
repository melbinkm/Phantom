// SPDX-License-Identifier: GPL-2.0-only
/*
 * guest_boot.c - Linux kernel image loading for Phantom Class B guests
 *
 * Implements:
 *   - phantom_parse_bzimage: validate header, extract PM blob location
 *   - phantom_ept_alloc_class_b: 256MB EPT with 4KB granularity
 *   - phantom_ept_free_class_b: reverse teardown, NULL-safe
 *   - phantom_load_kernel_image: copy kernel, build GDT + guest PTs +
 *     boot_params + cmdline per Linux x86 boot protocol
 *   - phantom_vmcs_setup_linux64: write VMCS guest state for direct
 *     64-bit kernel entry
 *
 * Class B guests boot a real Linux kernel.  We skip the 16-bit setup
 * stub entirely and enter the protected-mode kernel directly in 64-bit
 * long mode, with RSI pointing to a synthesised boot_params structure.
 *
 * EPT note: phantom_ept_alloc_class_b() allocates its own separate set
 * of EPT pages for the 256MB Class B RAM.  It stores them in a new
 * array class_b_pt_pages[128] and class_b_ram_pages[65536] that the
 * wiring agent must add to struct phantom_vmx_cpu_state.  Until those
 * fields exist, the function documents where they would live.
 *
 * Hot-path note: phantom_vmcs_setup_linux64() is NOT hot-path — it runs
 * once at boot setup time from the vCPU thread, not from the exit handler.
 * Use of rdmsrl() is therefore permitted here.
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/cpu.h>
#include <linux/numa.h>
#include <linux/topology.h>
#include <linux/slab.h>
#include <asm/page.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>
#include <linux/vmalloc.h>

#include "vmx_core.h"
#include "ept.h"
#include "hypercall.h"
#include "guest_boot.h"

/* ------------------------------------------------------------------
 * Internal constants
 * ------------------------------------------------------------------ */

/* bzImage setup header magic "HdrS" at offset 0x202 */
#define BZIMAGE_MAGIC		0x53726448U

/* Offsets within the bzImage setup header (relative to byte 0 of file) */
#define BZIMAGE_OFF_SETUP_SECTS	0x1F1	/* u8:  number of setup sectors */
#define BZIMAGE_OFF_MAGIC	0x202	/* u32: "HdrS" */
#define BZIMAGE_OFF_CODE32_START 0x214	/* u32: protected-mode code start */
#define BZIMAGE_OFF_PREF_ADDR	0x258	/* u64: preferred load address */
#define BZIMAGE_OFF_INIT_SIZE	0x260	/* u32: init_size (kernel init area) */

/* boot_params offsets (struct boot_params, include/uapi/asm/bootparam.h).
 * setup_header hdr is at offset 0x1F1 within boot_params, and maps
 * 1:1 to the bzImage setup header (bytes 0x1F1 onward in bzImage).
 */
#define BOOT_PARAMS_OFF_SETUP_HDR    0x1F1  /* start of setup_header in boot_params */
#define BOOT_PARAMS_OFF_SETUP_HDR_SZ 0x80  /* sizeof(setup_header) ~123 bytes; 0x80 covers all fields */
#define BOOT_PARAMS_OFF_CMDLINE_PTR  0x228  /* u32: GPA of cmdline (in setup_header) */
#define BOOT_PARAMS_OFF_E820_COUNT   0x1E8  /* u8:  number of E820 entries */
#define BOOT_PARAMS_OFF_E820_TABLE   0x2D0  /* array of e820_entry structs */

/* E820 entries we synthesise for Class B */
#define CLASS_B_E820_COUNT	4

/*
 * Guest page table entry flags (IA-32e paging, non-leaf and 2MB leaf).
 * Identity mapping: GVA = GPA for the whole 256MB range.
 */
#define GPTE_PRESENT	BIT_ULL(0)
#define GPTE_RW		BIT_ULL(1)
#define GPTE_PS		BIT_ULL(7)	/* large page in PDE */

/*
 * EPT leaf flags for Class B 4KB RAM pages.
 * R+W+X + WB memory type (bits [5:3] = 6).
 */
#define CLASS_B_EPT_LEAF	(EPT_PTE_READ | EPT_PTE_WRITE | \
				 EPT_PTE_EXEC | EPT_PTE_MEMTYPE_WB)

/* 256MB in bytes */
#define CLASS_B_RAM_BYTES	((u64)PHANTOM_CLASS_B_RAM_MB << 20)

/* ------------------------------------------------------------------
 * phantom_parse_bzimage - Parse bzImage header, extract PM kernel info
 * ------------------------------------------------------------------ */

/**
 * phantom_parse_bzimage - Parse a bzImage and fill phantom_bzimage_info.
 * @data:  Host kernel pointer to the bzImage bytes.
 * @size:  Total size of the bzImage in bytes.
 * @info:  Output structure to fill.
 *
 * The bzImage layout (Linux boot protocol §4.1):
 *   [0x000 – setup_sects×512+511] : real-mode setup stub
 *   [pm_offset – end]             : protected-mode kernel (vmlinux.bin)
 *
 * We skip the real-mode stub and directly load the PM blob.
 *
 * Returns 0 on success, -EINVAL for bad magic, -ERANGE if image too small.
 */
int phantom_parse_bzimage(const void *data, size_t size,
			  struct phantom_bzimage_info *info)
{
	const u8 *hdr = (const u8 *)data;
	u32 magic;
	u8  setup_sects;
	u32 pm_offset;

	if (size < 1024)
		return -EINVAL;

	/* Validate "HdrS" magic at offset 0x202 */
	memcpy(&magic, hdr + BZIMAGE_OFF_MAGIC, sizeof(magic));
	if (magic != BZIMAGE_MAGIC)
		return -EINVAL;

	/* setup_sects: if 0, the default is 4 (Linux boot protocol §4.2) */
	setup_sects = hdr[BZIMAGE_OFF_SETUP_SECTS];
	if (setup_sects == 0)
		setup_sects = 4;

	/* PM kernel starts immediately after the setup sectors */
	pm_offset = ((u32)setup_sects + 1) * 512;
	if (pm_offset >= (u32)size)
		return -ERANGE;

	info->setup_sects = setup_sects;
	info->pm_offset   = pm_offset;
	info->pm_size     = (u32)(size - pm_offset);

	memcpy(&info->code32_start,
	       hdr + BZIMAGE_OFF_CODE32_START,
	       sizeof(info->code32_start));

	memcpy(&info->pref_address,
	       hdr + BZIMAGE_OFF_PREF_ADDR,
	       sizeof(info->pref_address));

	/*
	 * Clamp pref_address: if the kernel has no preference or prefers
	 * an address too low, use our default 16MB load GPA.
	 */
	if (info->pref_address == 0 ||
	    info->pref_address < PHANTOM_KERNEL_LOAD_GPA)
		info->pref_address = PHANTOM_KERNEL_LOAD_GPA;

	/* init_size: kernel init area size (needed by startup_64 for relocation) */
	memcpy(&info->init_size, hdr + BZIMAGE_OFF_INIT_SIZE, sizeof(info->init_size));

	return 0;
}
EXPORT_SYMBOL_GPL(phantom_parse_bzimage);

/* ------------------------------------------------------------------
 * Class B EPT page storage
 *
 * The 256MB Class B EPT uses arrays of struct page pointers that are
 * too large to embed statically in phantom_vmx_cpu_state:
 *
 *   class_b_pt_pages[128]:   128 EPT PT pages (4KB granularity)
 *   class_b_ram_pages[65536]: 65536 individual 4KB backing RAM pages
 *
 * These arrays are heap-allocated (kvmalloc_array) by
 * phantom_ept_alloc_class_b() and stored in state->class_b_pt_pages
 * and state->class_b_ram_pages respectively.
 *
 * The wiring agent (task 4) must add the following fields to
 * struct phantom_vmx_cpu_state in vmx_core.h:
 *
 *   struct page  *class_b_ept_pml4;
 *   struct page  *class_b_ept_pdpt;
 *   struct page  *class_b_ept_pd;
 *   struct page **class_b_pt_pages;   // kvmalloc_array(128)
 *   struct page **class_b_ram_pages;  // kvmalloc_array(65536)
 *
 * Until those fields are wired, phantom_ept_alloc_class_b() and
 * phantom_ept_free_class_b() access them via the names above, and will
 * fail to compile until the struct is updated.
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------
 * phantom_ept_alloc_class_b - Allocate 256MB EPT for Class B guest
 * ------------------------------------------------------------------ */

/**
 * phantom_ept_alloc_class_b - Allocate and build a 256MB Class B EPT.
 * @state: Per-CPU VMX state.
 *
 * Allocation order (for correct goto-cleanup on failure):
 *   1. EPT PML4 (1 page, zeroed)
 *   2. EPT PDPT (1 page, zeroed)
 *   3. EPT PD   (1 page, zeroed)
 *   4. PT pointer array (kvmalloc_array, 128 entries)
 *   5. 128 EPT PT pages (each 1 page, zeroed)
 *   6. RAM pointer array (kvmalloc_array, 65536 entries)
 *   7. 65536 backing RAM pages (each 1 page, zeroed)
 *
 * Builds EPT entries after all allocations succeed:
 *   PML4[0] = phys(PDPT) | EPT_PERM_RWX
 *   PDPT[0] = phys(PD)   | EPT_PERM_RWX
 *   PD[i]   = phys(PT[i])| EPT_PERM_RWX    for i=0..127
 *   PT[i][j]= phys(ram[i*512+j]) | CLASS_B_EPT_LEAF  for j=0..511
 *
 * Stores the computed EPTP in state->ept.eptp.
 *
 * Returns 0 on success, -ENOMEM on failure.
 */
int phantom_ept_alloc_class_b(struct phantom_vmx_cpu_state *state)
{
	int node = cpu_to_node(state->cpu);
	int i, j, ret;
	u64 *pml4_va, *pdpt_va, *pd_va, *pt_va;
	unsigned int ram_idx;

	/* 1. EPT PML4 */
	state->class_b_ept_pml4 = alloc_pages_node(node,
					GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->class_b_ept_pml4) {
		ret = -ENOMEM;
		goto err_pml4;
	}

	/* 2. EPT PDPT */
	state->class_b_ept_pdpt = alloc_pages_node(node,
					GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->class_b_ept_pdpt) {
		ret = -ENOMEM;
		goto err_pdpt;
	}

	/* 3. EPT PD */
	state->class_b_ept_pd = alloc_pages_node(node,
					GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->class_b_ept_pd) {
		ret = -ENOMEM;
		goto err_pd;
	}

	/* 4. PT pointer array */
	state->class_b_pt_pages = kvmalloc_array(
			PHANTOM_CLASS_B_NR_PT_PAGES,
			sizeof(struct page *),
			GFP_KERNEL | __GFP_ZERO);
	if (!state->class_b_pt_pages) {
		ret = -ENOMEM;
		goto err_pt_array;
	}

	/* 5. 128 EPT PT pages */
	for (i = 0; i < PHANTOM_CLASS_B_NR_PT_PAGES; i++) {
		state->class_b_pt_pages[i] =
			alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
		if (!state->class_b_pt_pages[i]) {
			ret = -ENOMEM;
			goto err_pt_pages;
		}
	}

	/* 6. RAM pointer array */
	state->class_b_ram_pages = kvmalloc_array(
			PHANTOM_CLASS_B_RAM_PAGES,
			sizeof(struct page *),
			GFP_KERNEL | __GFP_ZERO);
	if (!state->class_b_ram_pages) {
		ret = -ENOMEM;
		goto err_ram_array;
	}

	/* 7. 65536 backing RAM pages */
	for (i = 0; i < PHANTOM_CLASS_B_RAM_PAGES; i++) {
		state->class_b_ram_pages[i] =
			alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
		if (!state->class_b_ram_pages[i]) {
			ret = -ENOMEM;
			goto err_ram_pages;
		}
	}

	/*
	 * vmap all 65536 RAM pages as a contiguous PAGE_KERNEL window.
	 * This bypasses any read-only direct-map PTEs that STRICT_MODULE_RWX
	 * may have left on recycled module pages, giving us a guaranteed
	 * writable mapping that class_b_gpa_to_kva() uses for all writes.
	 */
	state->class_b_vmap_base = vmap(state->class_b_ram_pages,
					PHANTOM_CLASS_B_RAM_PAGES,
					VM_MAP, PAGE_KERNEL);
	if (!state->class_b_vmap_base) {
		ret = -ENOMEM;
		i = PHANTOM_CLASS_B_RAM_PAGES;
		goto err_ram_pages;
	}

	/* ----------------------------------------------------------
	 * Build EPT entries now that all allocations succeeded.
	 * ---------------------------------------------------------- */
	pml4_va = (u64 *)page_address(state->class_b_ept_pml4);
	pdpt_va = (u64 *)page_address(state->class_b_ept_pdpt);
	pd_va   = (u64 *)page_address(state->class_b_ept_pd);

	/* PML4[0] → PDPT (non-leaf: RWX required) */
	pml4_va[0] = page_to_phys(state->class_b_ept_pdpt) | EPT_PERM_RWX;

	/* PDPT[0] → PD (non-leaf: RWX required) */
	pdpt_va[0] = page_to_phys(state->class_b_ept_pd) | EPT_PERM_RWX;

	/* PD[0..127] → PT[i] (non-leaf: RWX required) */
	for (i = 0; i < PHANTOM_CLASS_B_NR_PT_PAGES; i++)
		pd_va[i] = page_to_phys(state->class_b_pt_pages[i]) |
			   EPT_PERM_RWX;

	/* PT[i][j] → ram_pages[i*512+j] (4KB leaf: R+W+X+WB) */
	for (i = 0; i < PHANTOM_CLASS_B_NR_PT_PAGES; i++) {
		pt_va = (u64 *)page_address(state->class_b_pt_pages[i]);
		for (j = 0; j < 512; j++) {
			ram_idx = (unsigned int)i * 512 + (unsigned int)j;
			if (ram_idx >= PHANTOM_CLASS_B_RAM_PAGES)
				break;
			pt_va[j] = page_to_phys(
					state->class_b_ram_pages[ram_idx]) |
				   CLASS_B_EPT_LEAF;
		}
	}

	/* EPTP: PML4 phys | WB | 4-level walk (no A/D bits) */
	state->ept.eptp = page_to_phys(state->class_b_ept_pml4) |
			  EPTP_MEMTYPE_WB | EPTP_PAGEWALK_4;

	/* ----------------------------------------------------------
	 * Map the Local APIC MMIO page at GPA 0xFEE00000.
	 *
	 * 0xFEE00000 is at:
	 *   PML4[0] → PDPT[3] → PD[0x1F7=503] → PT[0x1EE=494]
	 *
	 * The 256MB RAM EPT only wires PDPT[0].  We add a separate
	 * PDPT[3] subtree with a single PT entry for the LAPIC page.
	 * Using UC memory type (bits[5:3]=0) for MMIO correctness.
	 * ---------------------------------------------------------- */
	state->class_b_lapic_page = alloc_pages_node(node,
					    GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->class_b_lapic_page) {
		ret = -ENOMEM;
		goto err_lapic_page;
	}

	state->class_b_lapic_pd = alloc_pages_node(node,
					    GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->class_b_lapic_pd) {
		ret = -ENOMEM;
		goto err_lapic_pd;
	}

	state->class_b_lapic_pt = alloc_pages_node(node,
					    GFP_KERNEL | __GFP_ZERO, 0);
	if (!state->class_b_lapic_pt) {
		ret = -ENOMEM;
		goto err_lapic_pt;
	}

	{
		u64 *lapic_pd_va, *lapic_pt_va;
		/* PD index for 0xFEE00000: (0xFEE00000 >> 21) & 0x1FF = 503 */
		/* PT index for 0xFEE00000: (0xFEE00000 >> 12) & 0x1FF = 494 */
		#define LAPIC_GPA_PDPT_IDX  3U
		#define LAPIC_GPA_PD_IDX  503U
		#define LAPIC_GPA_PT_IDX  0U

		lapic_pd_va = (u64 *)page_address(state->class_b_lapic_pd);
		lapic_pt_va = (u64 *)page_address(state->class_b_lapic_pt);

		/* PDPT[3] → LAPIC PD */
		pdpt_va[LAPIC_GPA_PDPT_IDX] =
			page_to_phys(state->class_b_lapic_pd) | EPT_PERM_RWX;
		/* LAPIC PD[503] → LAPIC PT */
		lapic_pd_va[LAPIC_GPA_PD_IDX] =
			page_to_phys(state->class_b_lapic_pt) | EPT_PERM_RWX;
		/* LAPIC PT[494] → LAPIC page (UC, RW, no exec needed) */
		lapic_pt_va[LAPIC_GPA_PT_IDX] =
			page_to_phys(state->class_b_lapic_page) |
			EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_MEMTYPE_UC;
	}

	pr_info("phantom: Class B EPT ready: 256MB RAM + LAPIC @ 0xfee00000, EPTP=0x%llx\n",
		state->ept.eptp);
	return 0;

err_lapic_pt:
	__free_page(state->class_b_lapic_pd);
	state->class_b_lapic_pd = NULL;
err_lapic_pd:
	__free_page(state->class_b_lapic_page);
	state->class_b_lapic_page = NULL;
err_lapic_page:
	vunmap(state->class_b_vmap_base);
	state->class_b_vmap_base = NULL;
	i = PHANTOM_CLASS_B_RAM_PAGES;

err_ram_pages:
	for (i = i - 1; i >= 0; i--) {
		__free_page(state->class_b_ram_pages[i]);
		state->class_b_ram_pages[i] = NULL;
	}
	kvfree(state->class_b_ram_pages);
	state->class_b_ram_pages = NULL;
err_ram_array:
	i = PHANTOM_CLASS_B_NR_PT_PAGES;
err_pt_pages:
	for (i = i - 1; i >= 0; i--) {
		__free_page(state->class_b_pt_pages[i]);
		state->class_b_pt_pages[i] = NULL;
	}
	kvfree(state->class_b_pt_pages);
	state->class_b_pt_pages = NULL;
err_pt_array:
	__free_page(state->class_b_ept_pd);
	state->class_b_ept_pd = NULL;
err_pd:
	__free_page(state->class_b_ept_pdpt);
	state->class_b_ept_pdpt = NULL;
err_pdpt:
	__free_page(state->class_b_ept_pml4);
	state->class_b_ept_pml4 = NULL;
err_pml4:
	return ret;
}
EXPORT_SYMBOL_GPL(phantom_ept_alloc_class_b);

/* ------------------------------------------------------------------
 * phantom_ept_free_class_b - Free all Class B EPT + RAM pages
 * ------------------------------------------------------------------ */

/**
 * phantom_ept_free_class_b - Release all pages from phantom_ept_alloc_class_b.
 * @state: Per-CPU VMX state.
 *
 * Frees in reverse allocation order.  NULL-safe throughout.
 */
void phantom_ept_free_class_b(struct phantom_vmx_cpu_state *state)
{
	int i;

	/* Unmap the vmap window before freeing the backing pages */
	if (state->class_b_vmap_base) {
		vunmap(state->class_b_vmap_base);
		state->class_b_vmap_base = NULL;
	}

	/* Free 65536 backing RAM pages */
	if (state->class_b_ram_pages) {
		for (i = PHANTOM_CLASS_B_RAM_PAGES - 1; i >= 0; i--) {
			if (state->class_b_ram_pages[i]) {
				__free_page(state->class_b_ram_pages[i]);
				state->class_b_ram_pages[i] = NULL;
			}
		}
		kvfree(state->class_b_ram_pages);
		state->class_b_ram_pages = NULL;
	}

	/* Free 128 EPT PT pages */
	if (state->class_b_pt_pages) {
		for (i = PHANTOM_CLASS_B_NR_PT_PAGES - 1; i >= 0; i--) {
			if (state->class_b_pt_pages[i]) {
				__free_page(state->class_b_pt_pages[i]);
				state->class_b_pt_pages[i] = NULL;
			}
		}
		kvfree(state->class_b_pt_pages);
		state->class_b_pt_pages = NULL;
	}

	if (state->class_b_ept_pd) {
		__free_page(state->class_b_ept_pd);
		state->class_b_ept_pd = NULL;
	}

	if (state->class_b_ept_pdpt) {
		__free_page(state->class_b_ept_pdpt);
		state->class_b_ept_pdpt = NULL;
	}

	if (state->class_b_ept_pml4) {
		__free_page(state->class_b_ept_pml4);
		state->class_b_ept_pml4 = NULL;
	}

	/* Free LAPIC MMIO EPT pages */
	if (state->class_b_lapic_pt) {
		__free_page(state->class_b_lapic_pt);
		state->class_b_lapic_pt = NULL;
	}
	if (state->class_b_lapic_pd) {
		__free_page(state->class_b_lapic_pd);
		state->class_b_lapic_pd = NULL;
	}
	if (state->class_b_lapic_page) {
		__free_page(state->class_b_lapic_page);
		state->class_b_lapic_page = NULL;
	}

	state->ept.eptp = 0;
}
EXPORT_SYMBOL_GPL(phantom_ept_free_class_b);

/* ------------------------------------------------------------------
 * phantom_load_kernel_image - Load bzImage and build boot structures
 * ------------------------------------------------------------------ */

/*
 * GDT descriptor encoding helpers.
 *
 * Intel SDM Vol 3A §3.4.5: segment descriptor bit layout.
 * We build each 8-byte descriptor as a raw u64.
 *
 * gdt_make_code64: DPL=0, type=0xA (execute/read), S=1, P=1, L=1 (64-bit)
 *   Upper 32: G=1(31), L=1(21), P=1(15), DPL=00(14:13), S=1(12), type=1010(11:8)
 *   Lower 32: base+limit fields (all 0/FFFF for flat segment)
 *
 * gdt_make_data32: DPL=0, type=0x2 (read/write), S=1, P=1, D/B=1, G=1
 */

/* 64-bit code segment: L=1, P=1, S=1, type=0xA, G=1, base=0, limit=FFFFF */
#define GDT_DESC_CODE64		0x00AF9A000000FFFFULL

/* 32/64-bit data segment: D/B=1, P=1, S=1, type=0x2, G=1, base=0, limit=FFFFF */
#define GDT_DESC_DATA		0x00CF92000000FFFFULL

/*
 * build_tss_low - encode the low 8 bytes of a 64-bit TSS descriptor.
 * @base:  TSS base linear address.
 * @limit: TSS limit in bytes.
 *
 * 64-bit TSS descriptor low word (Intel SDM Vol 3A Table 3-2):
 *   [15: 0] limit[15:0]
 *   [31:16] base[15:0]
 *   [39:32] base[23:16]
 *   [43:40] type = 0x9 (64-bit TSS, available)
 *   [44]    S    = 0   (system descriptor)
 *   [46:45] DPL  = 0
 *   [47]    P    = 1   (present)
 *   [51:48] limit[19:16]
 *   [52]    AVL  = 0
 *   [53]    0    = 0
 *   [54]    0    = 0   (D/B must be 0 for 64-bit TSS)
 *   [55]    G    = 0   (byte granularity for TSS)
 *   [63:56] base[31:24]
 */
static u64 build_tss_low(u64 base, u32 limit)
{
	u64 d = 0;

	d |= (u64)(limit & 0xFFFF);		     /* [15:0] */
	d |= (u64)(base  & 0xFFFF)   << 16;	     /* [31:16] */
	d |= (u64)((base >> 16) & 0xFF) << 32;      /* [39:32] */
	d |= (u64)0x89ULL             << 40;	     /* type=9, P=1 */
	d |= (u64)((limit >> 16) & 0xF) << 48;      /* [51:48] */
	d |= (u64)((base >> 24) & 0xFF) << 56;      /* [63:56] */
	return d;
}

/*
 * build_tss_high - encode the high 8 bytes of a 64-bit TSS descriptor.
 * @base:  TSS base linear address (bits [63:32] go here).
 */
static u64 build_tss_high(u64 base)
{
	return (base >> 32) & 0x00000000FFFFFFFFULL;
}

/*
 * class_b_gpa_to_kva - translate a Class B GPA to host kernel VA.
 *
 * For Class B guests the EPT is built from class_b_ram_pages[].
 * We index directly: page_address(class_b_ram_pages[gpa >> PAGE_SHIFT])
 * plus the page offset.  This is faster than walking the EPT and avoids
 * depending on phantom_gpa_to_kva() which walks state->ept (Class A EPT).
 */
static void *class_b_gpa_to_kva(struct phantom_vmx_cpu_state *state, u64 gpa)
{
	unsigned int idx;
	u64 page_off;

	if (gpa >= CLASS_B_RAM_BYTES)
		return NULL;

	idx      = (unsigned int)(gpa >> PAGE_SHIFT);
	page_off = gpa & ~PAGE_MASK;

	if (idx >= PHANTOM_CLASS_B_RAM_PAGES)
		return NULL;
	if (!state->class_b_vmap_base)
		return NULL;
	if (!state->class_b_ram_pages || !state->class_b_ram_pages[idx])
		return NULL;

	return (u8 *)state->class_b_vmap_base + (u64)idx * PAGE_SIZE + page_off;
}

/**
 * phantom_load_kernel_image - Copy bzImage PM kernel + build boot structures.
 * @state:        Per-CPU VMX state (Class B EPT allocated).
 * @bzimage:      Host kernel pointer to bzImage bytes.
 * @bzimage_size: Total bzImage size in bytes.
 *
 * Returns 0 on success, negative errno on failure.
 */
int phantom_load_kernel_image(struct phantom_vmx_cpu_state *state,
			      const void *bzimage, size_t bzimage_size)
{
	struct phantom_bzimage_info info;
	u64 load_gpa;
	void *dst;
	u64 *gdt;
	u64 *pml4_va, *pdpt_va, *pd_va, *pt_va;
	u8  *boot_params;
	void *cl;
	struct phantom_e820_entry e820[CLASS_B_E820_COUNT];
	int i, j, ret;

	/* Step 1: Parse the bzImage header */
	ret = phantom_parse_bzimage(bzimage, bzimage_size, &info);
	if (ret)
		return ret;

	/* Step 2: Determine load GPA */
	if (info.pref_address < CLASS_B_RAM_BYTES)
		load_gpa = info.pref_address;
	else
		load_gpa = PHANTOM_KERNEL_LOAD_GPA;

	/* Validate: PM kernel must fit within 256MB RAM */
	if (load_gpa + info.pm_size > CLASS_B_RAM_BYTES) {
		pr_err("phantom: Class B kernel does not fit: "
		       "load_gpa=0x%llx pm_size=0x%x limit=0x%llx\n",
		       load_gpa, info.pm_size, CLASS_B_RAM_BYTES);
		return -EINVAL;
	}

	/* Step 3: Copy protected-mode kernel blob into guest RAM */
	dst = class_b_gpa_to_kva(state, load_gpa);
	if (!dst)
		return -EFAULT;
	memcpy(dst, (const u8 *)bzimage + info.pm_offset, info.pm_size);

	pr_info("phantom: kernel loaded: GPA=0x%llx size=0x%x\n",
		load_gpa, info.pm_size);

	/* ----------------------------------------------------------
	 * Step 4: Build GDT at PHANTOM_GDT_GPA
	 *
	 * 6 descriptors × 8 bytes = 48 bytes; GDTR.limit = 0x27.
	 *
	 * Index   Selector  Description
	 *   0       0x00    Null descriptor
	 *   1       0x08    64-bit code (CS) — DPL=0, L=1, P=1, G=1
	 *   2       0x10    Data (SS/DS/ES) — DPL=0, D/B=1, P=1, G=1
	 *   3       0x18    TSS low  (64-bit TSS descriptor, word 1)
	 *   4       0x20    TSS high (64-bit TSS descriptor, word 2)
	 *   5       0x28    (unused; TSS base is PHANTOM_GDT_GPA+0x28)
	 * ---------------------------------------------------------- */
	gdt = class_b_gpa_to_kva(state, PHANTOM_GDT_GPA);
	if (!gdt)
		return -EFAULT;

	memset(gdt, 0, PAGE_SIZE);

	gdt[0] = 0ULL;				/* null descriptor */
	gdt[1] = GDT_DESC_CODE64;		/* 0x08: CS 64-bit */
	gdt[2] = GDT_DESC_DATA;		/* 0x10: data SS/DS */
	gdt[3] = build_tss_low(PHANTOM_GDT_GPA + 0x28ULL, 0x67);
	gdt[4] = build_tss_high(PHANTOM_GDT_GPA + 0x28ULL);
	/* gdt[5] unused */

	/* ----------------------------------------------------------
	 * Step 5: Build guest page tables at PHANTOM_PML4_GPA
	 *
	 * Identity mapping: GVA = GPA for the full 256MB range.
	 * Uses 4KB pages so every page in the 256MB space is individually
	 * addressable.  This matches the EPT granularity.
	 *
	 * Structure:
	 *   PML4[0] → PDPT at PHANTOM_PDPT_GPA
	 *   PDPT[0] → PD   at PHANTOM_PD_GPA
	 *   PD[0..127] → PT[i] at PHANTOM_PT_BASE_GPA + i*4096
	 *   PT[i][j]: GVA = (i*512+j)*4096 → GPA same (identity)
	 *
	 * Guest PTE HPA = GPA because Class B uses an identity EPT
	 * Identity mapping: GVA = GPA for the full 256MB range.
	 *
	 * Two-stage translation:
	 *   - Guest PT entries map GVA → GPA (identity: GPA = GVA).
	 *   - EPT maps GPA → HPA (built by phantom_ept_alloc_class_b).
	 *
	 * Guest PT entries must contain GPAs (not HPAs).  The CPU hardware
	 * walks the guest PT during address translation to get the GPA, then
	 * VMX uses the EPT to translate GPA → HPA.
	 * ---------------------------------------------------------- */
	pml4_va = class_b_gpa_to_kva(state, PHANTOM_PML4_GPA);
	pdpt_va = class_b_gpa_to_kva(state, PHANTOM_PDPT_GPA);
	pd_va   = class_b_gpa_to_kva(state, PHANTOM_PD_GPA);
	if (!pml4_va || !pdpt_va || !pd_va)
		return -EFAULT;

	memset(pml4_va, 0, PAGE_SIZE);
	memset(pdpt_va, 0, PAGE_SIZE);
	memset(pd_va,   0, PAGE_SIZE);

	/*
	 * Guest PML4[0] → PDPT_GPA: GVA[0] maps via PDPT at PHANTOM_PDPT_GPA.
	 * These entries contain GPAs — the CPU hardware walks the guest PT
	 * to get the GPA, then VMX/EPT translates GPA → HPA.
	 * The EPT (built in phantom_ept_alloc_class_b) handles GPA → HPA.
	 */
	pml4_va[0] = PHANTOM_PDPT_GPA | GPTE_PRESENT | GPTE_RW;

	/* PDPT[0] → PD_GPA */
	pdpt_va[0] = PHANTOM_PD_GPA | GPTE_PRESENT | GPTE_RW;

	/* PD[0..127] → PT[i] at PT_BASE_GPA + i*PAGE_SIZE */
	for (i = 0; i < PHANTOM_CLASS_B_NR_PT_PAGES; i++) {
		u64 pt_gpa = PHANTOM_PT_BASE_GPA + (u64)i * PAGE_SIZE;

		pd_va[i] = pt_gpa | GPTE_PRESENT | GPTE_RW;

		pt_va = class_b_gpa_to_kva(state, pt_gpa);
		if (!pt_va)
			return -EFAULT;
		memset(pt_va, 0, PAGE_SIZE);

		for (j = 0; j < 512; j++) {
			unsigned int ram_idx = (unsigned int)i * 512 +
					       (unsigned int)j;
			u64 gpa = (u64)ram_idx * PAGE_SIZE;

			if (ram_idx >= PHANTOM_CLASS_B_RAM_PAGES)
				break;

			/* Identity map: GVA = GPA = ram_idx * PAGE_SIZE */
			pt_va[j] = gpa | GPTE_PRESENT | GPTE_RW;
		}
	}

	/* ----------------------------------------------------------
	 * Step 6: Fill boot_params at PHANTOM_BOOT_PARAMS_GPA
	 *
	 * We write individual fields by offset to avoid a dependency on
	 * the kernel's struct boot_params definition (which may vary).
	 * ---------------------------------------------------------- */
	boot_params = class_b_gpa_to_kva(state, PHANTOM_BOOT_PARAMS_GPA);
	if (!boot_params)
		return -EFAULT;

	memset(boot_params, 0, PAGE_SIZE);

	/*
	 * Copy the bzImage setup header (bytes 0x1F1..0x28F) into boot_params
	 * at the same offsets.  The setup_header struct in boot_params starts
	 * at offset 0x1F1 with an identical layout to the bzImage header.
	 * This copies all critical fields: kernel_alignment (0x230),
	 * pref_address (0x258), init_size (0x260), etc.
	 *
	 * startup_64 reads boot_params+0x230 (kernel_alignment) to align rbp.
	 * With kernel_alignment=0 the calc overflows -> triple fault at +0x5a.
	 */
	if (bzimage_size > BOOT_PARAMS_OFF_SETUP_HDR + BOOT_PARAMS_OFF_SETUP_HDR_SZ)
		memcpy(boot_params + BOOT_PARAMS_OFF_SETUP_HDR,
		       (const u8 *)bzimage + BOOT_PARAMS_OFF_SETUP_HDR,
		       BOOT_PARAMS_OFF_SETUP_HDR_SZ);

	/* Override cmd_line_ptr with our GPA (bzImage has 0 there) */
	*(__le32 *)(boot_params + BOOT_PARAMS_OFF_CMDLINE_PTR) =
		cpu_to_le32((u32)PHANTOM_CMDLINE_GPA);

	/* e820_entries */
	boot_params[BOOT_PARAMS_OFF_E820_COUNT] = CLASS_B_E820_COUNT;

	/* E820 table: four entries */
	e820[0].addr = 0x00000000ULL;
	e820[0].size = 0x0009F000ULL;		/* 636KB low RAM */
	e820[0].type = E820_TYPE_RAM;

	e820[1].addr = 0x00100000ULL;		/* 1MB */
	e820[1].size = 0x0EF00000ULL;		/* 239MB extended RAM */
	e820[1].type = E820_TYPE_RAM;

	e820[2].addr = 0xFEE00000ULL;		/* LAPIC */
	e820[2].size = 0x00001000ULL;
	e820[2].type = E820_TYPE_RESERVED;

	e820[3].addr = 0xFEC00000ULL;		/* IOAPIC */
	e820[3].size = 0x00001000ULL;
	e820[3].type = E820_TYPE_RESERVED;

	memcpy(boot_params + BOOT_PARAMS_OFF_E820_TABLE,
	       e820, sizeof(e820));

	/* ----------------------------------------------------------
	 * Step 7: Write command line at PHANTOM_CMDLINE_GPA
	 * ---------------------------------------------------------- */
	cl = class_b_gpa_to_kva(state, PHANTOM_CMDLINE_GPA);
	if (!cl)
		return -EFAULT;

	strncpy(cl,
		"earlyprintk=serial,0x3f8,115200 "
		"noapic noapictimer nokaslr "
		"nosmp lpj=4000000 panic=-1",
		255);
	((char *)cl)[255] = '\0';

	/* Step 8: Record kernel entry GPA for VMCS setup */
	state->kernel_entry_gpa = load_gpa;

	pr_info("phantom: Class B boot structs ready: "
		"entry=0x%llx boot_params=0x%llx\n",
		load_gpa, (u64)PHANTOM_BOOT_PARAMS_GPA);

	return 0;
}
EXPORT_SYMBOL_GPL(phantom_load_kernel_image);

/* ------------------------------------------------------------------
 * phantom_vmcs_setup_linux64 - Configure VMCS for 64-bit Linux entry
 *
 * MUST be called from the vCPU thread (VMX-root context, VMCS current).
 * ------------------------------------------------------------------ */

/**
 * phantom_vmcs_setup_linux64 - Write VMCS guest state for 64-bit Linux boot.
 * @state: Per-CPU VMX state.  kernel_entry_gpa must be valid.
 *
 * Configures all VMCS guest-state fields for direct 64-bit entry into
 * a Linux kernel.  Follows the Linux x86 boot protocol (64-bit entry):
 *   - RSI = boot_params GPA
 *   - CR3 = guest PML4 GPA
 *   - EFER: LME + LMA + SCE (Linux requires SCE for syscall)
 *   - Segments: flat 64-bit CS + SS; DS/ES/FS/GS unusable
 *   - TR: busy 64-bit TSS at PHANTOM_GDT_GPA+0x28
 *   - GDTR: base=PHANTOM_GDT_GPA, limit=0x27
 *   - IDTR: base=0, limit=0xFFF (IDT set up by kernel itself)
 *
 * Returns 0 on success, negative errno on failure.
 */
int phantom_vmcs_setup_linux64(struct phantom_vmx_cpu_state *state)
{
	u64 cr0_fixed0, cr0_fixed1;
	u64 cr4_fixed0, cr4_fixed1;
	u64 cr0, cr4;

	if (!state->kernel_entry_gpa)
		return -EINVAL;

	/* ---- CR0 ---- */
	rdmsrl(MSR_IA32_VMX_CR0_FIXED0, cr0_fixed0);
	rdmsrl(MSR_IA32_VMX_CR0_FIXED1, cr0_fixed1);

	cr0 = X86_CR0_PE | X86_CR0_PG | X86_CR0_NE |
	      X86_CR0_WP | X86_CR0_MP;
	cr0 = (cr0 | cr0_fixed0) & cr0_fixed1;
	phantom_vmcs_write64(VMCS_GUEST_CR0, cr0);

	/* ---- CR3: guest PML4 GPA ---- */
	phantom_vmcs_write64(VMCS_GUEST_CR3, PHANTOM_PML4_GPA);

	/* ---- CR4 ---- */
	rdmsrl(MSR_IA32_VMX_CR4_FIXED0, cr4_fixed0);
	rdmsrl(MSR_IA32_VMX_CR4_FIXED1, cr4_fixed1);

	cr4 = X86_CR4_PAE | X86_CR4_OSFXSR |
	      X86_CR4_OSXMMEXCPT | X86_CR4_OSXSAVE;
	cr4 = (cr4 | cr4_fixed0) & cr4_fixed1;
	phantom_vmcs_write64(VMCS_GUEST_CR4, cr4);

	/*
	 * CR4 guest/host mask: intercept writes to VMXE (bit 13).
	 *
	 * In VMX non-root mode the guest cannot clear VMXE without causing
	 * a #GP (which, with no IDT, double-faults → triple-faults).
	 * Setting CR4_MASK bit 13 causes any MOV to CR4 that touches VMXE
	 * to VM-exit (reason 28), letting phantom_handle_cr_access() force
	 * VMXE back on.
	 *
	 * CR4_READ_SHADOW presents the guest-visible CR4 without VMXE, so
	 * the guest's own CR4 reads (e.g. rdcr4 in asm) return the value
	 * it expects.
	 */
	phantom_vmcs_write64(VMCS_CTRL_CR4_MASK,        X86_CR4_VMXE);
	phantom_vmcs_write64(VMCS_CTRL_CR4_READ_SHADOW, cr4 & ~X86_CR4_VMXE);

	/* ---- EFER: LME + LMA + SCE (Linux needs syscall) ---- */
	phantom_vmcs_write64(VMCS_GUEST_IA32_EFER,
			     EFER_LME | EFER_LMA | EFER_SCE);

	/* ---- RIP, RSP, RSI, RFLAGS ---- */
	/* startup_64 is at +0x200 from the bzImage PM kernel load address */
	phantom_vmcs_write64(VMCS_GUEST_RIP,    state->kernel_entry_gpa + 0x200ULL);
	phantom_vmcs_write64(VMCS_GUEST_RSP,    PHANTOM_GUEST_STACK_TOP);
	/* RSI = boot_params GPA per Linux boot protocol */
	state->guest_regs.rsi = PHANTOM_BOOT_PARAMS_GPA;
	phantom_vmcs_write64(VMCS_GUEST_RFLAGS, 0x202ULL);

	/* ---- DR7, debug exceptions ---- */
	phantom_vmcs_write64(VMCS_GUEST_DR7, 0x400ULL);
	phantom_vmcs_write64(VMCS_GUEST_PENDING_DBG_EXC, 0ULL);

	/* ---- CS: 64-bit code, selector 0x08 ----
	 * AR = 0xA09B:
	 *   type=0xB (execute/read accessed), S=1, DPL=0, P=1, L=1, G=1
	 */
	phantom_vmcs_write16(VMCS_GUEST_CS_SELECTOR, 0x08);
	phantom_vmcs_write64(VMCS_GUEST_CS_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_CS_LIMIT,    0xFFFFFFFFU);
	phantom_vmcs_write32(VMCS_GUEST_CS_AR,       0xA09B);

	/* ---- SS: 32/64-bit data, selector 0x10 ----
	 * AR = 0xC093:
	 *   type=3 (read/write accessed), S=1, DPL=0, P=1, D/B=1, G=1
	 */
	phantom_vmcs_write16(VMCS_GUEST_SS_SELECTOR, 0x10);
	phantom_vmcs_write64(VMCS_GUEST_SS_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_SS_LIMIT,    0xFFFFFFFFU);
	phantom_vmcs_write32(VMCS_GUEST_SS_AR,       0xC093);

	/* ---- DS: same as SS ---- */
	phantom_vmcs_write16(VMCS_GUEST_DS_SELECTOR, 0x10);
	phantom_vmcs_write64(VMCS_GUEST_DS_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_DS_LIMIT,    0xFFFFFFFFU);
	phantom_vmcs_write32(VMCS_GUEST_DS_AR,       0xC093);

	/* ---- ES: same as SS ---- */
	phantom_vmcs_write16(VMCS_GUEST_ES_SELECTOR, 0x10);
	phantom_vmcs_write64(VMCS_GUEST_ES_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_ES_LIMIT,    0xFFFFFFFFU);
	phantom_vmcs_write32(VMCS_GUEST_ES_AR,       0xC093);

	/* ---- FS: unusable (bit 16 set) ---- */
	phantom_vmcs_write16(VMCS_GUEST_FS_SELECTOR, 0);
	phantom_vmcs_write64(VMCS_GUEST_FS_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_FS_LIMIT,    0xFFFF);
	phantom_vmcs_write32(VMCS_GUEST_FS_AR,       VMX_SEGMENT_AR_UNUSABLE);

	/* ---- GS: unusable ---- */
	phantom_vmcs_write16(VMCS_GUEST_GS_SELECTOR, 0);
	phantom_vmcs_write64(VMCS_GUEST_GS_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_GS_LIMIT,    0xFFFF);
	phantom_vmcs_write32(VMCS_GUEST_GS_AR,       VMX_SEGMENT_AR_UNUSABLE);

	/* ---- TR: busy 64-bit TSS, selector 0x18 ----
	 * AR = 0x008B: type=0xB (busy 64-bit TSS), P=1
	 * Base = PHANTOM_GDT_GPA + 0x28 (TSS body starts after GDT entries)
	 */
	phantom_vmcs_write16(VMCS_GUEST_TR_SELECTOR, 0x18);
	phantom_vmcs_write64(VMCS_GUEST_TR_BASE,
			     PHANTOM_GDT_GPA + 0x28ULL);
	phantom_vmcs_write32(VMCS_GUEST_TR_LIMIT,    0x67);
	phantom_vmcs_write32(VMCS_GUEST_TR_AR,       0x008B);

	/* ---- LDTR: unusable ---- */
	phantom_vmcs_write16(VMCS_GUEST_LDTR_SELECTOR, 0);
	phantom_vmcs_write64(VMCS_GUEST_LDTR_BASE,     0ULL);
	phantom_vmcs_write32(VMCS_GUEST_LDTR_LIMIT,    0);
	phantom_vmcs_write32(VMCS_GUEST_LDTR_AR,       VMX_SEGMENT_AR_UNUSABLE);

	/* ---- GDTR: our synthesised GDT ---- */
	phantom_vmcs_write64(VMCS_GUEST_GDTR_BASE,  PHANTOM_GDT_GPA);
	phantom_vmcs_write32(VMCS_GUEST_GDTR_LIMIT, 0x27); /* 5 descs × 8B - 1 */

	/* ---- IDTR: no IDT yet; the kernel will install one ---- */
	phantom_vmcs_write64(VMCS_GUEST_IDTR_BASE,  0ULL);
	phantom_vmcs_write32(VMCS_GUEST_IDTR_LIMIT, 0xFFF);

	/* ---- Interruptibility and activity state ---- */
	phantom_vmcs_write32(VMCS_GUEST_INTR_STATE,     0);
	phantom_vmcs_write32(VMCS_GUEST_ACTIVITY_STATE, 0);

	/* ---- SYSENTER MSRs ---- */
	phantom_vmcs_write32(VMCS_GUEST_IA32_SYSENTER_CS,  0);
	phantom_vmcs_write64(VMCS_GUEST_IA32_SYSENTER_ESP, 0ULL);
	phantom_vmcs_write64(VMCS_GUEST_IA32_SYSENTER_EIP, 0ULL);

	/* ---- Debug control ---- */
	phantom_vmcs_write64(VMCS_GUEST_IA32_DEBUGCTL, 0ULL);

	/* ---- PAT: standard reset value ---- */
	phantom_vmcs_write64(VMCS_GUEST_IA32_PAT,
			     0x0007040600070406ULL);

	pr_info("phantom: VMCS Class B guest state configured: "
		"RIP=0x%llx RSP=0x%llx CR3=0x%llx\n",
		state->kernel_entry_gpa + 0x200ULL,
		(u64)PHANTOM_GUEST_STACK_TOP,
		(u64)PHANTOM_PML4_GPA);

	return 0;
}
EXPORT_SYMBOL_GPL(phantom_vmcs_setup_linux64);
