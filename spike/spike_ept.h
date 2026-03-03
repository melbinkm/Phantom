// SPDX-License-Identifier: GPL-2.0-only
/*
 * spike_ept.h — EPT structure and interface for the VMX feasibility spike.
 */

#ifndef SPIKE_EPT_H
#define SPIKE_EPT_H

#include <linux/types.h>
#include <linux/mm_types.h>

#include "spike_vmx.h"

/*
 * GPA at which the guest stack is mapped.
 * Chosen to be outside the kernel direct-map range so it falls in a
 * different PML4 slot from the code, exercising the EPT walk properly.
 * 16MB (0x1000000) is well below the kernel image, easily addressable.
 */
#define SPIKE_GUEST_STACK_GPA   0x1000000ULL

/* Size of the guest stack allocation (one page is enough for the spike). */
#define SPIKE_GUEST_STACK_SIZE  PAGE_SIZE

/*
 * struct spike_ept — holds all pages that make up the minimal EPT hierarchy.
 *
 * Initialise to zero before calling spike_ept_build().  spike_ept_destroy()
 * frees whichever pages are non-NULL, so partial initialisation is safe.
 */
struct spike_ept {
	/* Core EPT paging structure pages */
	struct page *pml4_page;         /* PML4 table (level 4) */
	struct page *pdpt_page;         /* PDPT table (level 3, code region) */
	struct page *pd_page;           /* PD   table (level 2, code region) */

	/* Guest stack mapping pages */
	struct page *stack_page;        /* Actual 4KB guest-stack page        */
	struct page *stack_pt_page;     /* EPT PT for the 4KB stack mapping   */
	struct page *stack_pdpt_page;   /* PDPT for stack region (may be NULL
					 * if same slot as code region)       */
	struct page *stack_pd_page;     /* PD   for stack region (may be NULL
					 * if same slot as code region)       */

	/* Cached addresses for VMCS setup */
	u64 eptp;        /* EPT Pointer — write into VMCS_EPT_POINTER          */
	u64 code_gpa;    /* GPA of guest_code_start — use as guest RIP         */
	u64 code_hpa;    /* HPA of guest_code_start (same as GPA, identity)    */
	u64 stack_gpa;   /* GPA of guest stack top (SPIKE_GUEST_STACK_GPA +
			  * SPIKE_GUEST_STACK_SIZE — grows downward)          */
	u64 stack_hpa;   /* HPA of stack page                                  */
};

/* Forward declaration — defined in spike_main.c / guest_code.S */
extern char guest_code_start[];
extern char guest_code_end[];

int  spike_ept_build(struct spike_ept *ept);
void spike_ept_destroy(struct spike_ept *ept);

#endif /* SPIKE_EPT_H */
