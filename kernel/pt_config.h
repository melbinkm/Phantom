// SPDX-License-Identifier: GPL-2.0-only
/*
 * pt_config.h — Intel Processor Trace (PT) configuration for phantom.ko
 *
 * Declares MSR constants, ToPA entry format, RTIT control bit definitions,
 * the per-instance PT state struct, and the PT lifecycle API.
 *
 * Key invariants (from Intel SDM Vol. 3C §36):
 *   - CYCEn = MTCEn = TSCEn = PTWEn = 0 — timing packets disabled for
 *     determinism.  Identical control flow produces byte-identical traces.
 *   - ToPA output base (IA32_RTIT_OUTPUT_BASE) is set once at init and
 *     never modified during fuzzing — only OUTPUT_MASK_PTRS is reset.
 *   - PT MSR writes must happen on the vCPU thread (pinned CPU).
 *   - VM-entry/exit controls preferred (PT-in-VMX); MSR load/store lists
 *     used as fallback if the CPU does not support PT-in-VMX.
 */
#ifndef PHANTOM_PT_CONFIG_H
#define PHANTOM_PT_CONFIG_H

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/eventfd.h>

/* ------------------------------------------------------------------
 * Intel PT MSR addresses (IA32_RTIT_*)
 * ------------------------------------------------------------------ */
#ifndef MSR_IA32_RTIT_OUTPUT_BASE
#define MSR_IA32_RTIT_OUTPUT_BASE	0x00000560
#endif
#ifndef MSR_IA32_RTIT_OUTPUT_MASK
#define MSR_IA32_RTIT_OUTPUT_MASK	0x00000561
#endif
#ifndef MSR_IA32_RTIT_CTL
#define MSR_IA32_RTIT_CTL		0x00000570
#endif
#ifndef MSR_IA32_RTIT_STATUS
#define MSR_IA32_RTIT_STATUS		0x00000571
#endif
#ifndef MSR_IA32_RTIT_CR3_MATCH
#define MSR_IA32_RTIT_CR3_MATCH		0x00000572
#endif
#ifndef MSR_IA32_RTIT_ADDR0_A
#define MSR_IA32_RTIT_ADDR0_A		0x00000580
#endif
#ifndef MSR_IA32_RTIT_ADDR0_B
#define MSR_IA32_RTIT_ADDR0_B		0x00000581
#endif

/*
 * RTIT_CTL bit definitions — use <asm/msr-index.h> names where available.
 *
 * The kernel defines: RTIT_CTL_TRACEEN, RTIT_CTL_OS, RTIT_CTL_USR,
 * RTIT_CTL_TOPA, RTIT_CTL_MTC_EN, RTIT_CTL_TSC_EN, RTIT_CTL_BRANCH_EN.
 * Note the different naming: RTIT_CTL_USR (not USER), RTIT_CTL_BRANCH_EN
 * (not BRANCHEN), RTIT_CTL_MTC_EN (not MTCEN), RTIT_CTL_TSC_EN (not TSCEN).
 *
 * We include <asm/msr-index.h> via the vmx_core.h chain.  Do NOT
 * redefine anything that the kernel header already provides.
 *
 * We only define what the kernel does NOT provide:
 */

/* ADDR0_CFG: enable ADDR0 IP filter range; bit 32 of RTIT_CTL.
 * The kernel defines RTIT_CTL_ADDR0 = (0x0full << 32) — a 4-bit field.
 * We use bit 32 (= value 1 in the field) to enable ADDR0 with config=1
 * (filter-in mode).  This is RTIT_CTL_ADDR0 with the lowest bit set.
 */
#define PHANTOM_RTIT_CTL_ADDR0_EN	(1ULL << 32)

/*
 * RTIT_CTL base value for phantom (timing packets disabled for determinism).
 *
 * Uses kernel-defined names from <asm/msr-index.h>:
 *   RTIT_CTL_OS        = BIT(2)  — trace kernel (CPL=0)
 *   RTIT_CTL_USR       = BIT(3)  — trace user (CPL>0)
 *   RTIT_CTL_TOPA      = BIT(8)  — ToPA output mode
 *   RTIT_CTL_BRANCH_EN = BIT(13) — branch trace (TNT/TIP packets)
 *
 * Timing packets NOT set (CYCEn=MTCEn=TSCEn=PTWEn=0) — determinism.
 * TraceEn NOT set — enabled at VM entry via VMCS load control.
 */
#define RTIT_CTL_BASE_VALUE	(RTIT_CTL_OS | RTIT_CTL_USR | \
				 RTIT_CTL_TOPA | RTIT_CTL_BRANCH_EN)

/* ------------------------------------------------------------------
 * ToPA entry format (Intel SDM Vol. 3C §36.2.4)
 *
 * Each ToPA entry is 8 bytes:
 *   bits [63:12]: physical address of output region (4KB aligned)
 *   bit 4:       INT — trigger PMI interrupt on this entry
 *   bit 2:       STOP — stop tracing after this entry
 *   bit 1:       reserved, must be 0
 *   bit 0:       END — last entry in this ToPA table
 * ------------------------------------------------------------------ */
#define TOPA_ENTRY_INT		BIT_ULL(4)	/* Interrupt on this entry */
#define TOPA_ENTRY_STOP		BIT_ULL(2)	/* Stop tracing here */
#define TOPA_ENTRY_END		BIT_ULL(0)	/* Last entry in table */
#define TOPA_ENTRY_ADDR_MASK	(~0xFFFULL)	/* Physical address bits */

/* ------------------------------------------------------------------
 * PT buffer sizing.
 *
 * Each double-buffer slot is 2MB of contiguous output capacity.
 * We use 512 × 4KB pages per slot (simpler than one 2MB contiguous alloc).
 * 512 pages × 4KB = 2MB per slot; two slots = 4MB total per instance.
 *
 * ToPA table fits 64 entries per slot (512 pages / 8 pages-per-entry = 64,
 * but we use one 4KB page per ToPA entry for simplicity, giving 512 entries;
 * we cap at PHANTOM_PT_TOPA_ENTRIES_PER_SLOT).
 * ------------------------------------------------------------------ */
#define PHANTOM_PT_PAGES_PER_SLOT	32	/* 32 × 4KB = 128KB per slot */
#define PHANTOM_PT_TOPA_ENTRIES_PER_SLOT PHANTOM_PT_PAGES_PER_SLOT
#define PHANTOM_PT_SLOT_COUNT		2	/* double-buffer */
#define PHANTOM_PT_SLOT_SIZE		\
	((unsigned long)PHANTOM_PT_PAGES_PER_SLOT * PAGE_SIZE)

/* Coverage flags */
#define PHANTOM_COVERAGE_DISCARDED	BIT(0)	/* ToPA overflow occurred */

/* ------------------------------------------------------------------
 * VMCS field encodings for PT-in-VMX (Intel SDM Vol. 3C §25.6.2)
 *
 * These are defined with #ifndef guards in case <asm/vmx.h> provides them.
 * ------------------------------------------------------------------ */
#ifndef VMCS_GUEST_IA32_RTIT_CTL
#define VMCS_GUEST_IA32_RTIT_CTL	0x2814	/* 64-bit guest-state */
#endif

/* VM-entry control bit 18: Load IA32_RTIT_CTL on entry (PT-in-VMX)
 * VM-exit control bit 25: Clear IA32_RTIT_CTL on exit (PT-in-VMX)
 * These are defined in <asm/vmx.h> on Linux 6.x; guard against redefinition.
 */
#ifndef VM_ENTRY_LOAD_IA32_RTIT_CTL
#define VM_ENTRY_LOAD_IA32_RTIT_CTL	0x00040000	/* bit 18 */
#endif
#ifndef VM_EXIT_CLEAR_IA32_RTIT_CTL
#define VM_EXIT_CLEAR_IA32_RTIT_CTL	0x02000000	/* bit 25 */
#endif

/*
 * RTIT_STATUS field notes:
 *   The kernel defines in <asm/msr-index.h>:
 *     RTIT_STATUS_BYTECNT_OFFSET = 32
 *     RTIT_STATUS_BYTECNT        = (0x1ffffull << 32)
 *     RTIT_STATUS_ERROR          = BIT(4)
 *     RTIT_STATUS_BUFFOVF        = BIT(3)
 *   We use these directly in pt_config.c.
 */

/* ------------------------------------------------------------------
 * Per-instance Intel PT state
 *
 * Embedded in phantom_vmx_cpu_state.  All fields are initialised by
 * phantom_pt_init() and cleaned up by phantom_pt_teardown().
 *
 * Memory layout:
 *   topa_table[slot]: kernel-VA array of u64 ToPA entries (one per page)
 *   topa_pages[slot][page]: backing struct page * for each PT output page
 *   topa_table_page[slot]: the 4KB page holding the ToPA entry array itself
 *
 * IMPORTANT: topa_table must be page-aligned (the MSR takes a physical
 * address; we use a dedicated page for each slot's ToPA table).
 * ------------------------------------------------------------------ */
struct phantom_pt_state {
	/* Configured RTIT_CTL value (TraceEn=0; set to 1 at VM entry) */
	u64			rtit_ctl;

	/* Physical address of the active slot's ToPA table page */
	u64			output_base_pa;

	/*
	 * ToPA table entries for each slot.
	 * Each entry is an 8-byte ToPA descriptor pointing to one output page.
	 * The last entry has INT=1 (overflow notification) and END=1.
	 * Stored in kernel VA; converted to PA when writing MSRs.
	 *
	 * topa_table_kva[slot]: kernel VA of the ToPA table page itself.
	 * This is the same memory as the array of u64 ToPA entries.
	 */
	u64			*topa_table_kva[PHANTOM_PT_SLOT_COUNT];

	/* Physical address of each slot's ToPA table (for OUTPUT_BASE MSR) */
	u64			topa_table_pa[PHANTOM_PT_SLOT_COUNT];

	/* ToPA table pages (holds the descriptor array) */
	struct page		*topa_table_page[PHANTOM_PT_SLOT_COUNT];

	/* Backing pages for PT output (indexed [slot][page_idx]) */
	struct page		*topa_pages[PHANTOM_PT_SLOT_COUNT]
					   [PHANTOM_PT_PAGES_PER_SLOT];
	int			topa_page_count[PHANTOM_PT_SLOT_COUNT];

	/* Currently-writing buffer index (0 or 1) */
	int			active_buf;

	/* eventfd for kernel→userspace PT iteration notification */
	struct eventfd_ctx	*eventfd;

	/* Byte count written in the last completed iteration */
	u64			last_byte_count;

	/* Health metrics */
	u64			topa_overflow_count;

	/* Coverage flags (PHANTOM_COVERAGE_DISCARDED) */
	u32			coverage_flags;

	/* false if PT is unavailable or init failed */
	bool			pt_enabled;

	/* true if VM entry/exit VMCS controls support PT-in-VMX */
	bool			pt_in_vmx;
};

/* ------------------------------------------------------------------
 * PT lifecycle API
 *
 * All functions MUST be called from the vCPU thread (pinned CPU)
 * except phantom_pt_init() which may run from any sleepable context.
 * ------------------------------------------------------------------ */

struct phantom_vmx_cpu_state;

/**
 * phantom_pt_init - Detect PT, allocate ToPA buffers, configure MSRs.
 * @state: Per-CPU VMX state.
 *
 * Called from the vCPU thread during VMCS setup (after VMXON).
 * Detects PT capability via CPUID.0x14, allocates two 2-buffer slots
 * of PT output pages, builds ToPA tables, and configures RTIT_CTL
 * (TraceEn=0 — enabled at VM entry by VMCS load control).
 *
 * Returns 0 on success.  On failure, state->pt.pt_enabled = false
 * and the module continues without PT coverage.
 */
int phantom_pt_init(struct phantom_vmx_cpu_state *state);

/**
 * phantom_pt_configure_vmcs - Write PT-related VMCS entry/exit controls.
 * @state: Per-CPU VMX state (VMCS must be current).
 *
 * Checks if PT-in-VMX is supported via MSR_IA32_VMX_TRUE_ENTRY/EXIT_CTLS.
 * If yes: sets VM_ENTRY_LOAD_IA32_RTIT_CTL and VM_EXIT_CLEAR_IA32_RTIT_CTL.
 * If no: records pt_in_vmx=false (fallback MSR management required).
 *
 * Called from phantom_vmcs_configure_fields() after control fields are set.
 */
void phantom_pt_configure_vmcs(struct phantom_vmx_cpu_state *state);

/**
 * phantom_pt_iteration_start - Enable tracing for the upcoming VM entry.
 * @state: Per-CPU VMX state.
 *
 * When pt_in_vmx=false (fallback mode): sets RTIT_CTL.TraceEn=1 manually.
 * When pt_in_vmx=true: the VMCS VM_ENTRY_LOAD control handles it; this
 * function ensures the RTIT_CTL VMCS field has TraceEn=1.
 *
 * Called from the vCPU thread immediately before VMRESUME.
 */
void phantom_pt_iteration_start(struct phantom_vmx_cpu_state *state);

/**
 * phantom_pt_iteration_reset - Finalize tracing after VM exit.
 * @state: Per-CPU VMX state.
 *
 * 6-step MSR sequence:
 *   1. Verify TraceEn=0 (cleared by VM_EXIT_CLEAR or fallback manual stop).
 *   2. Read byte count from IA32_RTIT_STATUS.
 *   3. Signal userspace via eventfd (write 1 to notify decoder).
 *   4. Reset IA32_RTIT_OUTPUT_MASK_PTRS to 0.
 *   5. Clear IA32_RTIT_STATUS.
 *   6. Swap double-buffer (active_buf ^= 1); update OUTPUT_BASE to new slot.
 *
 * Called from the vCPU thread after each iteration ends (RELEASE/PANIC).
 * Hot-path safe: no printk, no allocation, no sleeping.
 */
void phantom_pt_iteration_reset(struct phantom_vmx_cpu_state *state);

/**
 * phantom_pt_teardown - Disable PT and free all ToPA pages.
 * @state: Per-CPU VMX state.
 *
 * Disables RTIT_CTL.TraceEn, frees all topa_pages and topa_table_pages,
 * releases eventfd reference if held.
 *
 * Called from the vCPU thread during module unload (do_stop path).
 */
void phantom_pt_teardown(struct phantom_vmx_cpu_state *state);

#endif /* PHANTOM_PT_CONFIG_H */
