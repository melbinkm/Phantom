// SPDX-License-Identifier: GPL-2.0-only
/*
 * pt_config.c — Intel Processor Trace (PT) configuration for phantom.ko
 *
 * Implements the full PT lifecycle for the bare-metal hypervisor fuzzer:
 *   - PT capability detection (CPUID.0x14 + RTIT capability MSR check)
 *   - ToPA double-buffer allocation (2 slots × 32 × 4KB pages = 256KB each)
 *   - ToPA table construction (one 4KB table page per slot)
 *   - VMCS entry/exit control setup for PT-in-VMX (preferred path)
 *   - Per-iteration MSR management (6-step reset sequence)
 *   - eventfd-based kernel→userspace PT notification
 *   - Teardown and cleanup
 *
 * Hot-path discipline:
 *   phantom_pt_iteration_start() and phantom_pt_iteration_reset() are on
 *   the hot path (called around every VMRESUME).  They must NOT call
 *   printk, kmalloc(GFP_KERNEL), schedule(), or mutex_lock().
 *   trace_printk() is used inside PHANTOM_DEBUG guards.
 *
 * Determinism requirement:
 *   CYCEn=MTCEn=TSCEn=PTWEn=0 — timing packets are disabled so that
 *   identical control flow produces byte-identical PT traces (required
 *   for the 1000/1000 determinism gate at Phase 3 entry).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/eventfd.h>
#include <linux/string.h>
#include <asm/msr.h>
#include <asm/cpuid.h>
#include <asm/processor.h>
#include <asm/io.h>	/* page_to_phys */

#include "phantom.h"
#include "vmx_core.h"
#include "pt_config.h"

/* ------------------------------------------------------------------
 * Internal helpers — forward declarations
 * ------------------------------------------------------------------ */

static int pt_check_cpuid(void);
static int pt_alloc_topa_slot(struct phantom_pt_state *pt, int slot, int node);
static void pt_free_topa_slot(struct phantom_pt_state *pt, int slot);
static void pt_build_topa_table(struct phantom_pt_state *pt, int slot);
static void pt_set_output_base(struct phantom_pt_state *pt, int slot);

/* ------------------------------------------------------------------
 * phantom_pt_init - Detect PT, allocate buffers, configure MSRs.
 * ------------------------------------------------------------------ */

/**
 * phantom_pt_init - Initialise Intel PT for this vCPU instance.
 * @state: Per-CPU VMX state.
 *
 * Called from the vCPU thread after VMXON and VMCS alloc.
 * Sleepable context — may use GFP_KERNEL allocations.
 *
 * Returns 0 on success; on any failure, pt.pt_enabled is set to false
 * and the module continues without PT coverage (non-fatal).
 */
int phantom_pt_init(struct phantom_vmx_cpu_state *state)
{
	struct phantom_pt_state *pt = &state->pt;
	int cpu = state->cpu;
	int node = cpu_to_node(cpu);
	int slot;
	int ret;

	memset(pt, 0, sizeof(*pt));
	pt->pt_enabled = false;

	/* Step 1: Check PT availability via CPUID */
	ret = pt_check_cpuid();
	if (ret) {
		pr_info("phantom: CPU%d: Intel PT not available "
			"(cpuid check failed: %d)\n", cpu, ret);
		return 0;  /* Non-fatal: PT is optional */
	}

	/* Step 2: Allocate double-buffer slots */
	for (slot = 0; slot < PHANTOM_PT_SLOT_COUNT; slot++) {
		ret = pt_alloc_topa_slot(pt, slot, node);
		if (ret) {
			pr_warn("phantom: CPU%d: PT slot %d alloc failed: %d"
				" (running without PT)\n", cpu, slot, ret);
			goto err_free_slots;
		}
		pt_build_topa_table(pt, slot);
	}

	/*
	 * Step 3: Configure RTIT_CTL value (TraceEn=0 at init).
	 *
	 * Timing packets disabled (CYCEn=MTCEn=TSCEn=0) for determinism.
	 * OS=1: trace kernel mode.  USER=1: trace user mode.
	 * TOPA=1: use ToPA output scheme.
	 * BRANCHEN=1: branch trace mode (decode branch targets).
	 * TraceEn=0: enabled at VM entry by VMCS load control or manual MSR.
	 */
	pt->rtit_ctl = RTIT_CTL_BASE_VALUE;  /* TraceEn cleared */

	/* Step 4: Set initial output base to slot 0 */
	pt->active_buf = 0;
	pt_set_output_base(pt, 0);

	/*
	 * Step 5: Write initial MSR state.
	 *   OUTPUT_BASE: physical address of ToPA table (slot 0).
	 *   OUTPUT_MASK: 0 — write pointer at start of buffer.
	 *   RTIT_CTL: configured value with TraceEn=0.
	 *   RTIT_STATUS: 0 — clear any residual state.
	 */
	wrmsr(MSR_IA32_RTIT_OUTPUT_BASE,
	      (u32)(pt->output_base_pa & 0xFFFFFFFF),
	      (u32)(pt->output_base_pa >> 32));
	wrmsr(MSR_IA32_RTIT_OUTPUT_MASK, 0, 0);
	wrmsr(MSR_IA32_RTIT_CTL,
	      (u32)(pt->rtit_ctl & 0xFFFFFFFF),
	      (u32)(pt->rtit_ctl >> 32));
	wrmsr(MSR_IA32_RTIT_STATUS, 0, 0);

	pt->pt_enabled = true;
	pt->last_byte_count = 0;
	pt->topa_overflow_count = 0;
	pt->coverage_flags = 0;
	pt->eventfd = NULL;

	pr_info("phantom: CPU%d: Intel PT initialised "
		"(2 × %u pages = %lu KB per slot, rtit_ctl=0x%llx)\n",
		cpu,
		PHANTOM_PT_PAGES_PER_SLOT,
		(unsigned long)PHANTOM_PT_SLOT_SIZE / 1024,
		pt->rtit_ctl);
	return 0;

err_free_slots:
	for (slot = slot - 1; slot >= 0; slot--)
		pt_free_topa_slot(pt, slot);
	return 0;  /* Non-fatal */
}

/* ------------------------------------------------------------------
 * phantom_pt_configure_vmcs - Write PT-in-VMX VMCS controls.
 * ------------------------------------------------------------------ */

/**
 * phantom_pt_configure_vmcs - Configure VMCS for Intel PT.
 * @state: Per-CPU VMX state (VMCS must be current via VMPTRLD).
 *
 * Checks MSR_IA32_VMX_TRUE_ENTRY_CTLS bit 18 (Load IA32_RTIT_CTL)
 * and MSR_IA32_VMX_TRUE_EXIT_CTLS bit 25 (Clear IA32_RTIT_CTL).
 * If both are supported, sets pt_in_vmx=true and programs the VMCS
 * guest-state RTIT_CTL field so the hardware auto-enables PT on entry.
 *
 * If PT-in-VMX is not supported, falls back to manual MSR management
 * (phantom_pt_iteration_start writes RTIT_CTL manually).
 *
 * MUST be called on the vCPU thread with VMCS current.
 */
void phantom_pt_configure_vmcs(struct phantom_vmx_cpu_state *state)
{
	struct phantom_pt_state *pt = &state->pt;
	u64 entry_ctls_cap;
	u64 exit_ctls_cap;
	u64 cur_entry, cur_exit;

	if (!pt->pt_enabled)
		return;

	/*
	 * Check PT-in-VMX support.
	 * MSR_IA32_VMX_TRUE_ENTRY_CTLS[18] = Load IA32_RTIT_CTL allowed.
	 * MSR_IA32_VMX_TRUE_EXIT_CTLS[25]  = Clear IA32_RTIT_CTL allowed.
	 *
	 * The high 32 bits of these MSRs are the "allowed 1" bits —
	 * bits that CAN be set to 1.  Bit N is supported if
	 * allowed_1[N] == 1.
	 */
	rdmsrl(MSR_IA32_VMX_TRUE_ENTRY_CTLS, entry_ctls_cap);
	rdmsrl(MSR_IA32_VMX_TRUE_EXIT_CTLS,  exit_ctls_cap);

	/* Allowed-1 bits are in the high 32 bits of these MSRs */
	if (!((entry_ctls_cap >> 32) & VM_ENTRY_LOAD_IA32_RTIT_CTL) ||
	    !((exit_ctls_cap  >> 32) & VM_EXIT_CLEAR_IA32_RTIT_CTL)) {
		pr_info("phantom: CPU%d: PT-in-VMX not supported "
			"(entry_cap=0x%llx exit_cap=0x%llx) — "
			"using MSR fallback\n",
			state->cpu, entry_ctls_cap, exit_ctls_cap);
		pt->pt_in_vmx = false;
		return;
	}

	pt->pt_in_vmx = true;

	/*
	 * Set VM-entry control: Load IA32_RTIT_CTL on VM entry.
	 * This causes the hardware to load our rtit_ctl value (with
	 * TraceEn=1 when we want tracing) into the MSR on every VM entry,
	 * enabling PT automatically without manual MSR writes.
	 */
	cur_entry = phantom_vmcs_read64(VMCS_CTRL_ENTRY);
	phantom_vmcs_write64(VMCS_CTRL_ENTRY,
			     cur_entry | VM_ENTRY_LOAD_IA32_RTIT_CTL);

	/*
	 * Set VM-exit control: Clear IA32_RTIT_CTL on VM exit.
	 * This disables PT automatically on every VM exit, ensuring
	 * the VM exit handler is not traced (clean boundary).
	 */
	cur_exit = phantom_vmcs_read64(VMCS_CTRL_EXIT);
	phantom_vmcs_write64(VMCS_CTRL_EXIT,
			     cur_exit | VM_EXIT_CLEAR_IA32_RTIT_CTL);

	/*
	 * Write the RTIT_CTL value (with TraceEn=1) to the VMCS guest-state
	 * field 0x2814.  The hardware will load this on the next VM entry.
	 *
	 * We set TraceEn=1 here so that tracing begins immediately on
	 * VM entry without a separate MSR write.
	 */
	phantom_vmcs_write64(VMCS_GUEST_IA32_RTIT_CTL,
			     pt->rtit_ctl | RTIT_CTL_TRACEEN);

	pr_info("phantom: CPU%d: PT-in-VMX configured "
		"(VM_ENTRY_LOAD_RTIT_CTL + VM_EXIT_CLEAR_RTIT_CTL)\n",
		state->cpu);
}

/* ------------------------------------------------------------------
 * phantom_pt_iteration_start - Enable tracing before VMRESUME.
 * ------------------------------------------------------------------ */

/**
 * phantom_pt_iteration_start - Arm PT for the next VM entry.
 * @state: Per-CPU VMX state.
 *
 * When pt_in_vmx=true:  the VMCS load control handles TraceEn;
 *   we just ensure the VMCS RTIT_CTL field has TraceEn=1.
 * When pt_in_vmx=false: write RTIT_CTL with TraceEn=1 manually.
 *
 * Hot-path: no printk, no allocation, no sleeping.
 */
void phantom_pt_iteration_start(struct phantom_vmx_cpu_state *state)
{
	struct phantom_pt_state *pt = &state->pt;

	if (!pt->pt_enabled)
		return;

	if (pt->pt_in_vmx) {
		/*
		 * PT-in-VMX: update the VMCS guest-state field so TraceEn=1
		 * is loaded on the next VM entry.  The VMCS write here is
		 * hot-path safe (no sleeping, fast VMWRITE instruction).
		 */
		phantom_vmcs_write64(VMCS_GUEST_IA32_RTIT_CTL,
				     pt->rtit_ctl | RTIT_CTL_TRACEEN);
	} else {
		/*
		 * Fallback: manually enable PT via WRMSR.
		 * This is racy (we trace the gap between WRMSR and VMRESUME)
		 * but acceptable when PT-in-VMX is not available.
		 */
		wrmsr(MSR_IA32_RTIT_CTL,
		      (u32)((pt->rtit_ctl | RTIT_CTL_TRACEEN) & 0xFFFFFFFF),
		      (u32)((pt->rtit_ctl | RTIT_CTL_TRACEEN) >> 32));
	}

#ifdef PHANTOM_DEBUG
	trace_printk("PT_START slot=%d\n", pt->active_buf);
#endif
}

/* ------------------------------------------------------------------
 * phantom_pt_iteration_reset - 6-step MSR sequence after VM exit.
 * ------------------------------------------------------------------ */

/**
 * phantom_pt_iteration_reset - Finalise tracing after one iteration.
 * @state: Per-CPU VMX state.
 *
 * Executes the 6-step per-iteration PT reset sequence:
 *   1. PT already stopped (VM_EXIT_CLEAR or fallback).
 *   2. Read byte count from IA32_RTIT_STATUS.
 *   3. Signal userspace via eventfd (write 1).
 *   4. Reset IA32_RTIT_OUTPUT_MASK_PTRS to 0.
 *   5. Clear IA32_RTIT_STATUS.
 *   6. Swap double-buffer; update OUTPUT_BASE MSR to new slot.
 *
 * Hot-path: no printk, no allocation, no sleeping.
 * eventfd_signal() is safe in atomic context (uses spinlock internally).
 */
void phantom_pt_iteration_reset(struct phantom_vmx_cpu_state *state)
{
	struct phantom_pt_state *pt = &state->pt;
	u64 status;
	u32 lo, hi;

	if (!pt->pt_enabled)
		return;

	/*
	 * Step 1: PT is already stopped.
	 *   pt_in_vmx=true:  VM_EXIT_CLEAR zeroed RTIT_CTL on exit.
	 *   pt_in_vmx=false: we must stop it here.
	 */
	if (!pt->pt_in_vmx) {
		/* Stop tracing: clear TraceEn */
		wrmsr(MSR_IA32_RTIT_CTL,
		      (u32)(pt->rtit_ctl & 0xFFFFFFFF),
		      (u32)(pt->rtit_ctl >> 32));
	}

#ifdef PHANTOM_DEBUG
	{
		u64 ctl_val;

		rdmsrl(MSR_IA32_RTIT_CTL, ctl_val);
		if (ctl_val & RTIT_CTL_TRACEEN)
			trace_printk("PT_WARN: TraceEn still set after exit!\n");
	}
#endif

	/*
	 * Step 2: Read byte count from IA32_RTIT_STATUS.
	 * PacketByteCnt is in bits [48:32].
	 */
	rdmsr(MSR_IA32_RTIT_STATUS, lo, hi);
	status = ((u64)hi << 32) | lo;
	/*
	 * PacketByteCnt is in STATUS bits [48:32] (17 bits).
	 * The kernel defines RTIT_STATUS_BYTECNT_OFFSET=32 and
	 * RTIT_STATUS_BYTECNT = (0x1ffffull << 32).
	 */
	pt->last_byte_count = (status & RTIT_STATUS_BYTECNT) >>
			       RTIT_STATUS_BYTECNT_OFFSET;

	/*
	 * Check for overflow/error: RTIT_STATUS_ERROR (BIT(4)) indicates PT
	 * encountered an error (e.g., buffer full with STOP=1 and no WRAP).
	 * RTIT_STATUS_BUFFOVF (BIT(3)) indicates ToPA buffer overflow.
	 */
	if (status & (RTIT_STATUS_ERROR | RTIT_STATUS_BUFFOVF)) {
		/* PT error/overflow — coverage may be incomplete */
		pt->topa_overflow_count++;
		pt->coverage_flags |= PHANTOM_COVERAGE_DISCARDED;
#ifdef PHANTOM_DEBUG
		trace_printk("PT_OVERFLOW count=%llu status=0x%llx\n",
			     pt->topa_overflow_count, status);
#endif
	}

#ifdef PHANTOM_DEBUG
	trace_printk("PT_RESET slot=%d bytes=%llu\n",
		     pt->active_buf, pt->last_byte_count);
#endif

	/*
	 * Step 3: Signal userspace decoder via eventfd.
	 * eventfd_signal() is safe in softirq context.
	 * If no eventfd is registered, skip silently.
	 */
	if (pt->eventfd)
		eventfd_signal(pt->eventfd);

	/* Step 4: Reset write pointer to start of buffer */
	wrmsr(MSR_IA32_RTIT_OUTPUT_MASK, 0, 0);

	/* Step 5: Clear status register */
	wrmsr(MSR_IA32_RTIT_STATUS, 0, 0);

	/*
	 * Step 6: Swap double-buffer.
	 * Switch to the other slot so the decoder can read the completed
	 * buffer while we write the next iteration to the fresh slot.
	 */
	pt->active_buf ^= 1;
	pt_set_output_base(pt, pt->active_buf);

	/*
	 * Update OUTPUT_BASE MSR to point to the new active slot's ToPA table.
	 * IA32_RTIT_OUTPUT_BASE must contain the PA of the ToPA table.
	 */
	wrmsr(MSR_IA32_RTIT_OUTPUT_BASE,
	      (u32)(pt->output_base_pa & 0xFFFFFFFF),
	      (u32)(pt->output_base_pa >> 32));
}

/* ------------------------------------------------------------------
 * phantom_pt_teardown - Free all PT resources.
 * ------------------------------------------------------------------ */

/**
 * phantom_pt_teardown - Disable PT and release all allocated resources.
 * @state: Per-CPU VMX state.
 *
 * Disables RTIT_CTL.TraceEn, frees ToPA output pages and table pages,
 * releases eventfd reference.
 *
 * Called from the vCPU thread in the do_stop path (before VMXOFF).
 */
void phantom_pt_teardown(struct phantom_vmx_cpu_state *state)
{
	struct phantom_pt_state *pt = &state->pt;
	int slot;

	if (!pt->pt_enabled)
		return;

	/* Disable PT: clear TraceEn */
	wrmsr(MSR_IA32_RTIT_CTL, 0, 0);
	wrmsr(MSR_IA32_RTIT_STATUS, 0, 0);

	/* Release eventfd reference */
	if (pt->eventfd) {
		eventfd_ctx_put(pt->eventfd);
		pt->eventfd = NULL;
	}

	/* Free ToPA output pages and table pages */
	for (slot = 0; slot < PHANTOM_PT_SLOT_COUNT; slot++)
		pt_free_topa_slot(pt, slot);

	pt->pt_enabled = false;
	pr_info("phantom: CPU%d: Intel PT teardown complete\n", state->cpu);
}

/* ------------------------------------------------------------------
 * Internal implementation helpers
 * ------------------------------------------------------------------ */

/**
 * pt_check_cpuid - Verify Intel PT availability via CPUID and RTIT MSR.
 *
 * CPUID.0x14.ECX: Intel PT capability leaf.
 * CPUID.7.0.EBX[bit 25]: Intel PT feature bit.
 *
 * Returns 0 if PT is available, -ENODEV otherwise.
 */
static int pt_check_cpuid(void)
{
	u32 eax, ebx, ecx, edx;

	/* Check CPUID.07h.0:EBX[25] = Intel PT supported */
	cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
	if (!(ebx & BIT(25))) {
		pr_info("phantom: Intel PT: CPUID.7.0.EBX[25] not set\n");
		return -ENODEV;
	}

	/*
	 * Check CPUID.14h.0:EAX (max sub-leaf).
	 * If EAX >= 1, sub-leaf 1 provides further capability details.
	 * We just verify the leaf is valid (EAX >= 1 is typical on PT CPUs).
	 */
	cpuid_count(0x14, 0, &eax, &ebx, &ecx, &edx);
	if (eax < 1) {
		pr_debug("phantom: Intel PT: CPUID.0x14.0 sub-leaf 1 absent\n");
		/* Not fatal — basic PT still available */
	}

	/*
	 * Check ToPA support: CPUID.14h.0:ECX[0] = ToPA output supported.
	 * ToPA is required for our double-buffer scheme.
	 */
	if (!(ecx & BIT(0))) {
		pr_warn("phantom: Intel PT: ToPA output not supported "
			"(CPUID.0x14.0.ECX[0]=0)\n");
		return -ENODEV;
	}

	return 0;
}

/**
 * pt_alloc_topa_slot - Allocate one PT output slot (ToPA table + output pages).
 * @pt:   PT state.
 * @slot: Slot index (0 or 1).
 * @node: NUMA node for page allocation.
 *
 * Allocates:
 *   1. One 4KB page for the ToPA descriptor table.
 *   2. PHANTOM_PT_PAGES_PER_SLOT × 4KB pages for PT output.
 *
 * Returns 0 on success, negative errno on failure.
 */
static int pt_alloc_topa_slot(struct phantom_pt_state *pt, int slot, int node)
{
	struct page *pg;
	int i;

	/* Allocate the ToPA descriptor table page (must be page-aligned) */
	pg = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
	if (!pg)
		return -ENOMEM;

	pt->topa_table_page[slot] = pg;
	pt->topa_table_kva[slot]  = (u64 *)page_address(pg);
	pt->topa_table_pa[slot]   = page_to_phys(pg);

	/* Allocate output pages */
	for (i = 0; i < PHANTOM_PT_PAGES_PER_SLOT; i++) {
		pg = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
		if (!pg) {
			/* Free already-allocated pages */
			int j;

			for (j = 0; j < i; j++) {
				__free_page(pt->topa_pages[slot][j]);
				pt->topa_pages[slot][j] = NULL;
			}
			__free_page(pt->topa_table_page[slot]);
			pt->topa_table_page[slot] = NULL;
			pt->topa_table_kva[slot]  = NULL;
			return -ENOMEM;
		}
		pt->topa_pages[slot][i] = pg;
	}

	pt->topa_page_count[slot] = PHANTOM_PT_PAGES_PER_SLOT;
	return 0;
}

/**
 * pt_free_topa_slot - Free one PT output slot.
 * @pt:   PT state.
 * @slot: Slot index.
 */
static void pt_free_topa_slot(struct phantom_pt_state *pt, int slot)
{
	int i;

	for (i = 0; i < pt->topa_page_count[slot]; i++) {
		if (pt->topa_pages[slot][i]) {
			__free_page(pt->topa_pages[slot][i]);
			pt->topa_pages[slot][i] = NULL;
		}
	}
	pt->topa_page_count[slot] = 0;

	if (pt->topa_table_page[slot]) {
		__free_page(pt->topa_table_page[slot]);
		pt->topa_table_page[slot] = NULL;
		pt->topa_table_kva[slot]  = NULL;
	}
}

/**
 * pt_build_topa_table - Construct the ToPA descriptor array for one slot.
 * @pt:   PT state.
 * @slot: Slot index.
 *
 * Each ToPA entry: PA[63:12] | flags.
 *   - Normal entries: page PA, no flags.
 *   - Last entry: page PA, INT=1 (overflow PMI), END=1 (wrap/stop).
 *
 * The kernel reads the TOPA table via topa_table_kva[slot] (kernel VA).
 * The hardware reads it via OUTPUT_BASE MSR (physical address).
 */
static void pt_build_topa_table(struct phantom_pt_state *pt, int slot)
{
	u64 *table = pt->topa_table_kva[slot];
	int count  = pt->topa_page_count[slot];
	int i;

	for (i = 0; i < count; i++) {
		u64 pa    = page_to_phys(pt->topa_pages[slot][i]);
		u64 entry = pa & TOPA_ENTRY_ADDR_MASK;

		if (i == count - 1) {
			/*
			 * Last entry: INT=1 triggers PMI on overflow,
			 * END=1 wraps around or stops.
			 * We use STOP rather than wrap so we know when the
			 * buffer is full (topa_overflow_count metric).
			 */
			entry |= TOPA_ENTRY_INT | TOPA_ENTRY_STOP |
				 TOPA_ENTRY_END;
		}
		table[i] = entry;
	}
}

/**
 * pt_set_output_base - Update output_base_pa for the given slot.
 * @pt:   PT state.
 * @slot: Slot index.
 *
 * Sets pt->output_base_pa to the physical address of the ToPA table
 * for the specified slot.  This value is used by phantom_pt_init()
 * and phantom_pt_iteration_reset() when writing OUTPUT_BASE.
 */
static void pt_set_output_base(struct phantom_pt_state *pt, int slot)
{
	pt->output_base_pa = pt->topa_table_pa[slot];
}
