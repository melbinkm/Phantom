// SPDX-License-Identifier: GPL-2.0-only
/*
 * snapshot.c — Guest state snapshot/restore for phantom.ko
 *
 * Implements phantom_snapshot_create() and phantom_snapshot_restore().
 *
 * snapshot_create:
 *   - Saves all GPRs from state->guest_regs + VMCS fields
 *   - Saves VMCS control registers, segments, descriptor tables, MSRs
 *   - XSAVE extended registers to pre-allocated aligned buffer
 *   - Marks all EPT RAM pages read-only (snapshot point)
 *   - Resets dirty_count to 0
 *
 * snapshot_restore:
 *   - Walks dirty list: resets EPT PTEs to orig_hpa | RO
 *   - Returns private pages to CoW pool
 *   - Issues single batched INVEPT (single-context)
 *   - Restores VMCS guest-state fields from snapshot
 *   - Restores GPRs into state->guest_regs
 *   - XRSTOR extended registers from aligned buffer
 *
 * INVEPT rules (Intel SDM §28.3.3.1):
 *   - snapshot_restore: YES, one batched INVEPT after ALL EPT updates
 *     (all dirty PTEs reset to RO = structural changes for split pages)
 *
 * Hot-path discipline (snapshot_restore):
 *   - No printk, no sleeping functions, no dynamic allocation
 *   - trace_printk for major events (guarded by PHANTOM_DEBUG)
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/fpu/api.h>
#include <asm/processor.h>
#include <asm/cpuid.h>

#include "phantom.h"
#include "vmx_core.h"
#include "ept.h"
#include "ept_cow.h"
#include "snapshot.h"
#include "debug.h"

/* ------------------------------------------------------------------
 * Internal helpers: save/restore one segment register
 *
 * These read/write the four VMCS sub-fields for a single segment in
 * one call, keeping the save/restore code compact and symmetric.
 * ------------------------------------------------------------------ */

static void snap_save_seg(struct phantom_seg_reg *seg,
			  u32 sel_field, u32 base_field,
			  u32 limit_field, u32 ar_field)
{
	seg->sel   = phantom_vmcs_read16(sel_field);
	seg->base  = phantom_vmcs_read64(base_field);
	seg->limit = phantom_vmcs_read32(limit_field);
	seg->ar    = phantom_vmcs_read32(ar_field);
}

static void snap_restore_seg(const struct phantom_seg_reg *seg,
			     u32 sel_field, u32 base_field,
			     u32 limit_field, u32 ar_field)
{
	phantom_vmcs_write16(sel_field,   seg->sel);
	phantom_vmcs_write64(base_field,  seg->base);
	phantom_vmcs_write32(limit_field, seg->limit);
	phantom_vmcs_write32(ar_field,    seg->ar);
}

/* ------------------------------------------------------------------
 * phantom_snapshot_create
 * ------------------------------------------------------------------ */

/**
 * phantom_snapshot_create - Capture the current guest architectural state.
 * @state: Per-CPU VMX state (VMCS must be current on this CPU).
 *
 * Returns 0 on success.  Currently infallible, but returns int for
 * future extensibility (e.g., XSAVE failure detection).
 */
int phantom_snapshot_create(struct phantom_vmx_cpu_state *state)
{
	struct phantom_snapshot *snap = &state->snap;

	/* ----------------------------------------------------------
	 * Step 1: Save general-purpose registers from guest_regs.
	 *
	 * RSP and RIP are not in guest_regs (they live in the VMCS
	 * guest-state area), so we read them from the VMCS.
	 * RFLAGS is also only in the VMCS.
	 * ---------------------------------------------------------- */
	snap->rax = state->guest_regs.rax;
	snap->rbx = state->guest_regs.rbx;
	snap->rcx = state->guest_regs.rcx;
	snap->rdx = state->guest_regs.rdx;
	snap->rsi = state->guest_regs.rsi;
	snap->rdi = state->guest_regs.rdi;
	snap->rbp = state->guest_regs.rbp;
	snap->r8  = state->guest_regs.r8;
	snap->r9  = state->guest_regs.r9;
	snap->r10 = state->guest_regs.r10;
	snap->r11 = state->guest_regs.r11;
	snap->r12 = state->guest_regs.r12;
	snap->r13 = state->guest_regs.r13;
	snap->r14 = state->guest_regs.r14;
	snap->r15 = state->guest_regs.r15;

	/* RSP, RIP, RFLAGS from VMCS */
	snap->rip    = phantom_vmcs_read64(VMCS_GUEST_RIP);
	snap->rsp    = phantom_vmcs_read64(VMCS_GUEST_RSP);
	snap->rflags = phantom_vmcs_read64(VMCS_GUEST_RFLAGS);

	/* ----------------------------------------------------------
	 * Step 2: Save VMCS guest control registers.
	 * ---------------------------------------------------------- */
	snap->cr0 = phantom_vmcs_read64(VMCS_GUEST_CR0);
	snap->cr3 = phantom_vmcs_read64(VMCS_GUEST_CR3);
	snap->cr4 = phantom_vmcs_read64(VMCS_GUEST_CR4);
	snap->dr7 = phantom_vmcs_read64(VMCS_GUEST_DR7);

	/* ----------------------------------------------------------
	 * Step 3: Save segment registers (8 × 4 sub-fields each).
	 * ---------------------------------------------------------- */
	snap_save_seg(&snap->cs,
		      VMCS_GUEST_CS_SELECTOR, VMCS_GUEST_CS_BASE,
		      VMCS_GUEST_CS_LIMIT,   VMCS_GUEST_CS_AR);
	snap_save_seg(&snap->ss,
		      VMCS_GUEST_SS_SELECTOR, VMCS_GUEST_SS_BASE,
		      VMCS_GUEST_SS_LIMIT,   VMCS_GUEST_SS_AR);
	snap_save_seg(&snap->ds,
		      VMCS_GUEST_DS_SELECTOR, VMCS_GUEST_DS_BASE,
		      VMCS_GUEST_DS_LIMIT,   VMCS_GUEST_DS_AR);
	snap_save_seg(&snap->es,
		      VMCS_GUEST_ES_SELECTOR, VMCS_GUEST_ES_BASE,
		      VMCS_GUEST_ES_LIMIT,   VMCS_GUEST_ES_AR);
	snap_save_seg(&snap->fs,
		      VMCS_GUEST_FS_SELECTOR, VMCS_GUEST_FS_BASE,
		      VMCS_GUEST_FS_LIMIT,   VMCS_GUEST_FS_AR);
	snap_save_seg(&snap->gs,
		      VMCS_GUEST_GS_SELECTOR, VMCS_GUEST_GS_BASE,
		      VMCS_GUEST_GS_LIMIT,   VMCS_GUEST_GS_AR);
	snap_save_seg(&snap->ldtr,
		      VMCS_GUEST_LDTR_SELECTOR, VMCS_GUEST_LDTR_BASE,
		      VMCS_GUEST_LDTR_LIMIT,   VMCS_GUEST_LDTR_AR);
	snap_save_seg(&snap->tr,
		      VMCS_GUEST_TR_SELECTOR, VMCS_GUEST_TR_BASE,
		      VMCS_GUEST_TR_LIMIT,   VMCS_GUEST_TR_AR);

	/* ----------------------------------------------------------
	 * Step 4: Save descriptor tables.
	 * ---------------------------------------------------------- */
	snap->gdtr_base  = phantom_vmcs_read64(VMCS_GUEST_GDTR_BASE);
	snap->gdtr_limit = phantom_vmcs_read32(VMCS_GUEST_GDTR_LIMIT);
	snap->idtr_base  = phantom_vmcs_read64(VMCS_GUEST_IDTR_BASE);
	snap->idtr_limit = phantom_vmcs_read32(VMCS_GUEST_IDTR_LIMIT);

	/* ----------------------------------------------------------
	 * Step 5: Save guest MSRs from VMCS guest-state area.
	 * ---------------------------------------------------------- */
	snap->efer       = phantom_vmcs_read64(VMCS_GUEST_IA32_EFER);
	snap->debugctl   = phantom_vmcs_read64(VMCS_GUEST_IA32_DEBUGCTL);
	snap->pat        = phantom_vmcs_read64(VMCS_GUEST_IA32_PAT);
	snap->sysenter_cs  = phantom_vmcs_read32(VMCS_GUEST_IA32_SYSENTER_CS);
	snap->sysenter_esp = phantom_vmcs_read64(VMCS_GUEST_IA32_SYSENTER_ESP);
	snap->sysenter_eip = phantom_vmcs_read64(VMCS_GUEST_IA32_SYSENTER_EIP);

	/* ----------------------------------------------------------
	 * Step 6: Save guest interrupt / activity state.
	 * ---------------------------------------------------------- */
	snap->interruptibility = phantom_vmcs_read32(VMCS_GUEST_INTR_STATE);
	snap->activity_state   = phantom_vmcs_read32(VMCS_GUEST_ACTIVITY_STATE);

	/* ----------------------------------------------------------
	 * Step 7: XSAVE extended registers to aligned buffer.
	 *
	 * xsave_area_aligned is a 64-byte aligned pointer within the
	 * kzalloc'd xsave_area buffer.  We use inline asm xsave64
	 * directly, bracketed with kernel_fpu_begin/end, to avoid any
	 * dependency on copy_xregs_to_kernel() (which saves kernel
	 * thread state, not an arbitrary buffer).
	 *
	 * The xcr0_supported mask tells xsave64 which state components
	 * to save (same components that will be restored by xrstor64).
	 * ---------------------------------------------------------- */
	if (state->xsave_area_aligned) {
		u32 xcr0_lo = (u32)state->xcr0_supported;
		u32 xcr0_hi = (u32)(state->xcr0_supported >> 32);

		kernel_fpu_begin();
		asm volatile(
			"xsave64 %0"
			: "=m" (*(u8 *)state->xsave_area_aligned)
			: "a" (xcr0_lo), "d" (xcr0_hi)
			: "memory");
		kernel_fpu_end();
	}

	/* ----------------------------------------------------------
	 * Step 8: Mark all EPT RAM pages read-only.
	 *
	 * After this, any guest write to a RAM GPA triggers an EPT
	 * violation which is handled by phantom_cow_fault() to create
	 * a private copy.  This is the snapshot point: every subsequent
	 * write is tracked in the dirty list.
	 * ---------------------------------------------------------- */
	phantom_ept_mark_all_ro(&state->ept);

	/* ----------------------------------------------------------
	 * Step 9: Reset dirty list for the new iteration.
	 * ---------------------------------------------------------- */
	state->dirty_count = 0;

	snap->valid = true;

#ifdef PHANTOM_DEBUG
	trace_printk("PHANTOM SNAPSHOT_CREATE cpu=%d rip=0x%llx rsp=0x%llx "
		     "cr3=0x%llx\n",
		     state->cpu, snap->rip, snap->rsp, snap->cr3);
#endif

	return 0;
}
EXPORT_SYMBOL_GPL(phantom_snapshot_create);

/* ------------------------------------------------------------------
 * phantom_snapshot_restore
 * ------------------------------------------------------------------ */

/**
 * phantom_snapshot_restore - Restore guest state to the last snapshot.
 * @state: Per-CPU VMX state (VMCS must be current on this CPU).
 *
 * Hot-path safe: no printk outside PHANTOM_DEBUG, no sleeping,
 * no dynamic allocation.  All resources pre-allocated at setup time.
 *
 * Returns 0 on success, -EINVAL if no valid snapshot exists.
 */
int phantom_snapshot_restore(struct phantom_vmx_cpu_state *state)
{
	const struct phantom_snapshot *snap = &state->snap;
	u32 i;

	if (!snap->valid)
		return -EINVAL;

#ifdef PHANTOM_DEBUG
	trace_printk("PHANTOM SNAPSHOT_RESTORE cpu=%d dirty_count=%u\n",
		     state->cpu, state->dirty_count);
#endif

	/* ----------------------------------------------------------
	 * Step 1: Walk dirty list.
	 *
	 * For each dirty entry: reset the EPT PTE back to the
	 * original HPA with READ | EXEC | WB (write-protected, no W
	 * bit).  Return the private page to the CoW pool.
	 *
	 * Hot-path: no printk, no sleeping.
	 * ---------------------------------------------------------- */
	for (i = 0; i < state->dirty_count; i++) {
		struct phantom_dirty_entry *e = &state->dirty_list[i];
		u64 *pte;

		pte = phantom_ept_lookup_pte(&state->ept, e->gpa);
		if (pte) {
			/*
			 * Restore read-only (no write bit), write-back.
			 * EPT_PTE_WRITE is intentionally absent.
			 */
			*pte = (e->orig_hpa & EPT_PTE_HPA_MASK) |
			       EPT_PTE_READ | EPT_PTE_EXEC |
			       EPT_PTE_MEMTYPE_WB;
		}

		phantom_cow_pool_free(&state->cow_pool,
				      pfn_to_page(e->priv_hpa >> PAGE_SHIFT));
	}
	state->dirty_count = 0;

	/* ----------------------------------------------------------
	 * Step 2: Single batched INVEPT after ALL EPT updates.
	 *
	 * Required: we just changed multiple EPT PTEs (RW → RO).
	 * Intel SDM §28.3.3.1: permission-only changes to the faulting
	 * PTE do not require INVEPT; but here we are resetting ALL dirty
	 * PTEs (including ones that were not the last faulting page),
	 * and after 2MB→4KB splits the structural changes require INVEPT.
	 * One batched single-context INVEPT covers all updates.
	 * ---------------------------------------------------------- */
	phantom_invept_single_context(state->ept.eptp);

	/* ----------------------------------------------------------
	 * Step 3: Restore VMCS guest control registers.
	 * ---------------------------------------------------------- */
	phantom_vmcs_write64(VMCS_GUEST_CR0, snap->cr0);
	phantom_vmcs_write64(VMCS_GUEST_CR3, snap->cr3);
	phantom_vmcs_write64(VMCS_GUEST_CR4, snap->cr4);
	phantom_vmcs_write64(VMCS_GUEST_DR7, snap->dr7);

	/* ----------------------------------------------------------
	 * Step 4: Restore RIP, RSP, RFLAGS.
	 * ---------------------------------------------------------- */
	phantom_vmcs_write64(VMCS_GUEST_RIP,    snap->rip);
	phantom_vmcs_write64(VMCS_GUEST_RSP,    snap->rsp);
	phantom_vmcs_write64(VMCS_GUEST_RFLAGS, snap->rflags);

	/* ----------------------------------------------------------
	 * Step 5: Restore segment registers.
	 * ---------------------------------------------------------- */
	snap_restore_seg(&snap->cs,
			 VMCS_GUEST_CS_SELECTOR, VMCS_GUEST_CS_BASE,
			 VMCS_GUEST_CS_LIMIT,   VMCS_GUEST_CS_AR);
	snap_restore_seg(&snap->ss,
			 VMCS_GUEST_SS_SELECTOR, VMCS_GUEST_SS_BASE,
			 VMCS_GUEST_SS_LIMIT,   VMCS_GUEST_SS_AR);
	snap_restore_seg(&snap->ds,
			 VMCS_GUEST_DS_SELECTOR, VMCS_GUEST_DS_BASE,
			 VMCS_GUEST_DS_LIMIT,   VMCS_GUEST_DS_AR);
	snap_restore_seg(&snap->es,
			 VMCS_GUEST_ES_SELECTOR, VMCS_GUEST_ES_BASE,
			 VMCS_GUEST_ES_LIMIT,   VMCS_GUEST_ES_AR);
	snap_restore_seg(&snap->fs,
			 VMCS_GUEST_FS_SELECTOR, VMCS_GUEST_FS_BASE,
			 VMCS_GUEST_FS_LIMIT,   VMCS_GUEST_FS_AR);
	snap_restore_seg(&snap->gs,
			 VMCS_GUEST_GS_SELECTOR, VMCS_GUEST_GS_BASE,
			 VMCS_GUEST_GS_LIMIT,   VMCS_GUEST_GS_AR);
	snap_restore_seg(&snap->ldtr,
			 VMCS_GUEST_LDTR_SELECTOR, VMCS_GUEST_LDTR_BASE,
			 VMCS_GUEST_LDTR_LIMIT,   VMCS_GUEST_LDTR_AR);
	snap_restore_seg(&snap->tr,
			 VMCS_GUEST_TR_SELECTOR, VMCS_GUEST_TR_BASE,
			 VMCS_GUEST_TR_LIMIT,   VMCS_GUEST_TR_AR);

	/* ----------------------------------------------------------
	 * Step 6: Restore descriptor tables.
	 * ---------------------------------------------------------- */
	phantom_vmcs_write64(VMCS_GUEST_GDTR_BASE,  snap->gdtr_base);
	phantom_vmcs_write32(VMCS_GUEST_GDTR_LIMIT, snap->gdtr_limit);
	phantom_vmcs_write64(VMCS_GUEST_IDTR_BASE,  snap->idtr_base);
	phantom_vmcs_write32(VMCS_GUEST_IDTR_LIMIT, snap->idtr_limit);

	/* ----------------------------------------------------------
	 * Step 7: Restore guest MSRs.
	 * ---------------------------------------------------------- */
	phantom_vmcs_write64(VMCS_GUEST_IA32_EFER,       snap->efer);
	phantom_vmcs_write64(VMCS_GUEST_IA32_DEBUGCTL,   snap->debugctl);
	phantom_vmcs_write64(VMCS_GUEST_IA32_PAT,        snap->pat);
	phantom_vmcs_write32(VMCS_GUEST_IA32_SYSENTER_CS,  snap->sysenter_cs);
	phantom_vmcs_write64(VMCS_GUEST_IA32_SYSENTER_ESP, snap->sysenter_esp);
	phantom_vmcs_write64(VMCS_GUEST_IA32_SYSENTER_EIP, snap->sysenter_eip);

	/* ----------------------------------------------------------
	 * Step 8: Restore guest interrupt / activity state.
	 * ---------------------------------------------------------- */
	phantom_vmcs_write32(VMCS_GUEST_INTR_STATE,    snap->interruptibility);
	phantom_vmcs_write32(VMCS_GUEST_ACTIVITY_STATE, snap->activity_state);

	/* ----------------------------------------------------------
	 * Step 9: Restore GPRs into guest_regs.
	 *
	 * RSP, RIP, RFLAGS were already written to the VMCS above.
	 * ---------------------------------------------------------- */
	state->guest_regs.rax = snap->rax;
	state->guest_regs.rbx = snap->rbx;
	state->guest_regs.rcx = snap->rcx;
	state->guest_regs.rdx = snap->rdx;
	state->guest_regs.rsi = snap->rsi;
	state->guest_regs.rdi = snap->rdi;
	state->guest_regs.rbp = snap->rbp;
	state->guest_regs.r8  = snap->r8;
	state->guest_regs.r9  = snap->r9;
	state->guest_regs.r10 = snap->r10;
	state->guest_regs.r11 = snap->r11;
	state->guest_regs.r12 = snap->r12;
	state->guest_regs.r13 = snap->r13;
	state->guest_regs.r14 = snap->r14;
	state->guest_regs.r15 = snap->r15;

	/* ----------------------------------------------------------
	 * Step 10: XRSTOR extended registers from aligned buffer.
	 *
	 * Must be bracketed with kernel_fpu_begin/end so the kernel
	 * saves/restores its own FPU state around our XRSTOR.
	 * ---------------------------------------------------------- */
	if (state->xsave_area_aligned) {
		u32 xcr0_lo = (u32)state->xcr0_supported;
		u32 xcr0_hi = (u32)(state->xcr0_supported >> 32);

		kernel_fpu_begin();
		asm volatile(
			"xrstor64 %0"
			:: "m" (*(const u8 *)state->xsave_area_aligned),
			   "a" (xcr0_lo), "d" (xcr0_hi)
			: "memory");
		kernel_fpu_end();
	}

	return 0;
	/* Caller does VMRESUME */
}
EXPORT_SYMBOL_GPL(phantom_snapshot_restore);
