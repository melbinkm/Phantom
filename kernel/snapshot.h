// SPDX-License-Identifier: GPL-2.0-only
/*
 * snapshot.h — guest state snapshot for phantom.ko
 *
 * struct phantom_snapshot captures the complete guest architectural state
 * at a snapshot point.  phantom_snapshot_create() saves the state;
 * phantom_snapshot_restore() reinstates it and resets the EPT dirty list.
 *
 * The snapshot covers:
 *   - All 15 GPRs (RSP/RIP kept in VMCS; saved separately here too)
 *   - VMCS guest control registers (CR0, CR3, CR4, DR7)
 *   - VMCS guest segment registers (CS, SS, DS, ES, FS, GS, LDTR, TR)
 *   - VMCS guest descriptor tables (GDTR, IDTR)
 *   - VMCS guest MSRs (EFER, DEBUGCTL, PAT, SYSENTER_*)
 *   - VMCS guest interrupt/activity state
 *   - Extended register state via XSAVE area (in phantom_vmx_cpu_state)
 *
 * The XSAVE area is NOT stored inside this struct; it is stored in the
 * separately allocated and 64-byte aligned xsave_area_aligned pointer
 * within struct phantom_vmx_cpu_state.  snapshot_create/restore call
 * XSAVE/XRSTOR directly on that buffer.
 */
#ifndef PHANTOM_SNAPSHOT_H
#define PHANTOM_SNAPSHOT_H

#include <linux/types.h>

/*
 * struct phantom_seg_reg — VMCS encoding of one segment register.
 *
 * Covers the four VMCS sub-fields: selector, base, limit, access rights.
 * Used for CS, SS, DS, ES, FS, GS, LDTR, TR.
 */
struct phantom_seg_reg {
	u16	sel;	/* selector           */
	u32	limit;	/* segment limit      */
	u32	ar;	/* access rights      */
	u64	base;	/* segment base       */
};

/*
 * struct phantom_snapshot — complete guest architectural state.
 *
 * Allocated inline in struct phantom_vmx_cpu_state (no heap pointer).
 * ~200 bytes; fits comfortably in a cache line group.
 *
 * Field ordering: GPRs first (used most often in hot path), then VMCS
 * fields in the same order they are read/written by snapshot_create
 * and snapshot_restore.
 */
struct phantom_snapshot {
	/* General-purpose registers (from phantom_guest_regs + VMCS) */
	u64	rax;
	u64	rbx;
	u64	rcx;
	u64	rdx;
	u64	rsi;
	u64	rdi;
	u64	rbp;
	u64	r8;
	u64	r9;
	u64	r10;
	u64	r11;
	u64	r12;
	u64	r13;
	u64	r14;
	u64	r15;

	/* Instruction pointer, stack pointer, flags */
	u64	rip;
	u64	rsp;
	u64	rflags;

	/* VMCS guest control registers */
	u64	cr0;
	u64	cr3;
	u64	cr4;
	u64	dr7;

	/* VMCS guest segment registers */
	struct phantom_seg_reg	cs;
	struct phantom_seg_reg	ss;
	struct phantom_seg_reg	ds;
	struct phantom_seg_reg	es;
	struct phantom_seg_reg	fs;
	struct phantom_seg_reg	gs;
	struct phantom_seg_reg	ldtr;
	struct phantom_seg_reg	tr;

	/* VMCS guest descriptor tables */
	u64	gdtr_base;
	u32	gdtr_limit;
	u64	idtr_base;
	u32	idtr_limit;

	/* VMCS guest MSRs */
	u64	efer;
	u64	debugctl;
	u64	pat;
	u32	sysenter_cs;
	u64	sysenter_esp;
	u64	sysenter_eip;

	/* VMCS guest interrupt / activity state */
	u32	interruptibility;
	u32	activity_state;

	/* Set to true after first phantom_snapshot_create() */
	bool	valid;
};

/* ------------------------------------------------------------------
 * Forward declaration
 * ------------------------------------------------------------------ */
struct phantom_vmx_cpu_state;

/* ------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------ */

/**
 * phantom_snapshot_create - Capture the current guest architectural state.
 * @state: Per-CPU VMX state (VMCS must be current on this CPU).
 *
 * Saves all GPRs, VMCS guest-state fields, and extended register state
 * (XSAVE) to the snapshot in state->snap and state->xsave_area_aligned.
 * Then marks all EPT RAM pages read-only and resets dirty_count to 0.
 *
 * Must be called from VMX-root context on the vCPU's CPU.
 * Must NOT be called on the hot path — it touches all VMCS fields.
 *
 * Returns 0 on success, negative errno on failure.
 */
int phantom_snapshot_create(struct phantom_vmx_cpu_state *state);

/**
 * phantom_snapshot_restore - Restore guest state to the last snapshot.
 * @state: Per-CPU VMX state (VMCS must be current on this CPU).
 *
 * Algorithm:
 *   1. Walk dirty list — reset each EPT PTE to orig_hpa | RO, return
 *      private page to pool.
 *   2. Reset dirty_count = 0.
 *   3. Issue one batched single-context INVEPT.
 *   4. Restore all VMCS guest-state fields from snap.
 *   5. Restore GPRs into state->guest_regs.
 *   6. XRSTOR extended registers from xsave_area_aligned.
 *
 * Caller must VMRESUME after this returns 0.
 *
 * Must be called from VMX-root context on the vCPU's CPU.
 * Hot-path safe: no printk, no sleeping, no dynamic allocation.
 *
 * Returns 0 on success, -EINVAL if no valid snapshot exists.
 */
int phantom_snapshot_restore(struct phantom_vmx_cpu_state *state);

#endif /* PHANTOM_SNAPSHOT_H */
