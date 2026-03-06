// SPDX-License-Identifier: GPL-2.0-only
/*
 * hypercall.c — VMCALL hypercall dispatch for phantom.ko
 *
 * Two namespaces are supported:
 *
 *   1. Legacy Phantom hypercalls (task 1.x):
 *        0 = PHANTOM_HC_GET_HOST_DATA  — return GUEST_DATA_GPA in RBX
 *        1 = PHANTOM_HC_SUBMIT_RESULT  — store RBX as run_result_data
 *
 *   2. kAFL/Nyx ABI (task 2.1+, RAX in 0x11a–0x121):
 *        GET_PAYLOAD    (0x11a) — register fuzz payload GPA
 *        SUBMIT_CR3     (0x11b) — register guest CR3 for PT filtering
 *        ACQUIRE        (0x11c) — take snapshot (first call) or continue
 *        RELEASE        (0x11d) — end iteration normally, restore snapshot
 *        PANIC          (0x11e) — end iteration as crash, restore snapshot
 *        KASAN          (0x11f) — end iteration as KASAN, restore snapshot
 *        PRINTF         (0x120) — read guest string, emit via pr_info
 *        SUBMIT_PANIC   (0x121) — register guest panic handler GPA
 *
 * Hot-path rules:
 *   - ACQUIRE/RELEASE/PANIC/KASAN are on the hot path.
 *   - No printk, no kmalloc(GFP_KERNEL), no schedule().
 *   - trace_printk only inside PHANTOM_DEBUG guards.
 *   - PRINTF uses pr_info (not on the performance hot path).
 *
 * EPT memory access helpers (phantom_gpa_to_kva, phantom_copy_from_guest,
 * phantom_copy_to_guest) are defined here to keep all GPA↔HVA logic
 * in one file.  They walk the EPT to find the backing HPA and use
 * phys_to_virt() to get the kernel virtual address.
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/page.h>
#include <asm/io.h>

#include "vmx_core.h"
#include "hypercall.h"
#include "ept.h"
#include "snapshot.h"
#include "interface.h"
#include "phantom.h"
#include "debug.h"

/* ------------------------------------------------------------------
 * EPT guest memory access helpers
 *
 * These walk the 4-level EPT to find the HPA for a GPA, then access
 * the backing memory via phys_to_virt().
 *
 * All three helpers are hot-path safe: no allocation, no sleeping,
 * no printk.  They only call phantom_ept_lookup_pte() (a pure walk).
 * ------------------------------------------------------------------ */

/**
 * phantom_gpa_to_kva - Translate a GPA to a host kernel VA via EPT walk.
 * @state: Per-CPU VMX state.
 * @gpa:   Guest physical address.
 *
 * Returns kernel VA, or NULL if GPA is not backed by RAM in the EPT.
 */
void *phantom_gpa_to_kva(struct phantom_vmx_cpu_state *state, u64 gpa)
{
	u64 *pte;
	u64 hpa;

	pte = phantom_ept_lookup_pte(&state->ept, gpa);
	if (!pte || !(*pte & EPT_PTE_READ))
		return NULL;

	hpa = (*pte & EPT_PTE_HPA_MASK) + (gpa & ~PAGE_MASK);
	return phys_to_virt(hpa);
}

/**
 * phantom_copy_from_guest - Copy bytes from guest physical memory.
 * @state: Per-CPU VMX state.
 * @gpa:   Source GPA (may span multiple pages).
 * @dst:   Host kernel destination buffer.
 * @len:   Number of bytes to copy.
 *
 * Returns 0 on success, -EFAULT if any page is not backed by RAM.
 */
int phantom_copy_from_guest(struct phantom_vmx_cpu_state *state,
			    u64 gpa, void *dst, size_t len)
{
	u8 *out = dst;
	size_t remaining = len;

	while (remaining > 0) {
		u64 page_base = gpa & PAGE_MASK;
		size_t page_off = gpa & ~PAGE_MASK;
		size_t chunk = PAGE_SIZE - page_off;
		void *src_va;

		if (chunk > remaining)
			chunk = remaining;

		src_va = phantom_gpa_to_kva(state, page_base);
		if (!src_va)
			return -EFAULT;

		memcpy(out, (u8 *)src_va + page_off, chunk);
		out += chunk;
		gpa += chunk;
		remaining -= chunk;
	}

	return 0;
}

/**
 * phantom_copy_to_guest - Copy bytes from kernel buffer to guest RAM.
 * @state: Per-CPU VMX state.
 * @gpa:   Destination GPA (may span multiple pages).
 * @src:   Host kernel source buffer.
 * @len:   Number of bytes to copy.
 *
 * Returns 0 on success, -EFAULT if any page is not backed by RAM.
 */
int phantom_copy_to_guest(struct phantom_vmx_cpu_state *state,
			  u64 gpa, const void *src, size_t len)
{
	const u8 *in = src;
	size_t remaining = len;

	while (remaining > 0) {
		u64 page_base = gpa & PAGE_MASK;
		size_t page_off = gpa & ~PAGE_MASK;
		size_t chunk = PAGE_SIZE - page_off;
		void *dst_va;

		if (chunk > remaining)
			chunk = remaining;

		dst_va = phantom_gpa_to_kva(state, page_base);
		if (!dst_va)
			return -EFAULT;

		memcpy((u8 *)dst_va + page_off, in, chunk);
		in += chunk;
		gpa += chunk;
		remaining -= chunk;
	}

	return 0;
}

/* ------------------------------------------------------------------
 * Shared-memory payload injection
 *
 * Called from ACQUIRE handler (on first call) and from RUN_ITERATION
 * ioctl before VMRESUME.  Copies the host-side payload from shared_mem
 * into guest RAM at payload_gpa.
 *
 * Hot-path safe: phantom_copy_to_guest has no sleeping, no allocation.
 * ------------------------------------------------------------------ */
static int inject_payload(struct phantom_vmx_cpu_state *state)
{
	struct phantom_shared_mem *sm;
	u32 plen;
	int ret;

	if (!state->shared_mem || !state->payload_gpa)
		return 0;

	sm = (struct phantom_shared_mem *)state->shared_mem;
	plen = sm->payload_len;
	if (plen > PHANTOM_PAYLOAD_MAX)
		plen = PHANTOM_PAYLOAD_MAX;
	if (plen == 0)
		return 0;

	ret = phantom_copy_to_guest(state, state->payload_gpa,
				    sm->payload, plen);
	return ret;
}

/* ------------------------------------------------------------------
 * TSS dirty-list verification (Task 3.2)
 *
 * Called from HC_RELEASE after the dirty list is fully populated but
 * BEFORE phantom_snapshot_restore() resets dirty_count to 0.
 *
 * Hot-path rules: no printk, no sleeping, no allocation.
 * Uses pr_warn_ratelimited (not on the true hot path — once per iter
 * and only when verification fails, which is a diagnostic case).
 * ------------------------------------------------------------------ */

/*
 * phantom_verify_tss_dirty - Check TSS page is in the CoW dirty list.
 * @state: Per-CPU VMX state.
 *
 * The TSS GPA is derived from VMCS_GUEST_TR_BASE (page-aligned).
 * Must be called from VMX-root context (VMCS is current).
 * Sets state->tss_dirty_verified = true if found.
 */
static void phantom_verify_tss_dirty(struct phantom_vmx_cpu_state *state)
{
	u64 tss_base = phantom_vmcs_read64(VMCS_GUEST_TR_BASE);
	u64 tss_gpa  = tss_base & PAGE_MASK;
	bool found   = false;
	u32 i;

	for (i = 0; i < state->dirty_count; i++) {
		if (state->dirty_list[i].gpa == tss_gpa) {
			found = true;
			break;
		}
	}

	if (!found) {
		pr_warn_ratelimited(
			"phantom: TSS GPA 0x%llx NOT in dirty list "
			"(dirty_count=%u iter=%u)\n",
			tss_gpa, state->dirty_count, state->cow_iteration);
	}

	state->tss_dirty_verified = found;
}

/*
 * phantom_check_tss_rsp0_restored - Verify TSS RSP0 matches snapshot.
 * @state: Per-CPU VMX state.
 *
 * Called after phantom_snapshot_restore() to confirm the TSS page was
 * correctly restored.  Reads RSP0 (offset 4 in x86-64 TSS layout) from
 * guest memory and compares to tss_rsp0_snapshot.
 *
 * Must be called from VMX-root context (EPT is active).
 */
static void phantom_check_tss_rsp0_restored(struct phantom_vmx_cpu_state *state)
{
	u64 tss_base = phantom_vmcs_read64(VMCS_GUEST_TR_BASE);
	u64 rsp0_gpa = (tss_base & PAGE_MASK) + 4;
	u64 *rsp0_kva;

	rsp0_kva = phantom_gpa_to_kva(state, rsp0_gpa);
	if (!rsp0_kva) {
		state->tss_rsp0_restored = 0;
		return;
	}

	state->tss_rsp0_restored = *rsp0_kva;

	if (state->tss_rsp0_restored != state->tss_rsp0_snapshot) {
		pr_warn_ratelimited(
			"phantom: TSS RSP0 mismatch after restore: "
			"snap=0x%llx restored=0x%llx\n",
			state->tss_rsp0_snapshot, state->tss_rsp0_restored);
	}
}

/*
 * phantom_cache_iter_exit_regs - Cache VMCS guest state at iteration end.
 * @state: Per-CPU VMX state.
 *
 * Must be called from VMX-root context (VMCS is current) before any
 * snapshot_restore() call resets the VMCS guest-state fields.
 */
static void phantom_cache_iter_exit_regs(struct phantom_vmx_cpu_state *state)
{
	state->last_guest_rip    = phantom_vmcs_read64(VMCS_GUEST_RIP);
	state->last_guest_rflags = phantom_vmcs_read64(VMCS_GUEST_RFLAGS);
	state->last_guest_rsp    = phantom_vmcs_read64(VMCS_GUEST_RSP);
	state->last_guest_cr3    = phantom_vmcs_read64(VMCS_GUEST_CR3);
}

/* ------------------------------------------------------------------
 * kAFL/Nyx ABI hypercall handlers
 * ------------------------------------------------------------------ */

/*
 * handle_get_payload (0x11a):
 *   Guest RBX = payload GPA (must be RAM, must fit PHANTOM_PAYLOAD_SIZE).
 *   Host: validate GPA, store as state->payload_gpa.
 *   Returns 0 in guest RAX.
 */
static int handle_get_payload(struct phantom_vmx_cpu_state *state)
{
	u64 gpa = state->guest_regs.rbx;
	const struct phantom_gpa_region *region;

	region = phantom_ept_classify_gpa(gpa);
	if (region->type != PHANTOM_GPA_RAM) {
		state->run_result = PHANTOM_RESULT_HYPERCALL_ERROR;
		return -EINVAL;
	}

	/*
	 * Verify the full payload buffer fits within RAM.
	 * PHANTOM_PAYLOAD_MAX is 64KB; we check the end GPA too.
	 */
	region = phantom_ept_classify_gpa(gpa + PHANTOM_PAYLOAD_MAX - 1);
	if (region->type != PHANTOM_GPA_RAM) {
		state->run_result = PHANTOM_RESULT_HYPERCALL_ERROR;
		return -EINVAL;
	}

	state->payload_gpa = gpa;
	state->guest_regs.rax = 0;
	return 0;
}

/*
 * handle_submit_cr3 (0x11b):
 *   Guest RBX = guest CR3 value for PT IP filtering.
 *   Host: store as state->pt_cr3.
 *   Returns 0 in guest RAX.
 */
static int handle_submit_cr3(struct phantom_vmx_cpu_state *state)
{
	state->pt_cr3 = state->guest_regs.rbx;
	state->guest_regs.rax = 0;
	return 0;
}

/*
 * handle_acquire (0x11c):
 *   First call: take snapshot via phantom_snapshot_create().
 *   Subsequent calls: snapshot already taken — resume from snapshot.
 *   Injects payload into guest RAM if payload_gpa is set.
 *   Sets state->iteration_active = true.
 *   Returns 0 in guest RAX.
 */
static int handle_acquire(struct phantom_vmx_cpu_state *state)
{
	int ret;

	if (!state->snap_acquired) {
		u64 tss_base, rsp0_gpa;
		u64 *rsp0_kva;

		/*
		 * First ACQUIRE: initialise the kernel-side guest heap pointer
		 * to HEAP_BASE before creating the snapshot.  This value will
		 * be restored on every subsequent snapshot_restore() so each
		 * fuzzing iteration starts with a clean bump allocator.
		 */
		state->guest_heap_ptr = PHANTOM_GUEST_HEAP_BASE;

		ret = phantom_snapshot_create(state);
		if (ret) {
			state->run_result = PHANTOM_RESULT_HYPERCALL_ERROR;
			return ret;
		}
		state->snap_acquired = true;
		state->snap_taken = true;

		/*
		 * Task 3.2: Capture TSS RSP0 at snapshot time so we can verify
		 * it is correctly restored after each iteration.  RSP0 is at
		 * byte offset 4 of the x86-64 TSS (a u64 aligned to 4 bytes).
		 */
		tss_base = phantom_vmcs_read64(VMCS_GUEST_TR_BASE);
		rsp0_gpa = (tss_base & PAGE_MASK) + 4;
		rsp0_kva = phantom_gpa_to_kva(state, rsp0_gpa);
		state->tss_rsp0_snapshot = rsp0_kva ? *rsp0_kva : 0;

		/* Signal Class B guest boot success to host dmesg for test detection. */
		if (state->class_b)
			pr_info("phantom-harness: init\n");
	}

	/* Reset per-iteration TSS verification flag. */
	state->tss_dirty_verified = false;

	/*
	 * Inject current payload into guest RAM before the guest
	 * proceeds past the ACQUIRE point.
	 */
	if (state->payload_gpa) {
		ret = inject_payload(state);
		if (ret) {
#ifdef PHANTOM_DEBUG
			trace_printk("PHANTOM ACQUIRE payload inject "
				     "failed gpa=0x%llx ret=%d\n",
				     state->payload_gpa, ret);
#endif
		}
	}

	state->iteration_active = true;
	state->guest_regs.rax = 0;
	return 0;
}

/*
 * handle_release (0x11d):
 *   Normal end-of-iteration.  Set result OK, restore snapshot.
 *   The guest never returns from RELEASE — it resumes from the
 *   snapshot point (after ACQUIRE) on the next RUN_ITERATION call.
 */
static int handle_release(struct phantom_vmx_cpu_state *state)
{
	int ret;

	state->run_result = PHANTOM_RESULT_OK;
	state->crash_addr = 0;
	state->iteration_active = false;
	state->iter_count++;

	if (state->shared_mem) {
		struct phantom_shared_mem *sm =
			(struct phantom_shared_mem *)state->shared_mem;
		sm->status = PHANTOM_RESULT_OK;
		sm->crash_addr = 0;
	}

	/*
	 * Task 3.2: Cache VMCS guest-state before snapshot_restore() resets
	 * the VMCS fields.  These are used by PHANTOM_IOCTL_GET_ITER_STATE.
	 */
	phantom_cache_iter_exit_regs(state);

	/*
	 * Task 3.2: Verify TSS page appears in the dirty list for this
	 * iteration, BEFORE snapshot_restore() resets dirty_count to 0.
	 * Only meaningful when CoW is active (snap_acquired = true).
	 */
	if (state->snap_acquired && state->dirty_list)
		phantom_verify_tss_dirty(state);

	/*
	 * Restore snapshot: resets dirty EPT pages, restores VMCS,
	 * restores GPRs, XRSTOR extended state, issues batched INVEPT.
	 * After this returns, the caller does VMRESUME from snap->rip.
	 */
	ret = phantom_snapshot_restore(state);

	/*
	 * Task 3.2: After restore, verify TSS RSP0 matches the snapshot value.
	 * This catches TSS restore failures (e.g., dirty list missed the page).
	 */
	if (state->snap_acquired)
		phantom_check_tss_rsp0_restored(state);

	return ret;
}

/*
 * handle_panic (0x11e):
 *   Guest detected a crash.  RCX = crash address.
 *   Set result = CRASH, store crash_addr, restore snapshot.
 */
static int handle_panic(struct phantom_vmx_cpu_state *state)
{
	state->run_result = PHANTOM_RESULT_CRASH;
	state->crash_addr = state->guest_regs.rcx;
	state->iteration_active = false;
	state->iter_count++;

	if (state->shared_mem) {
		struct phantom_shared_mem *sm =
			(struct phantom_shared_mem *)state->shared_mem;
		sm->status = PHANTOM_RESULT_CRASH;
		sm->crash_addr = state->crash_addr;
	}

	/* Task 3.2: Cache VMCS state before restore resets it. */
	phantom_cache_iter_exit_regs(state);

	return phantom_snapshot_restore(state);
}

/*
 * handle_kasan (0x11f):
 *   Guest KASAN violation.  No crash address from this hypercall.
 *   Set result = KASAN, restore snapshot.
 */
static int handle_kasan(struct phantom_vmx_cpu_state *state)
{
	state->run_result = PHANTOM_RESULT_KASAN;
	state->crash_addr = 0;
	state->iteration_active = false;
	state->iter_count++;

	if (state->shared_mem) {
		struct phantom_shared_mem *sm =
			(struct phantom_shared_mem *)state->shared_mem;
		sm->status = PHANTOM_RESULT_KASAN;
		sm->crash_addr = 0;
	}

	/* Task 3.2: Cache VMCS state before restore resets it. */
	phantom_cache_iter_exit_regs(state);

	return phantom_snapshot_restore(state);
}

/*
 * handle_printf (0x120):
 *   Guest RBX = GPA of NUL-terminated string (max 256 bytes).
 *   Read the string from guest RAM and emit via pr_info.
 *   NOT on the hot path — PRINTF is for debugging/tracing only.
 */
static int handle_printf(struct phantom_vmx_cpu_state *state)
{
	u64 str_gpa = state->guest_regs.rbx;
	char buf[PHANTOM_PRINTF_MAX_LEN + 1];
	size_t i;
	int ret;

	memset(buf, 0, sizeof(buf));

	/*
	 * Read bytes one page at a time up to PHANTOM_PRINTF_MAX_LEN.
	 * Stop early if we find a NUL terminator.
	 */
	for (i = 0; i < PHANTOM_PRINTF_MAX_LEN; i++) {
		u8 ch;

		ret = phantom_copy_from_guest(state, str_gpa + i, &ch, 1);
		if (ret)
			break;
		if (ch == '\0')
			break;
		buf[i] = (char)ch;
	}
	buf[PHANTOM_PRINTF_MAX_LEN] = '\0';

	pr_info("phantom[guest]: %s\n", buf);
	state->guest_regs.rax = 0;
	return 0;
}

/*
 * handle_submit_panic (0x121):
 *   Guest RBX = GPA of guest panic handler.
 *   Host stores it for future use (e.g., to inject a controlled panic).
 */
static int handle_submit_panic(struct phantom_vmx_cpu_state *state)
{
	state->panic_handler_gpa = state->guest_regs.rbx;
	state->guest_regs.rax = 0;
	return 0;
}

/* ------------------------------------------------------------------
 * Main hypercall dispatch
 * ------------------------------------------------------------------ */

/**
 * phantom_handle_vmcall - Dispatch a VMCALL VM exit.
 * @state: Per-CPU VMX state; guest_regs.rax holds the hypercall number.
 *
 * Routes to the nyx_api handler when RAX is in 0x11a–0x121, otherwise
 * uses the legacy PHANTOM_HC_* dispatch path.
 *
 * Returns 0 on success (caller should VMRESUME or check run_result),
 * -EINVAL on unknown hypercall.
 */
int phantom_handle_vmcall(struct phantom_vmx_cpu_state *state)
{
	u64 nr = state->guest_regs.rax;
	u64 guest_rip;
	u32 instr_len;
	int ret = 0;

	PHANTOM_TRACE_HYPERCALL(state->cpu, nr);

	/*
	 * Route kAFL/Nyx hypercalls (0x11a–0x121) to the nyx_api handler.
	 * For RELEASE/PANIC/KASAN, the snapshot_restore() resets RIP to
	 * snap->rip, so we do NOT advance RIP here — snapshot_restore()
	 * does that via the VMCS write in phantom_snapshot_restore().
	 *
	 * For all other nyx_api hypercalls that return to the guest, we
	 * advance RIP by the VMCALL instruction length below.
	 */
	if (nr >= HYPERCALL_KAFL_FIRST && nr <= HYPERCALL_KAFL_LAST) {
		bool advances_rip = true;

		switch (nr) {
		case HYPERCALL_KAFL_GET_PAYLOAD:
			ret = handle_get_payload(state);
			break;
		case HYPERCALL_KAFL_SUBMIT_CR3:
			ret = handle_submit_cr3(state);
			break;
		case HYPERCALL_KAFL_ACQUIRE:
			ret = handle_acquire(state);
			break;
		case HYPERCALL_KAFL_RELEASE:
			/*
			 * RELEASE calls phantom_snapshot_restore() which
			 * restores RIP to snap->rip.  Do NOT advance RIP.
			 */
			advances_rip = false;
			ret = handle_release(state);
			break;
		case HYPERCALL_KAFL_PANIC:
			/* Same: snapshot_restore sets the RIP. */
			advances_rip = false;
			ret = handle_panic(state);
			break;
		case HYPERCALL_KAFL_KASAN:
			/* Same: snapshot_restore sets the RIP. */
			advances_rip = false;
			ret = handle_kasan(state);
			break;
		case HYPERCALL_KAFL_PRINTF:
			ret = handle_printf(state);
			break;
		case HYPERCALL_KAFL_SUBMIT_PANIC:
			ret = handle_submit_panic(state);
			break;
		default:
			/* Should not reach here given range check above */
			state->run_result = PHANTOM_RESULT_HYPERCALL_ERROR;
			return -EINVAL;
		}

		if (advances_rip && ret == 0) {
			instr_len = phantom_vmcs_read32(VMCS_RO_EXIT_INSTR_LEN);
			if (instr_len == 0)
				instr_len = 3;
			guest_rip = phantom_vmcs_read64(VMCS_GUEST_RIP);
			phantom_vmcs_write64(VMCS_GUEST_RIP,
					     guest_rip + instr_len);
		}
		return ret;
	}

	/*
	 * Legacy Phantom hypercall dispatch.
	 */
	switch (nr) {
	case PHANTOM_HC_GET_HOST_DATA:
		/*
		 * Tell the guest where its data buffer is.
		 * Return GUEST_DATA_GPA in guest RBX.
		 */
		state->guest_regs.rbx = GUEST_DATA_GPA;
		break;

	case PHANTOM_HC_SUBMIT_RESULT:
		/*
		 * Guest has computed a result and placed it in RBX.
		 * Save it and mark the run as complete.
		 */
		state->run_result_data = state->guest_regs.rbx;
		state->run_result = PHANTOM_RESULT_OK;
		break;

	default:
		/*
		 * Unknown hypercall — treat as a guest error.
		 * Do not advance RIP.
		 */
		state->run_result = PHANTOM_RESULT_CRASH;
		return -EINVAL;
	}

	/*
	 * Advance guest RIP past the VMCALL instruction.
	 * VMCALL is always 3 bytes (0F 01 C1); read VMCS length to be safe.
	 */
	instr_len = phantom_vmcs_read32(VMCS_RO_EXIT_INSTR_LEN);
	if (instr_len == 0)
		instr_len = 3;

	guest_rip = phantom_vmcs_read64(VMCS_GUEST_RIP);
	phantom_vmcs_write64(VMCS_GUEST_RIP, guest_rip + instr_len);

	return 0;
}
