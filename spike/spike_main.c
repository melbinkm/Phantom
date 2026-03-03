// SPDX-License-Identifier: GPL-2.0-only
/*
 * spike_main.c — VMX feasibility spike for Project Phantom.
 *
 * Demonstrates:
 *   1. VMXON on a single CPU core (CPU 0 via smp_call_function_single).
 *   2. Minimal VMCS setup and VMLAUNCH of a trivial guest.
 *   3. VMCALL exit (reason 18) — host logs and resumes guest.
 *   4. EPT violation (reason 48) — host logs GPA + qualification, aborts.
 *   5. VMXOFF on module unload.
 *   6. Intentional panic path (spike_trigger_panic) to validate kdump.
 *
 * Design notes:
 *   - All VMX operations are pinned to CPU 0 via smp_call_function_single().
 *   - A dedicated 4KB host exit stack is allocated per logical processor
 *     to ensure the VM exit handler executes on a known-good stack.
 *   - The exit handler trampoline (spike_vmexit_trampoline) is written in
 *     inline asm so we can guarantee it is reached directly as the host RIP
 *     without any prologue clobbering registers before saving state.
 *   - VMCS host-state RSP points to the top of the exit stack; the trampoline
 *     calls spike_vmexit_dispatch() as a normal C call.
 *
 * Module parameters:
 *   trigger_panic=1  — on module load, after the guest run completes, call
 *                       BUG() to test kdump / serial console observability.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/printk.h>
#include <linux/string.h>

#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/desc.h>
#include <asm/segment.h>
#include <asm/tlbflush.h>       /* cr4_set_bits, cr4_clear_bits */
#include <asm/special_insns.h>  /* __read_cr4, __native_read_cr3, read_cr0 */
#include <asm/io.h>             /* virt_to_phys */
#include <asm/unwind_hints.h>   /* UNWIND_HINT_UNDEFINED */

#include "spike_vmx.h"
#include "spike_ept.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Project Phantom contributors");
MODULE_DESCRIPTION("VMX feasibility spike — throwaway spike code");
MODULE_VERSION("0.1");

static int trigger_panic;
module_param(trigger_panic, int, 0444);
MODULE_PARM_DESC(trigger_panic,
	"Set to 1 to trigger a deliberate BUG() after the guest run "
	"(tests kdump / serial console observability)");

/* -------------------------------------------------------------------------
 * Per-CPU spike state
 * ------------------------------------------------------------------------- */

#define SPIKE_EXIT_STACK_SIZE   PAGE_SIZE   /* 4KB host exit stack */
#define SPIKE_GUEST_STACK_PAGES 1           /* 1 page for guest stack */

/*
 * struct spike_vcpu — all state for one virtual CPU.
 *
 * Allocated in spike_vmx_init() and freed in spike_vmx_cleanup().
 */
struct spike_vcpu {
	/* VMXON region: 4KB, first 4 bytes = VMCS revision ID */
	unsigned long vmxon_region_va;   /* kernel virtual address */
	u64           vmxon_region_pa;   /* physical address        */

	/* VMCS region: 4KB, first 4 bytes = VMCS revision ID */
	unsigned long vmcs_region_va;
	u64           vmcs_region_pa;

	/* Dedicated host exit stack: 4KB, RSP = top of stack */
	unsigned long exit_stack_va;
	u64           exit_stack_top_pa; /* physical addr of last byte + 1 */

	/* EPT */
	struct spike_ept ept;

	/* State set by the exit dispatch handler */
	bool vmx_active;    /* true after successful VMXON  */
	bool vmcs_loaded;   /* true after successful VMPTRLD */
	bool should_exit;   /* exit dispatch sets true to stop re-entry  */
	int  exit_count;    /* total VM exits observed */
};

/* We use a single global vCPU for the spike (one CPU, one guest). */
static struct spike_vcpu *g_vcpu;

/* -------------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------------- */

/* Both functions called from the asm trampoline — non-static, __noreturn. */
void spike_vmexit_dispatch(struct spike_vcpu *vcpu);
__noreturn void spike_maybe_resume(struct spike_vcpu *vcpu);

/* Defined in the inline asm block below; referenced in spike_setup_vmcs(). */
extern void spike_vmexit_trampoline(void);

/*
 * Per-CPU saved host context for the longjmp-back from spike_maybe_resume
 * to spike_do_vmlaunch().  Saved before VMLAUNCH, restored on guest exit.
 */
static DEFINE_PER_CPU(u64, spike_saved_rsp);
static DEFINE_PER_CPU(u64, spike_saved_rbp);
static DEFINE_PER_CPU(u64, spike_saved_rip);

/* -------------------------------------------------------------------------
 * VM exit trampoline (assembly)
 *
 * When VMLAUNCH / VMRESUME transitions to guest, the CPU saves host state in
 * the VMCS.  On VM exit, the CPU restores host state from the VMCS and jumps
 * to host RIP — which is this trampoline.
 *
 * The trampoline runs on the host exit stack (RSP was loaded from VMCS
 * HOST_RSP).  We simply set up a C ABI call frame and invoke
 * spike_vmexit_dispatch().
 *
 * NOTE: We do NOT save/restore general-purpose registers here because the
 * spike does not care about guest register state.  A production hypervisor
 * would push all GPRs, pass a pointer to them, and pop them before VMRESUME.
 * ------------------------------------------------------------------------- */
asm(
".section .text\n"
".global spike_vmexit_trampoline\n"
"spike_vmexit_trampoline:\n"
	/*
	 * HOST_RSP was set to the top of the dedicated exit stack (a 4KB
	 * page, top = page_base + PAGE_SIZE).  The hardware restores RSP
	 * from HOST_RSP on VM exit, so RSP is 16-byte aligned when we
	 * arrive here.  Subtract 8 to re-align before the call instruction
	 * pushes the return address (ABI requires 16B alignment before call).
	 */
	"subq  $8, %rsp\n"
	/* Load g_vcpu pointer into rdi (first argument register). */
	"leaq  g_vcpu(%rip), %rdi\n"
	"movq  (%rdi), %rdi\n"
	"callq spike_vmexit_dispatch\n"
	/* spike_vmexit_dispatch sets vcpu->should_exit.  Now call
	 * spike_maybe_resume which either VMRESUMEs or does the
	 * longjmp-back.  spike_maybe_resume is marked __noreturn so
	 * objtool knows nothing follows this call. */
	"leaq  g_vcpu(%rip), %rdi\n"
	"movq  (%rdi), %rdi\n"
	"callq spike_maybe_resume\n"
	/* Unreachable: spike_maybe_resume never returns.
	 * ud2 terminates the sequence so objtool sees no fallthrough. */
	"ud2\n"
);

/* -------------------------------------------------------------------------
 * Read VMCS revision ID from IA32_VMX_BASIC MSR.
 * ------------------------------------------------------------------------- */
static u32 read_vmcs_revision(void)
{
	u64 basic;

	rdmsrl(MSR_IA32_VMX_BASIC, basic);
	return (u32)(basic & 0x7fffffffULL);
}

/* -------------------------------------------------------------------------
 * Helper: adjust a control value against an MSR capability pair.
 *
 * The two flavours of capability MSR (plain vs. TRUE) follow the same format:
 *   bits [31: 0] — bits that MUST be 1 (allowed0)
 *   bits [63:32] — bits that MAY  be 1 (allowed1)
 * ------------------------------------------------------------------------- */
static u32 vmx_adjust_ctl(u64 cap_msr, u32 desired)
{
	return adjust_vmx_controls(desired, cap_msr);
}

/* -------------------------------------------------------------------------
 * VMCS setup helpers
 *
 * spike_setup_vmcs() writes the minimal set of VMCS fields required for a
 * legal 64-bit guest launch.  Comments reference Intel SDM Vol. 3C §26.
 * ------------------------------------------------------------------------- */

/*
 * Read descriptor-table base/limit from the current GDT/IDT.
 */
static void get_gdt(u64 *base, u32 *limit)
{
	struct desc_ptr dt;

	native_store_gdt(&dt);
	*base  = dt.address;
	*limit = dt.size;
}

static void get_idt(u64 *base, u32 *limit)
{
	struct desc_ptr dt;

	store_idt(&dt);
	*base  = dt.address;
	*limit = dt.size;
}

/*
 * Read the base address of a segment descriptor from the GDT.
 * Used to populate host FS/GS/TR bases in the VMCS.
 */
static u64 segment_base(u16 selector)
{
	struct desc_ptr gdt;
	struct desc_struct *d;
	u64 base;

	native_store_gdt(&gdt);
	if ((selector & 0xfffc) == 0)
		return 0;
	d = (struct desc_struct *)(gdt.address + (selector & ~0x7));
	base = (u64)get_desc_base(d);
	/* For a 64-bit system TSS (16-byte entry) the high 32 bits are in the
	 * next 8-byte slot. */
	if (d->s == 0 && (d->type == 9 || d->type == 11)) {
		struct ldttss_desc *td = (struct ldttss_desc *)d;

		base |= ((u64)td->base3 << 32);
	}
	return base;
}

static int spike_setup_vmcs(struct spike_vcpu *vcpu)
{
	u64 cap_msr;
	u32 pin_ctl, proc1_ctl, proc2_ctl, exit_ctl, entry_ctl;
	u64 gdt_base, idt_base;
	u32 gdt_limit, idt_limit;
	u64 fs_base, gs_base, tr_base;
	u16 tr_sel;

	/* -----------------------------------------------------------------
	 * Control fields — adjust each against its capability MSR so that
	 * mandatory bits are set and reserved bits are cleared.
	 * ----------------------------------------------------------------- */

	/* Pin-based: no NMI-exiting, no preemption timer — simplest config */
	rdmsrl(MSR_IA32_VMX_TRUE_PINBASED_CTLS, cap_msr);
	pin_ctl = vmx_adjust_ctl(cap_msr, 0);
	vmcs_write32(VMCS_PIN_BASED_CTLS, pin_ctl);

	/* Primary proc-based: enable secondary controls (bit 31) */
	rdmsrl(MSR_IA32_VMX_TRUE_PROCBASED_CTLS, cap_msr);
	proc1_ctl = vmx_adjust_ctl(cap_msr, PRI_PROC_ENABLE_SECONDARY);
	vmcs_write32(VMCS_PRI_PROC_BASED_CTLS, proc1_ctl);

	/* Secondary proc-based: enable EPT (VPID optional) */
	rdmsrl(MSR_IA32_VMX_PROCBASED_CTLS2, cap_msr);
	proc2_ctl = vmx_adjust_ctl(cap_msr, SEC_PROC_ENABLE_EPT);
	/*
	 * Enable VPID only if the capability MSR allows it.
	 * In nested KVM environments it may not be supported.
	 */
	if ((cap_msr >> 32) & SEC_PROC_ENABLE_VPID)
		proc2_ctl |= SEC_PROC_ENABLE_VPID;
	vmcs_write32(VMCS_SEC_PROC_BASED_CTLS, proc2_ctl);

	/* VM-exit: host-address-space-size (64-bit host) + ack interrupt */
	rdmsrl(MSR_IA32_VMX_TRUE_EXIT_CTLS, cap_msr);
	exit_ctl = vmx_adjust_ctl(cap_msr,
				  VMEXIT_HOST_ADDR_SPACE_SIZE |
				  VMEXIT_ACK_INTERRUPT_ON_EXIT);
	vmcs_write32(VMCS_EXIT_CTLS, exit_ctl);

	/* VM-entry: IA-32e mode guest (64-bit guest) */
	rdmsrl(MSR_IA32_VMX_TRUE_ENTRY_CTLS, cap_msr);
	entry_ctl = vmx_adjust_ctl(cap_msr, VMENTRY_IA32E_MODE_GUEST);
	vmcs_write32(VMCS_ENTRY_CTLS, entry_ctl);

	/* Exception bitmap: 0 — don't intercept any exceptions */
	vmcs_write32(VMCS_EXCEPTION_BITMAP, 0);
	vmcs_write32(VMCS_PF_ERROR_CODE_MASK,  0);
	vmcs_write32(VMCS_PF_ERROR_CODE_MATCH, 0);

	/* -----------------------------------------------------------------
	 * EPT pointer and VPID
	 * ----------------------------------------------------------------- */
	vmcs_write64(VMCS_EPT_POINTER, vcpu->ept.eptp);
	vmcs_write32(VMCS_VPID, 1);

	/* -----------------------------------------------------------------
	 * Guest state — copy from current host state.
	 * The guest runs with the host's CR0/CR3/CR4, so virtual addresses
	 * resolve through the host page tables + EPT.
	 * ----------------------------------------------------------------- */
	vmcs_write64(VMCS_GUEST_CR0, read_cr0());
	vmcs_write64(VMCS_GUEST_CR3, __native_read_cr3());
	vmcs_write64(VMCS_GUEST_CR4, __read_cr4());
	vmcs_write64(VMCS_GUEST_DR7, 0x400);   /* reset value */

	/* Guest RIP = GPA of guest_code_start (identity-mapped) */
	vmcs_write64(VMCS_GUEST_RIP,    vcpu->ept.code_gpa);

	/* Guest RSP = top of stack (stack grows down; GPA + size = top) */
	vmcs_write64(VMCS_GUEST_RSP,
		     vcpu->ept.stack_gpa + SPIKE_GUEST_STACK_SIZE);

	/* RFLAGS: reserved bit 1 must be 1; IF cleared (no interrupts in guest) */
	vmcs_write64(VMCS_GUEST_RFLAGS, 0x2);

	/* -----------------------------------------------------------------
	 * Guest segment registers — 64-bit long-mode layout.
	 *
	 * CS: 64-bit code segment, DPL=0, present, accessed.
	 * SS/DS/ES/FS/GS: data, DPL=0, present, accessed, 32-bit granularity.
	 * ----------------------------------------------------------------- */
	/* CS */
	vmcs_write32(VMCS_GUEST_CS_SEL,   __KERNEL_CS);
	vmcs_write64(VMCS_GUEST_CS_BASE,  0);
	vmcs_write32(VMCS_GUEST_CS_LIMIT, 0xffffffff);
	vmcs_write32(VMCS_GUEST_CS_AR,    GUEST_CS_AR_64BIT);

	/* SS */
	vmcs_write32(VMCS_GUEST_SS_SEL,   __KERNEL_DS);
	vmcs_write64(VMCS_GUEST_SS_BASE,  0);
	vmcs_write32(VMCS_GUEST_SS_LIMIT, 0xffffffff);
	vmcs_write32(VMCS_GUEST_SS_AR,    GUEST_DS_AR_NORMAL);

	/* DS */
	vmcs_write32(VMCS_GUEST_DS_SEL,   __KERNEL_DS);
	vmcs_write64(VMCS_GUEST_DS_BASE,  0);
	vmcs_write32(VMCS_GUEST_DS_LIMIT, 0xffffffff);
	vmcs_write32(VMCS_GUEST_DS_AR,    GUEST_DS_AR_NORMAL);

	/* ES */
	vmcs_write32(VMCS_GUEST_ES_SEL,   __KERNEL_DS);
	vmcs_write64(VMCS_GUEST_ES_BASE,  0);
	vmcs_write32(VMCS_GUEST_ES_LIMIT, 0xffffffff);
	vmcs_write32(VMCS_GUEST_ES_AR,    GUEST_DS_AR_NORMAL);

	/* FS */
	vmcs_write32(VMCS_GUEST_FS_SEL,   0);
	vmcs_write64(VMCS_GUEST_FS_BASE,  0);
	vmcs_write32(VMCS_GUEST_FS_LIMIT, 0xffffffff);
	vmcs_write32(VMCS_GUEST_FS_AR,    GUEST_DS_AR_NORMAL);

	/* GS */
	vmcs_write32(VMCS_GUEST_GS_SEL,   0);
	vmcs_write64(VMCS_GUEST_GS_BASE,  0);
	vmcs_write32(VMCS_GUEST_GS_LIMIT, 0xffffffff);
	vmcs_write32(VMCS_GUEST_GS_AR,    GUEST_DS_AR_NORMAL);

	/* LDTR: unusable */
	vmcs_write32(VMCS_GUEST_LDTR_SEL,   0);
	vmcs_write64(VMCS_GUEST_LDTR_BASE,  0);
	vmcs_write32(VMCS_GUEST_LDTR_LIMIT, 0);
	vmcs_write32(VMCS_GUEST_LDTR_AR,    GUEST_LDTR_AR_UNUSABLE);

	/* TR: read actual task register selector and base */
	asm volatile("str %0" : "=r"(tr_sel));
	tr_base = segment_base(tr_sel);
	vmcs_write32(VMCS_GUEST_TR_SEL,   tr_sel);
	vmcs_write64(VMCS_GUEST_TR_BASE,  tr_base);
	vmcs_write32(VMCS_GUEST_TR_LIMIT, 0x67);  /* minimum busy TSS limit */
	vmcs_write32(VMCS_GUEST_TR_AR,    GUEST_TR_AR);

	/* GDTR / IDTR */
	get_gdt(&gdt_base, &gdt_limit);
	get_idt(&idt_base, &idt_limit);
	vmcs_write64(VMCS_GUEST_GDTR_BASE,  gdt_base);
	vmcs_write32(VMCS_GUEST_GDTR_LIMIT, gdt_limit);
	vmcs_write64(VMCS_GUEST_IDTR_BASE,  idt_base);
	vmcs_write32(VMCS_GUEST_IDTR_LIMIT, idt_limit);

	/* SYSENTER state: zero (not used in the spike) */
	vmcs_write32(VMCS_GUEST_SYSENTER_CS,  0);
	vmcs_write64(VMCS_GUEST_SYSENTER_ESP, 0);
	vmcs_write64(VMCS_GUEST_SYSENTER_EIP, 0);

	/* Guest interruptibility / activity */
	vmcs_write32(VMCS_GUEST_INTERRUPTIBILITY, 0);
	vmcs_write32(VMCS_GUEST_ACTIVITY_STATE,   0);  /* active */

	/* VMCS link pointer: ~0ULL = no VMCS shadowing */
	vmcs_write64(VMCS_GUEST_VMCS_LINK_PTR, ~0ULL);

	vmcs_write64(VMCS_GUEST_PENDING_DBG_EXCEP, 0);

	/* -----------------------------------------------------------------
	 * Host state — snapshot of the current CPU state.
	 * HOST_RSP / HOST_RIP are critical: RSP = exit stack top,
	 * RIP = spike_vmexit_trampoline.
	 * ----------------------------------------------------------------- */
	vmcs_write64(VMCS_HOST_CR0, read_cr0());
	vmcs_write64(VMCS_HOST_CR3, __native_read_cr3());
	vmcs_write64(VMCS_HOST_CR4, native_read_cr4());

	vmcs_write32(VMCS_HOST_CS_SEL, __KERNEL_CS);
	vmcs_write32(VMCS_HOST_SS_SEL, __KERNEL_DS);
	vmcs_write32(VMCS_HOST_DS_SEL, __KERNEL_DS);
	vmcs_write32(VMCS_HOST_ES_SEL, __KERNEL_DS);
	vmcs_write32(VMCS_HOST_FS_SEL, 0);
	vmcs_write32(VMCS_HOST_GS_SEL, 0);
	asm volatile("str %0" : "=r"(tr_sel));
	vmcs_write32(VMCS_HOST_TR_SEL, tr_sel);

	rdmsrl(MSR_FS_BASE,  fs_base);
	rdmsrl(MSR_GS_BASE,  gs_base);
	tr_base = segment_base(tr_sel);
	vmcs_write64(VMCS_HOST_FS_BASE,   fs_base);
	vmcs_write64(VMCS_HOST_GS_BASE,   gs_base);
	vmcs_write64(VMCS_HOST_TR_BASE,   tr_base);

	get_gdt(&gdt_base, &gdt_limit);
	get_idt(&idt_base, &idt_limit);
	vmcs_write64(VMCS_HOST_GDTR_BASE, gdt_base);
	vmcs_write64(VMCS_HOST_IDTR_BASE, idt_base);

	vmcs_write32(VMCS_HOST_SYSENTER_CS,  0);
	vmcs_write64(VMCS_HOST_SYSENTER_ESP, 0);
	vmcs_write64(VMCS_HOST_SYSENTER_EIP, 0);

	/*
	 * HOST_RSP: top of exit stack (page-aligned, stack grows down).
	 * The trampoline subtracts 8 before the call to maintain 16-byte
	 * alignment, so we set RSP = va + PAGE_SIZE (one past the end).
	 */
	vmcs_write64(VMCS_HOST_RSP,
		     vcpu->exit_stack_va + SPIKE_EXIT_STACK_SIZE);
	vmcs_write64(VMCS_HOST_RIP,
		     (u64)(uintptr_t)spike_vmexit_trampoline);

	return 0;
}

/* -------------------------------------------------------------------------
 * VM exit dispatch
 * ------------------------------------------------------------------------- */

/*
 * spike_vmexit_dispatch() — called from the trampoline on every VM exit.
 *
 * Reads VMCS_EXIT_REASON, dispatches to the appropriate handler, and sets
 * vcpu->should_exit to tell the caller whether to VMRESUME or stop.
 *
 * This function MUST NOT call printk on a production hot-path.
 * For the spike, pr_info is acceptable as it is not performance-critical.
 */
/* Called from asm trampoline — must not be static. */
void spike_vmexit_dispatch(struct spike_vcpu *vcpu)
{
	u32 reason;
	u64 gpa, qual, rip;

	reason = vmcs_read32(VMCS_EXIT_REASON) & 0xffff;
	vcpu->exit_count++;

	switch (reason) {
	case VMX_EXIT_VMCALL:
		/*
		 * Guest executed VMCALL.  Log it and advance RIP past the
		 * 3-byte VMCALL instruction so the guest continues normally.
		 */
		rip = vmcs_read64(VMCS_GUEST_RIP);
		pr_info("spike: VMCALL exit #%d — guest RIP=0x%llx; "
			"advancing RIP by 3\n",
			vcpu->exit_count, rip);
		vmcs_write64(VMCS_GUEST_RIP, rip + 3);
		vcpu->should_exit = false;  /* resume guest */
		break;

	case VMX_EXIT_EPT_VIOLATION:
		/*
		 * Guest accessed an unmapped GPA.  Log GPA and exit
		 * qualification, then abort the guest (should_exit = true).
		 */
		gpa  = vmcs_read64(VMCS_GUEST_PHYS_ADDR);
		qual = vmcs_read64(VMCS_EXIT_QUALIFICATION);
		pr_info("spike: EPT violation #%d — GPA=0x%llx qual=0x%llx "
			"(read=%llu write=%llu fetch=%llu)\n",
			vcpu->exit_count, gpa, qual,
			qual & 1, (qual >> 1) & 1, (qual >> 2) & 1);
		vcpu->should_exit = true;  /* abort guest */
		break;

	case VMX_EXIT_TRIPLE_FAULT:
		pr_err("spike: guest triple-fault — aborting\n");
		vcpu->should_exit = true;
		break;

	case VMX_EXIT_EPT_MISCONFIG:
		pr_err("spike: EPT misconfiguration — check EPT entry format\n");
		vcpu->should_exit = true;
		break;

	default:
		pr_info("spike: unexpected exit reason %u — aborting guest\n",
			reason);
		vcpu->should_exit = true;
		break;
	}
}

/*
 * spike_maybe_resume() — called from the trampoline after spike_vmexit_dispatch.
 * Marked __noreturn: either VMRESUMEs or longjmps back to spike_do_vmlaunch().
 *
 * If should_exit is false: VMRESUME (does not return on success).
 * If should_exit is true: restore the saved RSP/RBP/RIP and jump to the
 * 'spike_vmlaunch_done' label inside spike_do_vmlaunch().
 *
 * The indirect jump is annotated with the inline-asm equivalent of
 * ANNOTATE_RETPOLINE_SAFE (asm/nospec-branch.h) — the target is always
 * the spike_vmlaunch_done label, which is a static kernel address.
 */
__noreturn void spike_maybe_resume(struct spike_vcpu *vcpu)
{
	if (!vcpu->should_exit) {
		/* Continue guest execution — does not return on success. */
		asm volatile("vmresume" ::: "cc", "memory");
		/*
		 * VMRESUME returns here only if it fails (CF=1 or ZF=1).
		 * Log the error and fall through to the longjmp-back.
		 */
		pr_err("spike: VMRESUME failed! instr_err=%u\n",
		       vmcs_read32(VMCS_VM_INSTR_ERROR));
	}

	/*
	 * Restore the original RSP/RBP from spike_do_vmlaunch() and jump
	 * to the spike_vmlaunch_done label.
	 *
	 * UNWIND_HINT_UNDEFINED: tell objtool that the unwind state after
	 * this point is intentionally undefined (we are changing RSP to
	 * a completely different stack frame — a longjmp).
	 *
	 * The ".discard.retpoline_safe" annotation tells objtool that the
	 * indirect jump is intentional (equivalent to ANNOTATE_RETPOLINE_SAFE).
	 */
	UNWIND_HINT_UNDEFINED;
	asm volatile(
		"movq %0, %%rsp\n\t"
		"movq %1, %%rbp\n\t"
		".Lspike_rp_safe:\n\t"
		".pushsection .discard.retpoline_safe\n\t"
		".long .Lspike_rp_safe\n\t"
		".popsection\n\t"
		"jmpq *%2\n\t"
		:
		: "r"(*this_cpu_ptr(&spike_saved_rsp)),
		  "r"(*this_cpu_ptr(&spike_saved_rbp)),
		  "r"(*this_cpu_ptr(&spike_saved_rip))
		: "memory"
	);
	unreachable();
}

/* -------------------------------------------------------------------------
 * Guest launch
 * ------------------------------------------------------------------------- */

/*
 * spike_do_vmlaunch() — execute VMLAUNCH and busy-wait for the guest to finish.
 *
 * VMLAUNCH transitions the CPU to non-root mode.  On each VM exit, the
 * trampoline calls spike_vmexit_dispatch + spike_maybe_resume.
 * spike_maybe_resume sets spike_guest_done and halts (on the exit stack).
 *
 * spike_do_vmlaunch() busy-polls spike_guest_done — which is set on the exit
 * stack, running on the same physical CPU, so the poll sees the write after
 * the exit stack returns control (via the VMRESUME → VMexit → trampoline path).
 *
 * Wait — if spike_maybe_resume halts (HLT on the exit stack), and
 * spike_do_vmlaunch is polling from the original stack on the SAME CPU,
 * they cannot both run at the same time.  We need a different signalling
 * mechanism.
 *
 * Correct design for single-CPU spike:
 * After VMLAUNCH succeeds, the CPU is in guest mode.  The NEXT time we
 * execute code on this CPU (on this call stack) is after spike_maybe_resume
 * returns — but it cannot return due to the __noreturn constraint.
 *
 * Resolution: make spike_maybe_resume restore the original RSP/RIP using
 * the longjmp approach, but avoid objtool's objections by:
 * (a) using ANNOTATE_RETPOLINE_SAFE for the indirect jump, and
 * (b) not having a bare retq in the trampoline (use ud2 instead, already done).
 *
 * This is the approach used here.
 */
static noinline int spike_do_vmlaunch(struct spike_vcpu *vcpu)
{
	int ret = 0;

	/*
	 * Save host context so spike_maybe_resume() can restore it.
	 * We capture:
	 *   RSP — points to the saved RBP/return address on the stack
	 *   RBP — frame pointer chain
	 *   RIP — address of 'vmlaunch_done' label (after VMLAUNCH)
	 *
	 * We need the label address BEFORE executing VMLAUNCH so we can
	 * store it.  After VMLAUNCH succeeds the CPU is in guest mode and
	 * only returns here via the trampoline + spike_maybe_resume().
	 */
	asm volatile(
		"movq  %%rsp, %0\n\t"
		"movq  %%rbp, %1\n\t"
		"leaq  spike_vmlaunch_done(%%rip), %%rax\n\t"
		"movq  %%rax, %2\n\t"
		: "=m"(*this_cpu_ptr(&spike_saved_rsp)),
		  "=m"(*this_cpu_ptr(&spike_saved_rbp)),
		  "=m"(*this_cpu_ptr(&spike_saved_rip))
		:
		: "rax", "memory"
	);

	/* Update HOST_RSP to exit stack top (recapture in case RSP changed). */
	vmcs_write64(VMCS_HOST_RSP,
		     vcpu->exit_stack_va + SPIKE_EXIT_STACK_SIZE);

	pr_info("spike: VMLAUNCH: guest RIP=0x%llx guest RSP=0x%llx\n",
		vcpu->ept.code_gpa,
		vcpu->ept.stack_gpa + SPIKE_GUEST_STACK_SIZE);

	ret = vmlaunch_safe();
	if (ret) {
		pr_err("spike: VMLAUNCH failed ret=%d instr_err=%u\n",
		       ret, vmcs_read32(VMCS_VM_INSTR_ERROR));
	}

	/*
	 * This label is the longjmp target.  spike_maybe_resume() restores
	 * RSP + RBP then jumps here.  On a failed VMLAUNCH we fall through
	 * here normally.  Either way, the guest is done.
	 */
	asm volatile("spike_vmlaunch_done:" ::: "memory");

	return ret;
}

/*
 * spike_run_guest() — orchestrate VMCS setup and guest launch.
 * Called on CPU 0 via smp_call_function_single().
 */
static void spike_run_guest(void *arg)
{
	struct spike_vcpu *vcpu = (struct spike_vcpu *)arg;
	int ret;

	ret = spike_do_vmlaunch(vcpu);
	if (ret && vcpu->exit_count == 0)
		pr_err("spike: guest never ran (VMLAUNCH failed)\n");
	else
		pr_info("spike: guest run complete after %d exits\n",
			vcpu->exit_count);
}

/* -------------------------------------------------------------------------
 * Per-CPU VMX init / cleanup (called via smp_call_function_single)
 * ------------------------------------------------------------------------- */

static void spike_vmx_init_cpu(void *arg)
{
	struct spike_vcpu *vcpu = (struct spike_vcpu *)arg;
	u32 revision;
	u32 *region;
	int ret;

	/* 1. Check CPU supports VT-x */
	if (!(cpuid_ecx(1) & (1U << 5))) {
		pr_err("spike: VMX not supported on this CPU\n");
		return;
	}

	/* 2. Pre-check CR4.VMXE — if set, another VMX user is active */
	if (__read_cr4() & X86_CR4_VMXE) {
		pr_warn("spike: CR4.VMXE already set — another VMX entity "
			"may be active (kvm_intel loaded?)\n");
	}

	/* 3. Read VMCS revision ID */
	revision = read_vmcs_revision();
	pr_info("spike: VMCS revision ID = 0x%x\n", revision);

	/* 4. Write revision ID into VMXON region */
	region = (u32 *)vcpu->vmxon_region_va;
	*region = revision;

	/* 5. Write revision ID into VMCS region */
	region = (u32 *)vcpu->vmcs_region_va;
	*region = revision;

	/* 6. Enable CR4.VMXE */
	cr4_set_bits(X86_CR4_VMXE);

	/* 7. VMXON */
	ret = vmxon_safe(vcpu->vmxon_region_pa);
	if (ret) {
		pr_err("spike: VMXON failed ret=%d — CF or ZF was set\n",
		       ret);
		cr4_clear_bits(X86_CR4_VMXE);
		return;
	}
	vcpu->vmx_active = true;
	pr_info("spike: VMXON succeeded on CPU %d\n", smp_processor_id());

	/* 8. VMCLEAR to initialise the VMCS */
	ret = vmclear_safe(vcpu->vmcs_region_pa);
	if (ret) {
		pr_err("spike: VMCLEAR failed ret=%d\n", ret);
		goto fail_vmclear;
	}

	/* 9. VMPTRLD to make the VMCS current */
	ret = vmptrld_safe(vcpu->vmcs_region_pa);
	if (ret) {
		pr_err("spike: VMPTRLD failed ret=%d\n", ret);
		goto fail_vmptrld;
	}
	vcpu->vmcs_loaded = true;

	/* 10. Populate VMCS fields */
	ret = spike_setup_vmcs(vcpu);
	if (ret) {
		pr_err("spike: spike_setup_vmcs failed ret=%d\n", ret);
		goto fail_vmcs;
	}

	/* 11. Launch the guest */
	spike_run_guest(vcpu);

	return;

fail_vmcs:
	vmclear_safe(vcpu->vmcs_region_pa);
	vcpu->vmcs_loaded = false;
fail_vmptrld:
fail_vmclear:
	vmxoff();
	cr4_clear_bits(X86_CR4_VMXE);
	vcpu->vmx_active = false;
}

static void spike_vmx_cleanup_cpu(void *arg)
{
	struct spike_vcpu *vcpu = (struct spike_vcpu *)arg;

	if (!vcpu->vmx_active)
		return;

	if (vcpu->vmcs_loaded) {
		vmclear_safe(vcpu->vmcs_region_pa);
		vcpu->vmcs_loaded = false;
	}

	vmxoff();
	cr4_clear_bits(X86_CR4_VMXE);
	vcpu->vmx_active = false;
	pr_info("spike: VMXOFF executed on CPU %d\n", smp_processor_id());
}

/* -------------------------------------------------------------------------
 * Module init / cleanup
 * ------------------------------------------------------------------------- */

static int __init spike_init(void)
{
	int ret;

	pr_info("spike: Project Phantom VMX feasibility spike loading\n");

	/* Allocate vCPU structure */
	g_vcpu = kzalloc(sizeof(*g_vcpu), GFP_KERNEL);
	if (!g_vcpu) {
		ret = -ENOMEM;
		goto err_alloc_vcpu;
	}

	/* Allocate VMXON region: 4KB, page-aligned */
	g_vcpu->vmxon_region_va = __get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!g_vcpu->vmxon_region_va) {
		ret = -ENOMEM;
		goto err_vmxon;
	}
	g_vcpu->vmxon_region_pa = virt_to_phys((void *)g_vcpu->vmxon_region_va);

	/* Allocate VMCS region: 4KB, page-aligned */
	g_vcpu->vmcs_region_va = __get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!g_vcpu->vmcs_region_va) {
		ret = -ENOMEM;
		goto err_vmcs;
	}
	g_vcpu->vmcs_region_pa = virt_to_phys((void *)g_vcpu->vmcs_region_va);

	/* Allocate dedicated host exit stack: 4KB */
	g_vcpu->exit_stack_va = __get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!g_vcpu->exit_stack_va) {
		ret = -ENOMEM;
		goto err_exit_stack;
	}

	/* Build EPT */
	memset(&g_vcpu->ept, 0, sizeof(g_vcpu->ept));
	ret = spike_ept_build(&g_vcpu->ept);
	if (ret) {
		pr_err("spike: EPT build failed ret=%d\n", ret);
		goto err_ept;
	}

	/*
	 * CHECKPOINT: About to execute VMXON — a dangerous operation.
	 * If this panics, kdump will capture the state.  Serial console
	 * output up to this point should be visible on the second machine.
	 */
	pr_info("spike: CHECKPOINT — about to execute VMXON on CPU 0\n");
	pr_info("spike: vmxon_pa=0x%llx vmcs_pa=0x%llx eptp=0x%llx\n",
		g_vcpu->vmxon_region_pa, g_vcpu->vmcs_region_pa,
		g_vcpu->ept.eptp);

	/* Run VMX operations on CPU 0 */
	ret = smp_call_function_single(0, spike_vmx_init_cpu, g_vcpu, 1);
	if (ret) {
		pr_err("spike: smp_call_function_single failed ret=%d\n", ret);
		goto err_smp;
	}

	if (!g_vcpu->vmx_active) {
		pr_err("spike: VMX not active after init — check dmesg for "
		       "errors\n");
		ret = -EIO;
		goto err_smp;
	}

	pr_info("spike: spike loaded successfully; exit_count=%d\n",
		g_vcpu->exit_count);

	/*
	 * Intentional panic scenario — validates kdump / serial console.
	 * Only triggered when trigger_panic=1 is passed as module parameter.
	 */
	if (trigger_panic) {
		pr_info("spike: trigger_panic=1 — about to BUG() for kdump "
			"validation\n");
		BUG();
	}

	return 0;

err_smp:
err_ept:
	spike_ept_destroy(&g_vcpu->ept);
	free_page(g_vcpu->exit_stack_va);
err_exit_stack:
	free_page(g_vcpu->vmcs_region_va);
err_vmcs:
	free_page(g_vcpu->vmxon_region_va);
err_vmxon:
	kfree(g_vcpu);
	g_vcpu = NULL;
err_alloc_vcpu:
	return ret;
}

static void __exit spike_exit(void)
{
	pr_info("spike: unloading\n");

	if (!g_vcpu)
		return;

	/* VMXOFF on CPU 0 */
	smp_call_function_single(0, spike_vmx_cleanup_cpu, g_vcpu, 1);

	/* Free all resources */
	spike_ept_destroy(&g_vcpu->ept);
	free_page(g_vcpu->exit_stack_va);
	free_page(g_vcpu->vmcs_region_va);
	free_page(g_vcpu->vmxon_region_va);
	kfree(g_vcpu);
	g_vcpu = NULL;

	pr_info("spike: unloaded cleanly\n");
}

module_init(spike_init);
module_exit(spike_exit);
