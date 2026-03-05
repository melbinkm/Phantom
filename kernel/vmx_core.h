// SPDX-License-Identifier: GPL-2.0-only
/*
 * vmx_core.h — VMX bootstrap declarations for phantom.ko
 *
 * Covers: per-CPU VMX state, MSR constants, VMCS field encodings,
 * VMCS read/write helpers, control adjustment, guest register file,
 * VMXON/VMXOFF/VMCS allocation prototypes, and guest execution API.
 */
#ifndef PHANTOM_VMX_CORE_H
#define PHANTOM_VMX_CORE_H

#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/mm_types.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <asm/msr-index.h>

#include "ept.h"
#include "ept_cow.h"
#include "snapshot.h"
#include "interface.h"
#include "pt_config.h"

/* ------------------------------------------------------------------
 * MSR constants — only defined if the running kernel headers omit them
 * ------------------------------------------------------------------ */

#ifndef MSR_IA32_VMX_BASIC
#define MSR_IA32_VMX_BASIC		0x00000480
#endif
#ifndef MSR_IA32_VMX_PINBASED_CTLS
#define MSR_IA32_VMX_PINBASED_CTLS	0x00000481
#endif
#ifndef MSR_IA32_VMX_PROCBASED_CTLS
#define MSR_IA32_VMX_PROCBASED_CTLS	0x00000482
#endif
#ifndef MSR_IA32_VMX_EXIT_CTLS
#define MSR_IA32_VMX_EXIT_CTLS		0x00000483
#endif
#ifndef MSR_IA32_VMX_ENTRY_CTLS
#define MSR_IA32_VMX_ENTRY_CTLS		0x00000484
#endif
#ifndef MSR_IA32_VMX_CR0_FIXED0
#define MSR_IA32_VMX_CR0_FIXED0		0x00000486
#endif
#ifndef MSR_IA32_VMX_CR0_FIXED1
#define MSR_IA32_VMX_CR0_FIXED1		0x00000487
#endif
#ifndef MSR_IA32_VMX_CR4_FIXED0
#define MSR_IA32_VMX_CR4_FIXED0		0x00000488
#endif
#ifndef MSR_IA32_VMX_CR4_FIXED1
#define MSR_IA32_VMX_CR4_FIXED1		0x00000489
#endif
#ifndef MSR_IA32_VMX_PROCBASED_CTLS2
#define MSR_IA32_VMX_PROCBASED_CTLS2	0x0000048b
#endif
#ifndef MSR_IA32_VMX_EPT_VPID_CAP
#define MSR_IA32_VMX_EPT_VPID_CAP	0x0000048c
#endif
#ifndef MSR_IA32_VMX_TRUE_PINBASED_CTLS
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS	 0x0000048d
#endif
#ifndef MSR_IA32_VMX_TRUE_PROCBASED_CTLS
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x0000048e
#endif
#ifndef MSR_IA32_VMX_TRUE_EXIT_CTLS
#define MSR_IA32_VMX_TRUE_EXIT_CTLS	0x0000048f
#endif
#ifndef MSR_IA32_VMX_TRUE_ENTRY_CTLS
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS	0x00000490
#endif

/* VMX_BASIC bits */
#define VMX_BASIC_REVISION_MASK		0x7fffffffULL

/* ------------------------------------------------------------------
 * VMCS field encodings (Intel SDM Vol. 3C §B.1 – §B.4)
 *
 * Naming: VMCS_GUEST_* / VMCS_HOST_* / VMCS_CTRL_* to avoid
 * collisions with <asm/vmx.h> which uses similar names.
 * ------------------------------------------------------------------ */

/* 16-bit Guest-State Fields */
#define VMCS_GUEST_ES_SELECTOR		0x0800
#define VMCS_GUEST_CS_SELECTOR		0x0802
#define VMCS_GUEST_SS_SELECTOR		0x0804
#define VMCS_GUEST_DS_SELECTOR		0x0806
#define VMCS_GUEST_FS_SELECTOR		0x0808
#define VMCS_GUEST_GS_SELECTOR		0x080A
#define VMCS_GUEST_LDTR_SELECTOR	0x080C
#define VMCS_GUEST_TR_SELECTOR		0x080E

/* 16-bit Host-State Fields */
#define VMCS_HOST_ES_SELECTOR		0x0C00
#define VMCS_HOST_CS_SELECTOR		0x0C02
#define VMCS_HOST_SS_SELECTOR		0x0C04
#define VMCS_HOST_DS_SELECTOR		0x0C06
#define VMCS_HOST_FS_SELECTOR		0x0C08
#define VMCS_HOST_GS_SELECTOR		0x0C0A
#define VMCS_HOST_TR_SELECTOR		0x0C0C

/* 16-bit Control Fields */
#define VMCS_CTRL_VPID			0x0000

/* 64-bit Control Fields */
#define VMCS_CTRL_IO_BITMAP_A		0x2000
#define VMCS_CTRL_IO_BITMAP_B		0x2002
#define VMCS_CTRL_MSR_BITMAP		0x2004
#define VMCS_CTRL_TSC_OFFSET		0x2010
#define VMCS_CTRL_EPT_POINTER		0x201A
#define VMCS_CTRL_VMCS_LINK_PTR		0x2800

/* 64-bit Guest-State Fields */
#define VMCS_GUEST_IA32_DEBUGCTL	0x2802
#define VMCS_GUEST_IA32_PAT		0x2804
#define VMCS_GUEST_IA32_EFER		0x2806
#define VMCS_GUEST_IA32_PERF_GLOBAL	0x2808
/* PDPTE entries (PAE paging) */
#define VMCS_GUEST_PDPTE0		0x280A
#define VMCS_GUEST_PDPTE1		0x280C
#define VMCS_GUEST_PDPTE2		0x280E
#define VMCS_GUEST_PDPTE3		0x2810

/* 64-bit Host-State Fields */
#define VMCS_HOST_IA32_PAT		0x2C00
#define VMCS_HOST_IA32_EFER		0x2C02
#define VMCS_HOST_IA32_PERF_GLOBAL	0x2C04

/* 32-bit Control Fields */
#define VMCS_CTRL_PINBASED		0x4000
#define VMCS_CTRL_PROCBASED		0x4002
#define VMCS_CTRL_EXCEPTION_BITMAP	0x4004
#define VMCS_CTRL_PF_EC_MASK		0x4006
#define VMCS_CTRL_PF_EC_MATCH		0x4008
#define VMCS_CTRL_CR3_TARGET_COUNT	0x400A
#define VMCS_CTRL_EXIT			0x400C
#define VMCS_CTRL_EXIT_MSR_STORE_COUNT	0x400E
#define VMCS_CTRL_EXIT_MSR_LOAD_COUNT	0x4010
#define VMCS_CTRL_ENTRY			0x4012
#define VMCS_CTRL_ENTRY_MSR_LOAD_COUNT	0x4014
#define VMCS_CTRL_ENTRY_INTR_INFO	0x4016
#define VMCS_CTRL_ENTRY_EXCEPTION_EC	0x4018
#define VMCS_CTRL_ENTRY_INSTR_LEN	0x401A
#define VMCS_CTRL_PROCBASED2		0x401E

/* 32-bit Read-Only Data Fields */
#define VMCS_RO_VM_INSTR_ERROR		0x4400
#define VMCS_RO_EXIT_REASON		0x4402
#define VMCS_RO_EXIT_INTR_INFO		0x4404
#define VMCS_RO_EXIT_INTR_EC		0x4406
#define VMCS_RO_IDT_VECTORING_INFO	0x4408
#define VMCS_RO_IDT_VECTORING_EC	0x440A
#define VMCS_RO_EXIT_INSTR_LEN		0x440C
#define VMCS_RO_EXIT_INSTR_INFO		0x440E

/* 32-bit Guest-State Fields */
#define VMCS_GUEST_ES_LIMIT		0x4800
#define VMCS_GUEST_CS_LIMIT		0x4802
#define VMCS_GUEST_SS_LIMIT		0x4804
#define VMCS_GUEST_DS_LIMIT		0x4806
#define VMCS_GUEST_FS_LIMIT		0x4808
#define VMCS_GUEST_GS_LIMIT		0x480A
#define VMCS_GUEST_LDTR_LIMIT		0x480C
#define VMCS_GUEST_TR_LIMIT		0x480E
#define VMCS_GUEST_GDTR_LIMIT		0x4810
#define VMCS_GUEST_IDTR_LIMIT		0x4812
#define VMCS_GUEST_ES_AR		0x4814
#define VMCS_GUEST_CS_AR		0x4816
#define VMCS_GUEST_SS_AR		0x4818
#define VMCS_GUEST_DS_AR		0x481A
#define VMCS_GUEST_FS_AR		0x481C
#define VMCS_GUEST_GS_AR		0x481E
#define VMCS_GUEST_LDTR_AR		0x4820
#define VMCS_GUEST_TR_AR		0x4822
#define VMCS_GUEST_INTR_STATE		0x4824
#define VMCS_GUEST_ACTIVITY_STATE	0x4826
#define VMCS_GUEST_SMBASE		0x4828
#define VMCS_GUEST_IA32_SYSENTER_CS	0x482A
#define VMCS_CTRL_PREEMPT_TIMER		0x482E

/* 32-bit Host-State Fields */
#define VMCS_HOST_IA32_SYSENTER_CS	0x4C00

/* Natural-width Control Fields */
#define VMCS_CTRL_CR0_MASK		0x6000
#define VMCS_CTRL_CR4_MASK		0x6002
#define VMCS_CTRL_CR0_READ_SHADOW	0x6004
#define VMCS_CTRL_CR4_READ_SHADOW	0x6006
#define VMCS_CTRL_CR3_TARGET0		0x6008
#define VMCS_CTRL_CR3_TARGET1		0x600A
#define VMCS_CTRL_CR3_TARGET2		0x600C
#define VMCS_CTRL_CR3_TARGET3		0x600E

/* Natural-width Read-Only Data Fields */
#define VMCS_RO_EXIT_QUAL		0x6400
#define VMCS_RO_IO_RCX			0x6402
#define VMCS_RO_IO_RSI			0x6404
#define VMCS_RO_IO_RDI			0x6406
#define VMCS_RO_IO_RIP			0x6408
#define VMCS_RO_GUEST_LIN_ADDR		0x640A
#define VMCS_RO_GUEST_PHYS_ADDR		0x2400  /* 64-bit field */

/* Natural-width Guest-State Fields */
#define VMCS_GUEST_CR0			0x6800
#define VMCS_GUEST_CR3			0x6802
#define VMCS_GUEST_CR4			0x6804
#define VMCS_GUEST_ES_BASE		0x6806
#define VMCS_GUEST_CS_BASE		0x6808
#define VMCS_GUEST_SS_BASE		0x680A
#define VMCS_GUEST_DS_BASE		0x680C
#define VMCS_GUEST_FS_BASE		0x680E
#define VMCS_GUEST_GS_BASE		0x6810
#define VMCS_GUEST_LDTR_BASE		0x6812
#define VMCS_GUEST_TR_BASE		0x6814
#define VMCS_GUEST_GDTR_BASE		0x6816
#define VMCS_GUEST_IDTR_BASE		0x6818
#define VMCS_GUEST_DR7			0x681A
#define VMCS_GUEST_RSP			0x681C
#define VMCS_GUEST_RIP			0x681E
#define VMCS_GUEST_RFLAGS		0x6820
#define VMCS_GUEST_PENDING_DBG_EXC	0x6822
#define VMCS_GUEST_IA32_SYSENTER_ESP	0x6824
#define VMCS_GUEST_IA32_SYSENTER_EIP	0x6826

/* Natural-width Host-State Fields */
#define VMCS_HOST_CR0			0x6C00
#define VMCS_HOST_CR3			0x6C02
#define VMCS_HOST_CR4			0x6C04
#define VMCS_HOST_FS_BASE		0x6C06
#define VMCS_HOST_GS_BASE		0x6C08
#define VMCS_HOST_TR_BASE		0x6C0A
#define VMCS_HOST_GDTR_BASE		0x6C0C
#define VMCS_HOST_IDTR_BASE		0x6C0E
#define VMCS_HOST_IA32_SYSENTER_ESP	0x6C10
#define VMCS_HOST_IA32_SYSENTER_EIP	0x6C12
#define VMCS_HOST_RSP			0x6C14
#define VMCS_HOST_RIP			0x6C16

/* ------------------------------------------------------------------
 * VM exit reason codes (Intel SDM Vol. 3C Appendix C)
 * ------------------------------------------------------------------ */
#define VMX_EXIT_EXCEPTION_NMI		0
#define VMX_EXIT_EXTERNAL_INT		1
#define VMX_EXIT_TRIPLE_FAULT		2
#define VMX_EXIT_CPUID			10
#define VMX_EXIT_CR_ACCESS		28
#define VMX_EXIT_IO_INSTR		30
#define VMX_EXIT_MSR_READ		31
#define VMX_EXIT_MSR_WRITE		32
#define VMX_EXIT_VMCALL			18
#define VMX_EXIT_EPT_VIOLATION		48
#define VMX_EXIT_EPT_MISCONFIG		49
#define VMX_EXIT_PREEMPT_TIMER		52
#define VMX_EXIT_XSETBV			55

/* ------------------------------------------------------------------
 * VMCS control field bit definitions
 *
 * Use #ifndef guards to avoid clashing with <asm/vmx.h> which defines
 * most of these with identical names.  The kernel header takes priority
 * when included; our definitions are only active if the kernel omits them.
 * ------------------------------------------------------------------ */

/* Pin-based execution controls */
#ifndef PIN_BASED_EXT_INT_EXITING
#define PIN_BASED_EXT_INT_EXITING	BIT(0)
#endif
#ifndef PIN_BASED_NMI_EXITING
#define PIN_BASED_NMI_EXITING		BIT(3)
#endif
#ifndef PIN_BASED_VIRTUAL_NMIS
#define PIN_BASED_VIRTUAL_NMIS		BIT(5)
#endif
#ifndef PIN_BASED_PREEMPT_TIMER
#define PIN_BASED_PREEMPT_TIMER		BIT(6)
#endif

/* Primary proc-based execution controls */
#ifndef CPU_BASED_HLT_EXITING
#define CPU_BASED_HLT_EXITING		BIT(7)
#endif
/* The kernel uses CPU_BASED_UNCOND_IO_EXITING (UNCOND not UNCONDITIONAL) */
#if !defined(CPU_BASED_UNCONDITIONAL_IO) && \
    !defined(CPU_BASED_UNCOND_IO_EXITING)
#define CPU_BASED_UNCONDITIONAL_IO	BIT(24)
#elif defined(CPU_BASED_UNCOND_IO_EXITING) && \
      !defined(CPU_BASED_UNCONDITIONAL_IO)
#define CPU_BASED_UNCONDITIONAL_IO	CPU_BASED_UNCOND_IO_EXITING
#endif
#ifndef CPU_BASED_USE_MSR_BITMAPS
#define CPU_BASED_USE_MSR_BITMAPS	BIT(28)
#endif
/* The kernel 6.8+ uses CPU_BASED_ACTIVATE_SECONDARY_CONTROLS for bit 31 */
#if !defined(CPU_BASED_SECONDARY_ENABLE) && \
    !defined(CPU_BASED_ACTIVATE_SECONDARY_CONTROLS)
#define CPU_BASED_SECONDARY_ENABLE	BIT(31)
#elif defined(CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) && \
      !defined(CPU_BASED_SECONDARY_ENABLE)
#define CPU_BASED_SECONDARY_ENABLE	CPU_BASED_ACTIVATE_SECONDARY_CONTROLS
#endif

/* Secondary proc-based execution controls */
#ifndef SECONDARY_EXEC_ENABLE_EPT
#define SECONDARY_EXEC_ENABLE_EPT	BIT(1)
#endif
#ifndef SECONDARY_EXEC_ENABLE_VPID
#define SECONDARY_EXEC_ENABLE_VPID	BIT(5)
#endif

/* VM-exit controls */
#ifndef VM_EXIT_HOST_ADDR_SPACE_SIZE
#define VM_EXIT_HOST_ADDR_SPACE_SIZE	BIT(9)
#endif
/* The kernel uses VM_EXIT_ACK_INTR_ON_EXIT (note: INTR not INT) */
#if !defined(VM_EXIT_ACK_INT_ON_EXIT) && !defined(VM_EXIT_ACK_INTR_ON_EXIT)
#define VM_EXIT_ACK_INT_ON_EXIT		BIT(15)
#elif defined(VM_EXIT_ACK_INTR_ON_EXIT) && !defined(VM_EXIT_ACK_INT_ON_EXIT)
#define VM_EXIT_ACK_INT_ON_EXIT		VM_EXIT_ACK_INTR_ON_EXIT
#endif
#ifndef VM_EXIT_SAVE_IA32_PAT
#define VM_EXIT_SAVE_IA32_PAT		BIT(18)
#endif
#ifndef VM_EXIT_LOAD_IA32_PAT
#define VM_EXIT_LOAD_IA32_PAT		BIT(19)
#endif
#ifndef VM_EXIT_SAVE_IA32_EFER
#define VM_EXIT_SAVE_IA32_EFER		BIT(20)
#endif
#ifndef VM_EXIT_LOAD_IA32_EFER
#define VM_EXIT_LOAD_IA32_EFER		BIT(21)
#endif

/* VM-entry controls */
#ifndef VM_ENTRY_IA32E_MODE
#define VM_ENTRY_IA32E_MODE		BIT(9)
#endif
#ifndef VM_ENTRY_LOAD_IA32_PAT
#define VM_ENTRY_LOAD_IA32_PAT		BIT(14)
#endif
#ifndef VM_ENTRY_LOAD_IA32_EFER
#define VM_ENTRY_LOAD_IA32_EFER		BIT(15)
#endif

/* Segment access rights: unusable bit */
#ifndef VMX_SEGMENT_AR_UNUSABLE
#define VMX_SEGMENT_AR_UNUSABLE		BIT(16)
#endif

/* ------------------------------------------------------------------
 * EPT constants and GPA definitions are in ept.h (included above).
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------
 * Guest register file (saved/restored around VM entry/exit)
 *
 * RSP and RIP are kept in the VMCS guest-state area, not here.
 * All 15 other GPRs are stored in this struct.
 * ------------------------------------------------------------------ */
struct phantom_guest_regs {
	u64 rax;
	u64 rbx;
	u64 rcx;
	u64 rdx;
	u64 rsi;
	u64 rdi;
	u64 rbp;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

/* ------------------------------------------------------------------
 * Per-CPU VMX state
 *
 * Extended from task 1.1 to include VMCS guest execution state,
 * EPT page table pages, MSR bitmap, and guest memory pages.
 * ------------------------------------------------------------------ */
struct phantom_vmx_cpu_state {
	/* Task 1.1 fields */
	struct page		*vmxon_region;
	struct page		*vmcs_region;
	bool			 vmx_active;
	unsigned long		 saved_cr4;
	int			 cpu;
	int			 init_err;

	/* Task 1.2: MSR bitmap (4KB zero page — no MSR exits) */
	struct page		*msr_bitmap;

	/* Task 1.2: EPT page-table pages (4 levels) */
	struct page		*ept_pml4;
	struct page		*ept_pdpt;
	struct page		*ept_pd;
	struct page		*ept_pt;

	/* Task 1.2: Guest memory pages */
	struct page		*guest_code_page;
	struct page		*guest_stack_page;
	struct page		*guest_data_page;
	struct page		*guest_pml4_page;  /* guest CR3 page */
	struct page		*guest_pdpt_page;
	struct page		*guest_pd_page;

	/* Task 1.2: Guest execution state */
	struct phantom_guest_regs guest_regs;
	u32			 exit_reason;
	u64			 exit_qualification;
	u32			 vm_instr_error;
	int			 run_result;
	u64			 run_result_data;   /* checksum from guest */
	bool			 launched;
	bool			 pages_allocated;   /* pages alloc'd (process ctx) */
	bool			 vmcs_configured;   /* VMCS fields written (CPU ctx) */
	u64			 host_rsp;          /* saved by trampoline */

	/*
	 * Dedicated vCPU kernel thread (pinned to this CPU).
	 * The ioctl hands work to this thread via completions to avoid
	 * the IPI mechanism which breaks KVM nested VMX state on re-entry.
	 *
	 * Thread stop protocol (IPI-free two-phase approach):
	 *   1. WRITE_ONCE(vcpu_stop_requested, true) — no IPI.
	 *   2. complete(&vcpu_run_start) — safe (only needed for Phase 1,
	 *      where VMLAUNCH hasn't happened so the IPI is harmless).
	 *   3. wait_for_completion(&vcpu_stopped) — thread signals this
	 *      after VMXOFF completes (in do_stop).
	 *   4. kthread_stop() — reclaims thread resources; by this point
	 *      the thread is post-VMXOFF so any IPI is safe.
	 *   phantom_vmxoff_all() skips the SMP call for this CPU because
	 *   vmx_active == false (VMXOFF already ran in thread).
	 *
	 * Init protocol (IPI-free VMXON + VMCS alloc):
	 *   After the first load's VMLAUNCH+VMXOFF cycle, KVM L0's nested
	 *   VMX tracking for this CPU is in a post-nested-exit state.  Any
	 *   cross-CPU IPI (smp_call_function_single) to this CPU — even
	 *   after VMXOFF — causes a triple fault in the guest kernel.
	 *
	 *   Solution: the vCPU thread performs VMXON, VMCS alloc, and
	 *   VMPTRLD locally on its own CPU at startup, then signals
	 *   vcpu_init_done.  Module init waits on vcpu_init_done instead
	 *   of using smp_call_function_single.  Zero cross-CPU IPIs during
	 *   the per-CPU VMX init path.
	 */
	struct task_struct	*vcpu_thread;
	struct completion	 vcpu_init_done;  /* thread → init: VMXON done */
	int			 vcpu_init_result; /* 0 = success, else errno */
	u32			 vmx_revision_id;  /* VMX_BASIC revision for VMXON */
	struct completion	 vcpu_run_start;  /* ioctl → thread: 1st run */
	struct completion	 vcpu_run_done;   /* thread → ioctl: done */
	int			 vcpu_run_request; /* 1=run, 2=reset, 0=exit */
	int			 vcpu_run_result;  /* thread's run result */
	/*
	 * vcpu_work_ready: IPI-free wakeup for runs after the first VMLAUNCH.
	 *
	 * After the first VMLAUNCH, KVM L0's nested VMX tracking is "dirty"
	 * even after the guest exits.  Any RESCHEDULE IPI (e.g., from
	 * complete()) sent to CPU0 while this state is active causes a triple
	 * fault.  We avoid IPIs entirely by busy-waiting on this flag.
	 *
	 * Set by the ioctl handler (no IPI) after the first VMLAUNCH.
	 * Read by the vCPU thread via cpu_relax() busy-wait.
	 * Protected by smp_store_release / smp_load_acquire barriers.
	 */
	bool			 vcpu_work_ready;  /* set by ioctl (no IPI) */

	/*
	 * IPI-free stop protocol for post-VMLAUNCH teardown.
	 *
	 * After the first VMLAUNCH, KVM L0's nested VMX state is "dirty" for
	 * this CPU.  kthread_stop() calls wake_up_process() which may send a
	 * RESCHEDULE IPI to this CPU even when the thread appears TASK_RUNNING
	 * (e.g., if the thread was briefly preempted by the scheduler between
	 * cond_resched() calls).  Such an IPI causes a triple fault in the
	 * nested KVM guest.
	 *
	 * Fix: phantom_vcpu_thread_stop() uses a two-phase stop:
	 *   1. Set vcpu_stop_requested = true (plain memory write, no IPI).
	 *   2. Wait on vcpu_stopped (thread signals this after VMXOFF).
	 *   3. Call kthread_stop() — thread has already exited VMX-root mode
	 *      and either returned or is about to; any IPI at this point is
	 *      harmless (VMX is inactive, no triple fault risk).
	 *
	 * vcpu_stop_requested: set by phantom_vcpu_thread_stop(), read by the
	 *   vCPU thread in both Phase 1 and Phase 2.
	 * vcpu_stopped: signaled by the vCPU thread after do_stop (VMXOFF done),
	 *   before the thread function returns.
	 */
	bool			 vcpu_stop_requested; /* flag: request stop (no IPI) */
	struct completion	 vcpu_stopped;        /* thread → stop: VMX done */

	/*
	 * Task 1.3: Proper 4-level EPT state.
	 *
	 * Placed at END of struct to preserve all offsets used by the
	 * assembly trampoline (guest_regs, launched, host_rsp etc. must
	 * remain at the same offsets as task 1.2).
	 *
	 * The old ept_pml4/ept_pdpt/ept_pd/ept_pt convenience fields and
	 * guest_*_page fields are kept above for backward compatibility;
	 * they are initialised from ept.ram_pages[] in phantom_vmcs_setup().
	 */
	struct phantom_ept_state ept;

	/*
	 * test_id: selects which guest binary to run.
	 *   0 = R/W test (10 pages, compute checksum)
	 *   1 = absent-GPA test (access GPA 0x1000000 → EPT violation)
	 *   2 = CoW write test (20 pages at GPA 0x30000–0x43000)
	 *   3 = pool exhaustion test (tiny 5-page pool, 10-write guest)
	 *
	 * Set by the ioctl handler from args.reserved before each run.
	 */
	u32			 test_id;

	/*
	 * Task 1.4: CoW snapshot engine fields.
	 *
	 * Placed AFTER host_rsp and all assembly-trampoline-referenced
	 * fields to preserve hardcoded struct offsets in vmx_trampoline.S.
	 *
	 * cow_pool:      pre-allocated private page pool
	 * dirty_list:    kvmalloc_array of phantom_dirty_entry records
	 * dirty_count:   number of dirty entries in current iteration
	 * dirty_max:     capacity of dirty_list (== cow_pool.capacity)
	 * cow_iteration: current fuzzing iteration counter
	 * cow_enabled:   true once EPT has been marked RO (snapshot taken)
	 */
	struct phantom_cow_pool	  cow_pool;
	struct phantom_dirty_entry *dirty_list;
	u32			  dirty_count;
	u32			  dirty_max;
	u32			  cow_iteration;
	bool			  cow_enabled;
	/*
	 * last_dirty_count: number of dirty entries from the most recently
	 * completed iteration, captured before phantom_cow_abort_iteration()
	 * resets dirty_count to 0.  Used by the debug ioctl and test code
	 * to verify CoW correctness without a race.
	 */
	u32			  last_dirty_count;

	/*
	 * Task 1.5: 2MB→4KB split list.
	 *
	 * Tracks PT pages allocated when phantom_split_2mb_page() converts
	 * a 2MB large-page PD entry into 512 × 4KB PTEs.  Entries are freed
	 * in phantom_cow_abort_iteration() after restoring the 2MB PD entry.
	 *
	 * Placed after cow_enabled/last_dirty_count to preserve prior field
	 * offsets (assembly trampoline accesses fields above by offset).
	 */
	struct phantom_split_list split_list;

	/*
	 * Task 1.5: dirty list overflow counter.
	 *
	 * Incremented when phantom_cow_fault() detects dirty_count >=
	 * dirty_max.  Unlike pool exhaustion (which sets CRASH result),
	 * overflow causes a graceful abort via phantom_cow_abort_iteration()
	 * and returns -ENOSPC.  The counter persists across iterations for
	 * health monitoring.
	 */
	u32			  dirty_overflow_count;

	/*
	 * Task 1.6: Snapshot/restore fields.
	 *
	 * snap:                 Complete guest architectural state captured
	 *                       by phantom_snapshot_create().
	 *
	 * xsave_area:           Raw allocation from kzalloc (xsave_area_size
	 *                       + 64 bytes for alignment padding).  Freed in
	 *                       phantom_vmcs_teardown().  NULL if XSAVE is
	 *                       not supported or allocation failed.
	 *
	 * xsave_area_aligned:   PTR_ALIGN(xsave_area, 64) — the actual
	 *                       64-byte aligned pointer passed to xsave64 /
	 *                       xrstor64.
	 *
	 * xsave_area_size:      From CPUID.(EAX=0Dh,ECX=0).EBX, rounded up
	 *                       to the next 64-byte boundary.  Minimum 512
	 *                       bytes (SSE fallback for legacy hardware).
	 *
	 * xcr0_supported:       Host XCR0 value at instance creation.  Used
	 *                       as the EDX:EAX pair for xsave64/xrstor64 to
	 *                       specify which state components to save/restore.
	 *
	 * snap_taken:           true after the first successful
	 *                       phantom_snapshot_create().  Cleared by
	 *                       phantom_vmcs_teardown().
	 */
	struct phantom_snapshot	  snap;
	void			 *xsave_area;          /* raw allocation */
	void			 *xsave_area_aligned;  /* 64-byte aligned */
	u32			  xsave_area_size;
	u64			  xcr0_supported;
	bool			  snap_taken;
	/*
	 * snap_continue: set by the RUN_GUEST ioctl handler to true only
	 * when test_id==7 AND snap_taken==true (phase-2 or post-restore
	 * continuation runs that must resume from snap->rip rather than
	 * resetting to GUEST_CODE_GPA).  Always false for test_id != 7 and
	 * for the initial phase-1 test_id=7 run (snap_taken=false).
	 *
	 * When true, the vCPU thread skips the RIP/RSP/RFLAGS reset in
	 * the relaunch path (snapshot_restore or snapshot_create already
	 * wrote the correct VMCS values).
	 */
	bool			  snap_continue;

	/*
	 * Task 1.8: Per-phase rdtsc cycle counts from the last
	 * phantom_snapshot_restore() call.
	 *
	 * Populated atomically within snapshot_restore() using the pattern:
	 *   t0 = rdtsc_ordered(); <dirty_walk>  t1 = rdtsc_ordered();
	 *   <INVEPT>               t2 = rdtsc_ordered();
	 *   <VMCS restore>         t3 = rdtsc_ordered();
	 *   <XRSTOR>               t4 = rdtsc_ordered();
	 *   t5 = rdtsc_ordered();
	 *
	 * Exposed via PHANTOM_IOCTL_PERF_RESTORE_LATENCY.
	 * All fields are zero until the first successful SNAPSHOT_RESTORE.
	 *
	 * Placed at the END of the struct to avoid disturbing the
	 * assembly-trampoline-referenced field offsets above.
	 */
	struct phantom_perf_result perf_last;

	/*
	 * Task 2.1: kAFL/Nyx ABI hypercall state.
	 *
	 * payload_gpa:       GPA registered by GET_PAYLOAD hypercall.
	 *                    The host writes the fuzz payload here each
	 *                    iteration before VMRESUME.  0 = not registered.
	 *
	 * pt_cr3:            Guest CR3 value registered by SUBMIT_CR3.
	 *                    Used by Intel PT for address filtering.
	 *                    0 = not submitted.
	 *
	 * crash_addr:        Guest address provided with PANIC hypercall.
	 *                    Stored for retrieval via GET_RESULT ioctl.
	 *
	 * panic_handler_gpa: GPA of the guest panic handler, registered
	 *                    by SUBMIT_PANIC.  Allows host to inject a
	 *                    controlled panic in future iterations.
	 *
	 * iteration_active:  true after ACQUIRE (snapshot taken), false
	 *                    after RELEASE/PANIC/KASAN (iteration ended).
	 *
	 * snap_acquired:     true once the very first ACQUIRE snapshot has
	 *                    been taken.  ACQUIRE is idempotent after this:
	 *                    subsequent ACQUIRE calls advance from the same
	 *                    snapshot point without re-creating the snapshot.
	 *
	 * shared_mem:        Kernel virtual address of the shared memory
	 *                    region (payload + status word + crash addr).
	 *                    Allocated at VMCS setup time.  mmap'd to
	 *                    userspace on demand.
	 *
	 * shared_mem_pages:  Backing pages for shared_mem (order-N block).
	 *                    Freed in phantom_vmcs_teardown().
	 *
	 * shared_mem_order:  Page allocation order for shared_mem_pages.
	 */
	u64			  payload_gpa;
	u64			  pt_cr3;
	u64			  crash_addr;
	u64			  panic_handler_gpa;
	bool			  iteration_active;
	bool			  snap_acquired;
	int			  last_test_id;	  /* last RUN_GUEST test_id, for re-prime detection */
	void			 *shared_mem;
	struct page		 *shared_mem_pages;
	unsigned int		  shared_mem_order;

	/*
	 * Task 2.2: Intel PT double-buffer state.
	 *
	 * Placed at END of struct to preserve all field offsets used by
	 * the assembly trampoline (guest_regs, launched, host_rsp etc.
	 * must remain at the same offsets as prior tasks).
	 *
	 * Initialised by phantom_pt_init() from the vCPU thread after
	 * VMXON + VMCS setup.  Torn down by phantom_pt_teardown() in the
	 * do_stop path before VMXOFF.
	 */
	struct phantom_pt_state	  pt;

	/*
	 * Task 2.4: VMX preemption timer.
	 *
	 * Computed once during phantom_vmcs_configure_fields() from
	 * MSR_IA32_VMX_MISC[4:0] (the timer shift) and tsc_khz.
	 * Set in the VMCS field VMX_PREEMPTION_TIMER_VALUE (0x482E) before
	 * each VM entry so the guest is forcibly evicted after ~1 second
	 * (configurable via PHANTOM_TIMEOUT_CLASS_A_MS).
	 *
	 * 0 means "timer not supported" — phantom_adjust_controls() cleared
	 * PIN_BASED_VMX_PREEMPTION_TIMER in the pin-based controls.
	 */
	u32			  preemption_timer_value;

	/*
	 * Task 3.1: Class B (Linux kernel) mode fields.
	 *
	 * class_b:            True when this vCPU runs a Linux guest kernel.
	 *
	 * snapshot_tsc:       TSC value at snapshot creation time.
	 *                     Used to compute TSC_OFFSET for the VMCS so the
	 *                     guest sees a monotonically increasing TSC from 0.
	 *
	 * guest_mem_mb:       Guest physical memory in MB.
	 *                     16 for Class A, 256 for Class B.
	 *
	 * kernel_entry_gpa:   GPA of the kernel entry point (for Class B boot).
	 *
	 * MSR shadows — emulated in phantom_handle_msr_read/write():
	 *   msr_apicbase:     IA32_APICBASE shadow (0xFEE00900).
	 *   msr_misc_enable:  IA32_MISC_ENABLE shadow (0x850089).
	 *   msr_mtrr_def_type: IA32_MTRR_DEF_TYPE shadow (0xC06).
	 *   msr_star/lstar/cstar/sfmask: syscall MSR shadows.
	 *   msr_kernel_gs_base: IA32_KERNEL_GS_BASE shadow.
	 *   msr_tsc_aux:      IA32_TSC_AUX shadow.
	 *   msr_mtrr_fix[11]: Fixed MTRR shadows (all default 0x0606...).
	 */
	bool			  class_b;
	u64			  snapshot_tsc;
	u32			  guest_mem_mb;
	u64			  kernel_entry_gpa;
	u64			  msr_apicbase;
	u64			  msr_misc_enable;
	u64			  msr_mtrr_def_type;
	u64			  msr_star;
	u64			  msr_lstar;
	u64			  msr_cstar;
	u64			  msr_sfmask;
	u64			  msr_kernel_gs_base;
	u64			  msr_tsc_aux;
	u64			  msr_mtrr_fix[11];

	/*
	 * Task 3.1: Class B EPT backing pages.
	 *
	 * The 256MB Class B EPT uses separate page arrays managed by
	 * phantom_ept_alloc_class_b() / phantom_ept_free_class_b() in
	 * guest_boot.c.  They are distinct from state->ept which holds
	 * the 16MB Class A EPT.
	 *
	 * class_b_ept_pml4:   EPT PML4 page (1 page).
	 * class_b_ept_pdpt:   EPT PDPT page (1 page).
	 * class_b_ept_pd:     EPT PD page (1 page, 128 active entries).
	 * class_b_pt_pages:   kvmalloc_array of 128 EPT PT pages.
	 * class_b_ram_pages:  kvmalloc_array of 65536 RAM backing pages.
	 * class_b_vmap_base:  writable vmap() window over all 65536 RAM pages.
	 */
	struct page		 *class_b_ept_pml4;
	struct page		 *class_b_ept_pdpt;
	struct page		 *class_b_ept_pd;
	struct page		**class_b_pt_pages;    /* 128 PT pages  */
	struct page		**class_b_ram_pages;   /* 65536 RAM pages */
	void			 *class_b_vmap_base;  /* writable vmap window over all RAM pages */

	/*
	 * Task 3.1: LAPIC MMIO EPT mapping.
	 *
	 * The Linux guest accesses the Local APIC at GPA 0xFEE00000.
	 * This GPA is in PDPT[3] (3-4GB range), outside the 256MB RAM window.
	 * We allocate one zeroed page for LAPIC MMIO and wire a separate
	 * PDPT[3] subtree for it so EPT violations at 0xFEE00000 don't abort boot.
	 *
	 * class_b_lapic_page:    backing page for LAPIC MMIO (4KB, zeroed).
	 * class_b_lapic_pd:      EPT PD page for PDPT[3] → covers 3-4GB.
	 * class_b_lapic_pt:      EPT PT page covering the 2MB slot with LAPIC.
	 */
	struct page		 *class_b_lapic_page;  /* LAPIC MMIO backing page */
	struct page		 *class_b_lapic_pd;    /* EPT PD for PDPT[3] */
	struct page		 *class_b_lapic_pt;    /* EPT PT for LAPIC 2MB slot */

	/*
	 * Task 2.4: Kernel-side guest heap tracker.
	 *
	 * The bare-metal guest has no OS and therefore no syscall handler.
	 * EFER_SCE is cleared so 'syscall' raises #UD.  The #UD exit handler
	 * intercepts 'syscall' (0F 05) and implements a minimal subset:
	 *   SYS_brk  (12) — extend heap via bump pointer
	 *   SYS_mmap  (9) — anonymous mmap via bump pointer
	 *   SYS_munmap(11) — no-op
	 *   SYS_write  (1) — silently succeed (drop stderr)
	 *
	 * guest_heap_ptr is reset to PHANTOM_GUEST_HEAP_BASE on every
	 * snapshot restore so that each iteration gets a clean heap.
	 * Range: [PHANTOM_GUEST_HEAP_BASE, PHANTOM_GUEST_HEAP_LIMIT).
	 */
	u64			  guest_heap_ptr;
	/*
	 * Task 3.1: Guest XCR0 — set by XSETBV VM-exit emulation.
	 * Applied at VM-entry, host XCR0 (xcr0_supported) restored at VM-exit.
	 * 0 = guest has not issued XSETBV yet.
	 */
	u64			  guest_xcr0;

	/*
	 * Task 3.1: Serial console line buffer for guest diagnostics.
	 * Accumulates COM1 (0x3F8) writes until newline, then logs to host dmesg.
	 */
	char			  serial_buf[256];
	int			  serial_buf_len;
};

DECLARE_PER_CPU(struct phantom_vmx_cpu_state, phantom_vmx_state);

/* ------------------------------------------------------------------
 * VMXON region layout (Intel SDM Vol. 3C §24.2)
 * ------------------------------------------------------------------ */
struct phantom_vmxon_region {
	__le32	revision_id;
	u8	reserved[4092];
} __packed;

/* ------------------------------------------------------------------
 * Feature detection results
 * ------------------------------------------------------------------ */
struct phantom_cpu_features {
	bool	vtx;
	bool	ept;
	bool	ept_4lvl;
	bool	ept_wb;
	bool	ept_2mb;
	bool	ept_ad;
	bool	intel_pt;
	bool	xsave;
	bool	true_ctls;
	u32	vmx_revision;
};

/* ------------------------------------------------------------------
 * VMCS read/write helpers (static inline — used in VMX-root context)
 *
 * VMWRITE takes (field, value); VMREAD takes (field) and returns value.
 * Both modify RFLAGS; we ignore the flags here — use the dedicated
 * VMLAUNCH/VMRESUME wrappers for error checking.
 * ------------------------------------------------------------------ */

static inline void phantom_vmcs_write64(u32 field, u64 val)
{
	asm volatile("vmwrite %1, %0"
		     :: "r"((u64)field), "rm"(val)
		     : "cc");
}

static inline void phantom_vmcs_write32(u32 field, u32 val)
{
	phantom_vmcs_write64(field, (u64)val);
}

static inline void phantom_vmcs_write16(u32 field, u16 val)
{
	phantom_vmcs_write64(field, (u64)val);
}

static inline u64 phantom_vmcs_read64(u32 field)
{
	u64 val;

	asm volatile("vmread %1, %0"
		     : "=rm"(val)
		     : "r"((u64)field)
		     : "cc");
	return val;
}

static inline u32 phantom_vmcs_read32(u32 field)
{
	return (u32)phantom_vmcs_read64(field);
}

static inline u16 phantom_vmcs_read16(u32 field)
{
	return (u16)phantom_vmcs_read64(field);
}

/* ------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------ */

int phantom_vmx_check_cpu_features(struct phantom_cpu_features *feat);

int phantom_vmxon_all(const struct cpumask *cpumask);
void phantom_vmxoff_all(const struct cpumask *cpumask);

int phantom_vmcs_alloc_all(const struct cpumask *cpumask);
void phantom_vmcs_free_all(const struct cpumask *cpumask);

/* Task 1.2: VMCS population and guest execution */

/**
 * phantom_vmcs_setup - Allocate and initialise all guest/EPT pages.
 *
 * MUST be called from process context (GFP_KERNEL allocation).
 * Safe to call multiple times — idempotent once pages_allocated is set.
 * Does NOT write any VMCS fields; call phantom_vmcs_configure_fields()
 * on the target CPU afterwards.
 */
int phantom_vmcs_setup(struct phantom_vmx_cpu_state *state);

/**
 * phantom_vmcs_configure_fields - Write VMCS control and state fields.
 *
 * MUST be called on the target CPU (VMCS must be current via VMPTRLD).
 * Safe in interrupt context — no sleeping allocations.
 * Idempotent once vmcs_configured is set.
 */
int phantom_vmcs_configure_fields(struct phantom_vmx_cpu_state *state);

void phantom_vmcs_teardown(struct phantom_vmx_cpu_state *state);

/**
 * phantom_run_guest - Enter guest and run until VM exit.
 * @state: Per-CPU VMX state with VMCS configured.
 *
 * Runs on the target CPU (caller must ensure this via the vCPU thread).
 * Returns 0 on expected exit (VMCALL result available),
 * negative errno on VM-entry failure.
 */
int phantom_run_guest(struct phantom_vmx_cpu_state *state);

/**
 * phantom_vcpu_thread_start - Start the per-CPU vCPU kernel thread.
 * @state: Per-CPU VMX state for the target CPU.
 *
 * Creates a kernel thread pinned to state->cpu.  The thread waits for
 * work signals via vcpu_run_start completion and executes guest runs.
 * Returns 0 on success, negative errno on failure.
 */
int phantom_vcpu_thread_start(struct phantom_vmx_cpu_state *state);

/**
 * phantom_vcpu_thread_stop - Stop and destroy the per-CPU vCPU thread.
 * @state: Per-CPU VMX state for the target CPU.
 *
 * Uses a two-phase IPI-free stop protocol:
 *   1. Sets vcpu_stop_requested (no IPI).
 *   2. Wakes Phase-1 sleeper via complete() if needed (safe — pre-VMLAUNCH).
 *   3. Waits on vcpu_stopped (thread signals after VMXOFF).
 *   4. Calls kthread_stop() for resource cleanup (safe — post-VMXOFF).
 */
void phantom_vcpu_thread_stop(struct phantom_vmx_cpu_state *state);

/**
 * phantom_vcpu_thread_wait_init - Wait for the vCPU thread's per-CPU init.
 * @state: Per-CPU VMX state for the target CPU.
 *
 * Blocks until the vCPU thread has completed VMXON + VMCS alloc + VMPTRLD
 * on its own CPU (no cross-CPU IPI involved).
 *
 * Returns 0 on success, negative errno if per-CPU init failed.
 */
int phantom_vcpu_thread_wait_init(struct phantom_vmx_cpu_state *state);

/**
 * phantom_vm_exit_return - VM exit landing pad (HOST_RIP target).
 *
 * This function is jumped to (not called) by the CPU hardware on VM exit.
 * It saves guest GPRs, restores host callee-saved registers, and returns
 * 0 to the caller of phantom_vmlaunch_trampoline.
 *
 * Declared __visible to prevent the compiler from removing it.
 */
__visible void phantom_vm_exit_return(void);

#endif /* PHANTOM_VMX_CORE_H */
