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
#include <asm/msr-index.h>

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
#define VMX_EXIT_VMCALL			18
#define VMX_EXIT_EPT_VIOLATION		48
#define VMX_EXIT_EPT_MISCONFIG		49
#define VMX_EXIT_PREEMPT_TIMER		52

/* ------------------------------------------------------------------
 * VMCS control field bit definitions
 * ------------------------------------------------------------------ */

/* Pin-based execution controls */
#define PIN_BASED_EXT_INT_EXITING	BIT(0)
#define PIN_BASED_NMI_EXITING		BIT(3)
#define PIN_BASED_VIRTUAL_NMIS		BIT(5)
#define PIN_BASED_PREEMPT_TIMER		BIT(6)

/* Primary proc-based execution controls */
#define CPU_BASED_HLT_EXITING		BIT(7)
#define CPU_BASED_UNCONDITIONAL_IO	BIT(24)
#define CPU_BASED_USE_MSR_BITMAPS	BIT(28)
#define CPU_BASED_SECONDARY_ENABLE	BIT(31)

/* Secondary proc-based execution controls */
#define SECONDARY_EXEC_ENABLE_EPT	BIT(1)
#define SECONDARY_EXEC_ENABLE_VPID	BIT(5)

/* VM-exit controls */
#define VM_EXIT_HOST_ADDR_SPACE_SIZE	BIT(9)
#define VM_EXIT_ACK_INT_ON_EXIT		BIT(15)
#define VM_EXIT_SAVE_IA32_PAT		BIT(18)
#define VM_EXIT_LOAD_IA32_PAT		BIT(19)
#define VM_EXIT_SAVE_IA32_EFER		BIT(20)
#define VM_EXIT_LOAD_IA32_EFER		BIT(21)

/* VM-entry controls */
#define VM_ENTRY_IA32E_MODE		BIT(9)
#define VM_ENTRY_LOAD_IA32_PAT		BIT(14)
#define VM_ENTRY_LOAD_IA32_EFER		BIT(15)

/* Segment access rights: unusable bit */
#define VMX_SEGMENT_AR_UNUSABLE		BIT(16)

/* ------------------------------------------------------------------
 * EPT constants
 * ------------------------------------------------------------------ */
#define EPT_PTE_READ			(1ULL << 0)
#define EPT_PTE_WRITE			(1ULL << 1)
#define EPT_PTE_EXEC			(1ULL << 2)
#define EPT_PTE_MEMTYPE_WB		(6ULL << 3)
#define EPT_PTE_PS			(1ULL << 7)  /* 2MB large page */

#define EPTP_MEMTYPE_WB			(6ULL << 0)
#define EPTP_PAGEWALK_4			(3ULL << 3)  /* 4-level walk */

/* Guest physical address of the trivial guest code */
#define GUEST_CODE_GPA			0x10000ULL
#define GUEST_STACK_GPA			0x11000ULL
#define GUEST_DATA_GPA			0x12000ULL
#define GUEST_PML4_GPA			0x13000ULL
#define GUEST_PDPT_GPA			0x14000ULL
#define GUEST_PD_GPA			0x15000ULL

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
	bool			 vmcs_configured;
	u64			 host_rsp;          /* saved by trampoline */
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
int phantom_vmcs_setup(struct phantom_vmx_cpu_state *state);
void phantom_vmcs_teardown(struct phantom_vmx_cpu_state *state);

/**
 * phantom_run_guest - Enter guest and run until VM exit.
 * @state: Per-CPU VMX state with VMCS configured.
 *
 * Runs on the target CPU (caller must ensure this via
 * smp_call_function_single or preemption disable).
 * Returns 0 on expected exit (VMCALL result available),
 * negative errno on VM-entry failure.
 */
int phantom_run_guest(struct phantom_vmx_cpu_state *state);

#endif /* PHANTOM_VMX_CORE_H */
