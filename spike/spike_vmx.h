// SPDX-License-Identifier: GPL-2.0-only
/*
 * spike_vmx.h — VMX constants, VMCS field encodings, inline asm wrappers
 *
 * Feasibility spike for Project Phantom.
 * This file contains the complete set of VMCS field hex IDs needed for the
 * spike's minimal guest launch, plus safe wrappers for VMXON/VMXOFF/VMLAUNCH/
 * VMRESUME and VMREAD/VMWRITE.
 *
 * Intel SDM Vol. 3C Appendix B lists all VMCS encodings.
 */

#ifndef SPIKE_VMX_H
#define SPIKE_VMX_H

#include <linux/types.h>
#include <linux/printk.h>
#include <asm/processor.h>
#include <asm/msr.h>

/* -----------------------------------------------------------------------
 * VMCS Control Fields
 * ----------------------------------------------------------------------- */

/* 16-bit control fields */
#define VMCS_VPID                       0x0000

/* 32-bit control fields */
#define VMCS_PIN_BASED_CTLS             0x4000
#define VMCS_PRI_PROC_BASED_CTLS        0x4002
#define VMCS_EXCEPTION_BITMAP           0x4004
#define VMCS_PF_ERROR_CODE_MASK         0x4006
#define VMCS_PF_ERROR_CODE_MATCH        0x4008
#define VMCS_EXIT_CTLS                  0x400c
#define VMCS_ENTRY_CTLS                 0x4012
#define VMCS_SEC_PROC_BASED_CTLS        0x401e

/* 64-bit control fields */
#define VMCS_MSR_BITMAP                 0x2004
#define VMCS_EPT_POINTER                0x201a

/* -----------------------------------------------------------------------
 * VMCS Guest-State Fields
 * ----------------------------------------------------------------------- */

/* 16-bit guest segment selectors */
#define VMCS_GUEST_ES_SEL               0x0800
#define VMCS_GUEST_CS_SEL               0x0802
#define VMCS_GUEST_SS_SEL               0x0804
#define VMCS_GUEST_DS_SEL               0x0806
#define VMCS_GUEST_FS_SEL               0x0808
#define VMCS_GUEST_GS_SEL               0x080a
#define VMCS_GUEST_LDTR_SEL             0x080c
#define VMCS_GUEST_TR_SEL               0x080e

/* 32-bit guest segment limits */
#define VMCS_GUEST_ES_LIMIT             0x4800
#define VMCS_GUEST_CS_LIMIT             0x4802
#define VMCS_GUEST_SS_LIMIT             0x4804
#define VMCS_GUEST_DS_LIMIT             0x4806
#define VMCS_GUEST_FS_LIMIT             0x4808
#define VMCS_GUEST_GS_LIMIT             0x480a
#define VMCS_GUEST_LDTR_LIMIT           0x480c
#define VMCS_GUEST_TR_LIMIT             0x480e
#define VMCS_GUEST_GDTR_LIMIT           0x4810
#define VMCS_GUEST_IDTR_LIMIT           0x4812

/* 32-bit guest segment access rights */
#define VMCS_GUEST_ES_AR                0x4814
#define VMCS_GUEST_CS_AR                0x4816
#define VMCS_GUEST_SS_AR                0x4818
#define VMCS_GUEST_DS_AR                0x481a
#define VMCS_GUEST_FS_AR                0x481c
#define VMCS_GUEST_GS_AR                0x481e
#define VMCS_GUEST_LDTR_AR              0x4820
#define VMCS_GUEST_TR_AR                0x4822

/* 32-bit guest MSR/misc fields */
#define VMCS_GUEST_INTERRUPTIBILITY     0x4824
#define VMCS_GUEST_ACTIVITY_STATE       0x4826
#define VMCS_GUEST_SYSENTER_CS          0x482a

/* 64-bit guest state */
#define VMCS_GUEST_VMCS_LINK_PTR        0x2800

/* Natural-width guest control registers */
#define VMCS_GUEST_CR0                  0x6800
#define VMCS_GUEST_CR3                  0x6802
#define VMCS_GUEST_CR4                  0x6804
#define VMCS_GUEST_ES_BASE              0x6806
#define VMCS_GUEST_CS_BASE              0x6808
#define VMCS_GUEST_SS_BASE              0x680a
#define VMCS_GUEST_DS_BASE              0x680c
#define VMCS_GUEST_FS_BASE              0x680e
#define VMCS_GUEST_GS_BASE              0x6810
#define VMCS_GUEST_LDTR_BASE            0x6812
#define VMCS_GUEST_TR_BASE              0x6814
#define VMCS_GUEST_GDTR_BASE            0x6816
#define VMCS_GUEST_IDTR_BASE            0x6818
#define VMCS_GUEST_DR7                  0x681a
#define VMCS_GUEST_RSP                  0x681c
#define VMCS_GUEST_RIP                  0x681e
#define VMCS_GUEST_RFLAGS               0x6820
#define VMCS_GUEST_PENDING_DBG_EXCEP    0x6822
#define VMCS_GUEST_SYSENTER_ESP         0x6824
#define VMCS_GUEST_SYSENTER_EIP         0x6826

/* -----------------------------------------------------------------------
 * VMCS Host-State Fields
 * ----------------------------------------------------------------------- */

/* 16-bit host segment selectors */
#define VMCS_HOST_ES_SEL                0x0c00
#define VMCS_HOST_CS_SEL                0x0c02
#define VMCS_HOST_SS_SEL                0x0c04
#define VMCS_HOST_DS_SEL                0x0c06
#define VMCS_HOST_FS_SEL                0x0c08
#define VMCS_HOST_GS_SEL                0x0c0a
#define VMCS_HOST_TR_SEL                0x0c0c  /* SDM Vol.3C App.B: 0x00000c0c */

/* Natural-width host state */
#define VMCS_HOST_CR0                   0x6c00
#define VMCS_HOST_CR3                   0x6c02
#define VMCS_HOST_CR4                   0x6c04
#define VMCS_HOST_FS_BASE               0x6c06
#define VMCS_HOST_GS_BASE               0x6c08
#define VMCS_HOST_TR_BASE               0x6c0a
#define VMCS_HOST_GDTR_BASE             0x6c0c
#define VMCS_HOST_IDTR_BASE             0x6c0e
#define VMCS_HOST_SYSENTER_ESP          0x6c10
#define VMCS_HOST_SYSENTER_EIP          0x6c12
#define VMCS_HOST_RSP                   0x6c14
#define VMCS_HOST_RIP                   0x6c16

/* 32-bit host MSR fields */
#define VMCS_HOST_SYSENTER_CS           0x4c00

/* -----------------------------------------------------------------------
 * VMCS Read-Only Data Fields
 * ----------------------------------------------------------------------- */

#define VMCS_VM_INSTR_ERROR             0x4400
#define VMCS_EXIT_REASON                0x4402
#define VMCS_EXIT_INTR_INFO             0x4404
#define VMCS_EXIT_INTR_ERR_CODE         0x4406
#define VMCS_IDT_VECTORING_INFO         0x4408
#define VMCS_IDT_VECTORING_ERR_CODE     0x440a
#define VMCS_EXIT_INSTR_LEN             0x440c
#define VMCS_EXIT_INSTR_INFO            0x440e
#define VMCS_EXIT_QUALIFICATION         0x6400
#define VMCS_GUEST_PHYS_ADDR            0x2400

/* -----------------------------------------------------------------------
 * VM Exit Reason Codes (Intel SDM Vol. 3C §27.9.1)
 * ----------------------------------------------------------------------- */

#define VMX_EXIT_EXCEPTION_NMI          0
#define VMX_EXIT_EXT_INTERRUPT          1
#define VMX_EXIT_TRIPLE_FAULT           2
#define VMX_EXIT_CPUID                  10
#define VMX_EXIT_HLT                    12
#define VMX_EXIT_VMCALL                 18
#define VMX_EXIT_CR_ACCESS              28  /* MOV to/from CR */
#define VMX_EXIT_MOV_DR                 29  /* MOV to/from DR */
#define VMX_EXIT_IO_INSTR               30  /* IN/OUT */
#define VMX_EXIT_RDMSR                  31
#define VMX_EXIT_WRMSR                  32
#define VMX_EXIT_EPT_VIOLATION          48
#define VMX_EXIT_EPT_MISCONFIG          49
#define VMX_EXIT_PREEMPT_TIMER          52

/* -----------------------------------------------------------------------
 * VM-Execution Control Bits
 * ----------------------------------------------------------------------- */

/* Pin-based controls */
#define PIN_BASED_NMI_EXITING           (1U << 3)
#define PIN_BASED_PREEMPT_TIMER         (1U << 6)

/* Primary processor-based controls */
#define PRI_PROC_HLT_EXITING            (1U << 7)
#define PRI_PROC_USE_MSR_BITMAPS        (1U << 28)
#define PRI_PROC_ENABLE_SECONDARY       (1U << 31)

/* Secondary processor-based controls */
#define SEC_PROC_ENABLE_EPT             (1U << 1)
#define SEC_PROC_ENABLE_VPID            (1U << 5)
#define SEC_PROC_UNRESTRICTED_GUEST     (1U << 7)

/* VM-exit controls */
#define VMEXIT_HOST_ADDR_SPACE_SIZE     (1U << 9)
#define VMEXIT_ACK_INTERRUPT_ON_EXIT    (1U << 15)

/* VM-entry controls */
#define VMENTRY_IA32E_MODE_GUEST        (1U << 9)

/* -----------------------------------------------------------------------
 * Segment Access Rights (packed format for VMCS AR fields)
 *
 * Intel SDM Vol. 3C §24.4.1 — Segment AR format mirrors descriptor bits
 * 55:52,47:40 with "unusable" bit at bit 16.
 * ----------------------------------------------------------------------- */

/* 64-bit code, DPL=0, P=1, S=1, type=0xb (execute/read/accessed) */
#define GUEST_CS_AR_64BIT               0xa09b
/* Data, DPL=0, P=1, S=1, type=3 (read/write/accessed), G=1, B=1 */
#define GUEST_DS_AR_NORMAL              0xc093
/* TR: type=0xb (64-bit busy TSS), P=1, S=0 */
#define GUEST_TR_AR                     0x008b
/* LDTR: unusable */
#define GUEST_LDTR_AR_UNUSABLE          0x00010000

/*
 * MSR definitions — use the kernel's own definitions from asm/msr-index.h
 * (included transitively via asm/msr.h).  We only define the ones that the
 * kernel does NOT define.
 */
#include <asm/msr-index.h>

/* EPTP memory type WB (6), page-walk length 4 (value 3 = 4-1) */
#define EPTP_FLAGS_WB_4LEVEL            ((6ULL) | (3ULL << 3))

/* -----------------------------------------------------------------------
 * Inline VMREAD / VMWRITE wrappers
 * ----------------------------------------------------------------------- */

static inline void vmcs_write32(u32 field, u32 val)
{
	u8 err;

	asm volatile("vmwrite %2, %1; setna %0"
		     : "=qm"(err)
		     : "r"((u64)field), "rm"((u64)val)
		     : "cc");
	if (unlikely(err))
		pr_err("spike: vmwrite32 field=0x%x val=0x%x failed\n",
		       field, val);
}

static inline void vmcs_write64(u32 field, u64 val)
{
	u8 err;

	asm volatile("vmwrite %2, %1; setna %0"
		     : "=qm"(err)
		     : "r"((u64)field), "rm"(val)
		     : "cc");
	if (unlikely(err))
		pr_err("spike: vmwrite64 field=0x%x val=0x%llx failed\n",
		       field, val);
}

static inline u64 vmcs_read64(u32 field)
{
	u64 val;

	asm volatile("vmread %1, %0"
		     : "=rm"(val)
		     : "r"((u64)field)
		     : "cc");
	return val;
}

static inline u32 vmcs_read32(u32 field)
{
	return (u32)vmcs_read64(field);
}

/* -----------------------------------------------------------------------
 * VMXON / VMXOFF / VMCLEAR / VMPTRLD helpers
 * ----------------------------------------------------------------------- */

/*
 * vmxon_safe() — execute VMXON and return 0 on success.
 * Returns -EBUSY if CF=1 (VMX already active or setup error).
 * Returns -EINVAL if ZF=1 (VM instruction error).
 */
static inline int vmxon_safe(u64 phys)
{
	u8 cf, zf;

	asm volatile("vmxon %2; setc %0; setz %1"
		     : "=qm"(cf), "=qm"(zf)
		     : "m"(phys)
		     : "cc", "memory");
	if (cf)
		return -EBUSY;
	if (zf)
		return -EINVAL;
	return 0;
}

static inline void vmxoff(void)
{
	asm volatile("vmxoff" ::: "cc");
}

/*
 * vmclear_safe() — VMCLEAR the given VMCS physical address.
 * Marks VMCS as not current/active on this logical processor.
 */
static inline int vmclear_safe(u64 phys)
{
	u8 cf, zf;

	asm volatile("vmclear %2; setc %0; setz %1"
		     : "=qm"(cf), "=qm"(zf)
		     : "m"(phys)
		     : "cc", "memory");
	if (cf || zf)
		return -EIO;
	return 0;
}

/*
 * vmptrld_safe() — load (make current) the VMCS at the given physical address.
 */
static inline int vmptrld_safe(u64 phys)
{
	u8 cf, zf;

	asm volatile("vmptrld %2; setc %0; setz %1"
		     : "=qm"(cf), "=qm"(zf)
		     : "m"(phys)
		     : "cc", "memory");
	if (cf || zf)
		return -EIO;
	return 0;
}

/*
 * vmlaunch_safe() — attempt VMLAUNCH; returns 0 only if CF=ZF=0.
 * A non-zero return means the instruction failed before launching the guest.
 * This is distinct from a successful launch followed by a VM exit.
 */
static inline int vmlaunch_safe(void)
{
	u8 cf, zf;

	asm volatile("vmlaunch; setc %0; setz %1"
		     : "=qm"(cf), "=qm"(zf)
		     :
		     : "cc", "memory");
	if (cf)
		return -EBUSY;
	if (zf)
		return -EINVAL;
	return 0;
}

/* -----------------------------------------------------------------------
 * Adjust VMX controls: enforce required bits from capability MSRs.
 *
 * Intel SDM §A.2: capability MSR layout
 *   bits [31:0]  — allowed-0 bits (must be 0 unless bit is 1 here)
 *   bits [63:32] — allowed-1 bits (may be 1 only if bit is 1 here)
 *
 * Returns adjusted value with mandatory bits set and reserved bits cleared.
 * ----------------------------------------------------------------------- */
static inline u32 adjust_vmx_controls(u32 ctl, u64 cap_msr)
{
	u32 allowed0 = (u32)(cap_msr);        /* bits that must be 1  */
	u32 allowed1 = (u32)(cap_msr >> 32);  /* bits that may  be 1  */

	ctl |= allowed0;
	ctl &= allowed1;
	return ctl;
}

#endif /* SPIKE_VMX_H */
