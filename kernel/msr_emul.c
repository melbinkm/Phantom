// SPDX-License-Identifier: GPL-2.0-only
/*
 * msr_emul.c - MSR read/write exit handling for Phantom Class B guest
 *
 * Handles RDMSR/WRMSR VM exits for Linux kernel boot. Maintains shadow
 * copies of MSRs that cannot be passed through (APICBASE, MISC_ENABLE,
 * MTRRs, syscall MSRs). Uses MSR bitmap to selectively exit only on
 * MSRs that need emulation; all others pass through to hardware.
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/vmx.h>
#include "msr_emul.h"
#include "vmx_core.h"

/* Fixed MTRR MSR base offsets relative to 0x250 */
#define MTRR_FIX_COUNT	11

/* IA32_APICBASE default: BSP bit (8) + xAPIC enable (11) + base 0xFEE00000 */
#define APICBASE_DEFAULT	0xFEE00900ULL
/* IA32_MISC_ENABLE default: fast-strings, PEBS, perf bias, XD disable */
#define MISC_ENABLE_DEFAULT	0x850089ULL
/* IA32_MTRR_DEF_TYPE default: MTRR enable (11) + type WB (6) */
#define MTRR_DEF_TYPE_DEFAULT	0xC06ULL
/* Fixed MTRR default: all ranges WC (type 6) */
#define MTRR_FIX_DEFAULT	0x0606060606060606ULL

/* IA32_ARCH_CAPABILITIES: no MDS/TAA/SRBDS mitigations needed in guest */
#define ARCH_CAP_GUEST_VAL	0ULL
/* IA32_SPEC_CTRL: no IBRS/STIBP/SSBD in guest */
#define SPEC_CTRL_GUEST_VAL	0ULL

/*
 * Fixed MTRR MSR numbers (Intel SDM Vol. 3A §11.11.2.2).
 *
 * Index mapping:
 *   0  = 0x250 (FIX64K_00000)
 *   1  = 0x258 (FIX16K_80000)
 *   2  = 0x259 (FIX16K_A0000)
 *   3  = 0x268 (FIX4K_C0000)
 *   4  = 0x269 (FIX4K_C8000)
 *   5  = 0x26A (FIX4K_D0000)
 *   6  = 0x26B (FIX4K_D8000)
 *   7  = 0x26C (FIX4K_E0000)
 *   8  = 0x26D (FIX4K_E8000)
 *   9  = 0x26E (FIX4K_F0000)
 *   10 = 0x26F (FIX4K_F8000)
 */
static const u32 mtrr_fix_msrs[MTRR_FIX_COUNT] = {
	0x250, 0x258, 0x259,
	0x268, 0x269, 0x26A, 0x26B, 0x26C, 0x26D, 0x26E, 0x26F,
};

/**
 * phantom_msr_state_init - Initialise MSR shadow values to hardware defaults.
 * @state: Per-CPU VMX state.
 *
 * Called once during Class B guest setup (before VMCS configuration).
 * Sets sane default values for all emulated MSRs.
 */
void phantom_msr_state_init(struct phantom_vmx_cpu_state *state)
{
	int i;

	state->msr_apicbase     = APICBASE_DEFAULT;
	state->msr_misc_enable  = MISC_ENABLE_DEFAULT;
	state->msr_mtrr_def_type = MTRR_DEF_TYPE_DEFAULT;

	for (i = 0; i < MTRR_FIX_COUNT; i++)
		state->msr_mtrr_fix[i] = MTRR_FIX_DEFAULT;

	state->msr_star           = 0;
	state->msr_lstar          = 0;
	state->msr_cstar          = 0;
	state->msr_sfmask         = 0;
	state->msr_kernel_gs_base = 0;
	state->msr_tsc_aux        = 0;
}

/* Advance guest RIP past a 2-byte RDMSR (0F 32) or WRMSR (0F 30). */
static void advance_rip(void)
{
	u32 ilen = phantom_vmcs_read32(VMCS_RO_EXIT_INSTR_LEN);
	u64 rip  = phantom_vmcs_read64(VMCS_GUEST_RIP);

	phantom_vmcs_write64(VMCS_GUEST_RIP, rip + ilen);
}

/**
 * phantom_handle_msr_read - Handle RDMSR VM exit (exit reason 31).
 * @state: Per-CPU VMX state (guest_regs.rcx = MSR number on entry).
 *
 * Emulates the requested MSR read.  On return, guest_regs.rax holds
 * the low 32 bits and guest_regs.rdx holds the high 32 bits of the
 * MSR value, matching the RDMSR result convention.
 *
 * Advances guest RIP by the instruction length.
 * Returns 0 (caller should VMRESUME).
 */
int phantom_handle_msr_read(struct phantom_vmx_cpu_state *state)
{
	u32 msr_nr = (u32)state->guest_regs.rcx;
	u64 val = 0;
	int i;

	switch (msr_nr) {
	/* TSC: return guest-relative TSC from snapshot time */
	case 0x10: /* IA32_TSC */
		val = state->snapshot_tsc;
		break;

	/* APICBASE */
	case 0x1B: /* IA32_APICBASE */
		val = state->msr_apicbase;
		break;

	/* SPEC_CTRL */
	case 0x48: /* IA32_SPEC_CTRL */
		val = SPEC_CTRL_GUEST_VAL;
		break;

	/* ARCH_CAPABILITIES */
	case 0x10A: /* IA32_ARCH_CAPABILITIES */
		val = ARCH_CAP_GUEST_VAL;
		break;

	/* MISC_ENABLE */
	case 0x1A0: /* IA32_MISC_ENABLE */
		val = state->msr_misc_enable;
		break;

	/* SYSENTER MSRs — live in the VMCS guest-state area */
	case 0x174: /* IA32_SYSENTER_CS */
		val = (u64)phantom_vmcs_read32(VMCS_GUEST_IA32_SYSENTER_CS);
		break;
	case 0x175: /* IA32_SYSENTER_ESP */
		val = phantom_vmcs_read64(VMCS_GUEST_IA32_SYSENTER_ESP);
		break;
	case 0x176: /* IA32_SYSENTER_EIP */
		val = phantom_vmcs_read64(VMCS_GUEST_IA32_SYSENTER_EIP);
		break;

	/* PAT — live in the VMCS guest-state area */
	case 0x277: /* IA32_PAT */
		val = phantom_vmcs_read64(VMCS_GUEST_IA32_PAT);
		break;

	/* MTRR_DEF_TYPE */
	case 0x2FF: /* IA32_MTRR_DEF_TYPE */
		val = state->msr_mtrr_def_type;
		break;

	/* Fixed MTRRs: 0x250, 0x258–0x259, 0x268–0x26F */
	case 0x250:
	case 0x258:
	case 0x259:
	case 0x268:
	case 0x269:
	case 0x26A:
	case 0x26B:
	case 0x26C:
	case 0x26D:
	case 0x26E:
	case 0x26F:
		for (i = 0; i < MTRR_FIX_COUNT; i++) {
			if (mtrr_fix_msrs[i] == msr_nr) {
				val = state->msr_mtrr_fix[i];
				break;
			}
		}
		break;

	/* EFER — live in the VMCS guest-state area */
	case 0xC0000080: /* IA32_EFER */
		val = phantom_vmcs_read64(VMCS_GUEST_IA32_EFER);
		break;

	/* Syscall MSRs */
	case 0xC0000081: /* IA32_STAR */
		val = state->msr_star;
		break;
	case 0xC0000082: /* IA32_LSTAR */
		val = state->msr_lstar;
		break;
	case 0xC0000083: /* IA32_CSTAR */
		val = state->msr_cstar;
		break;
	case 0xC0000084: /* IA32_FMASK / IA32_SFMASK */
		val = state->msr_sfmask;
		break;

	/* FS/GS base — live in the VMCS guest-state area */
	case 0xC0000100: /* IA32_FS_BASE */
		val = phantom_vmcs_read64(VMCS_GUEST_FS_BASE);
		break;
	case 0xC0000101: /* IA32_GS_BASE */
		val = phantom_vmcs_read64(VMCS_GUEST_GS_BASE);
		break;

	/* KERNEL_GS_BASE and TSC_AUX */
	case 0xC0000102: /* IA32_KERNEL_GS_BASE */
		val = state->msr_kernel_gs_base;
		break;
	case 0xC0000103: /* IA32_TSC_AUX */
		val = state->msr_tsc_aux;
		break;

	default:
		pr_warn_ratelimited("phantom: CPU%d: unhandled RDMSR 0x%x — returning 0\n",
				    state->cpu, msr_nr);
		val = 0;
		break;
	}

	state->guest_regs.rax = val & 0xFFFFFFFFULL;
	state->guest_regs.rdx = val >> 32;
	advance_rip();
	return 0;
}

/**
 * phantom_handle_msr_write - Handle WRMSR VM exit (exit reason 32).
 * @state: Per-CPU VMX state (guest_regs.rcx = MSR number, rax/rdx = value).
 *
 * Emulates the requested MSR write.  The 64-bit value is constructed
 * from (rdx[31:0] << 32) | rax[31:0] per the WRMSR convention.
 *
 * Advances guest RIP by the instruction length.
 * Returns 0 (caller should VMRESUME).
 */
int phantom_handle_msr_write(struct phantom_vmx_cpu_state *state)
{
	u32 msr_nr = (u32)state->guest_regs.rcx;
	u64 val = ((state->guest_regs.rdx & 0xFFFFFFFFULL) << 32) |
		   (state->guest_regs.rax & 0xFFFFFFFFULL);
	int i;

	switch (msr_nr) {
	/* SPEC_CTRL and PRED_CMD: silently ignore */
	case 0x48: /* IA32_SPEC_CTRL */
	case 0x49: /* IA32_PRED_CMD */
		break;

	/* APICBASE: update shadow */
	case 0x1B: /* IA32_APICBASE */
		state->msr_apicbase = val;
		break;

	/* MISC_ENABLE: update shadow */
	case 0x1A0: /* IA32_MISC_ENABLE */
		state->msr_misc_enable = val;
		break;

	/* MTRR_DEF_TYPE: update shadow */
	case 0x2FF: /* IA32_MTRR_DEF_TYPE */
		state->msr_mtrr_def_type = val;
		break;

	/* Fixed MTRRs: update shadow */
	case 0x250:
	case 0x258:
	case 0x259:
	case 0x268:
	case 0x269:
	case 0x26A:
	case 0x26B:
	case 0x26C:
	case 0x26D:
	case 0x26E:
	case 0x26F:
		for (i = 0; i < MTRR_FIX_COUNT; i++) {
			if (mtrr_fix_msrs[i] == msr_nr) {
				state->msr_mtrr_fix[i] = val;
				break;
			}
		}
		break;

	/* SYSENTER MSRs — write to VMCS guest-state */
	case 0x174: /* IA32_SYSENTER_CS */
		phantom_vmcs_write32(VMCS_GUEST_IA32_SYSENTER_CS, (u32)val);
		break;
	case 0x175: /* IA32_SYSENTER_ESP */
		phantom_vmcs_write64(VMCS_GUEST_IA32_SYSENTER_ESP, val);
		break;
	case 0x176: /* IA32_SYSENTER_EIP */
		phantom_vmcs_write64(VMCS_GUEST_IA32_SYSENTER_EIP, val);
		break;

	/* PAT — write to VMCS guest-state */
	case 0x277: /* IA32_PAT */
		phantom_vmcs_write64(VMCS_GUEST_IA32_PAT, val);
		break;

	/* EFER — write to VMCS guest-state */
	case 0xC0000080: /* IA32_EFER */
		phantom_vmcs_write64(VMCS_GUEST_IA32_EFER, val);
		break;

	/* FS/GS base — write to VMCS guest-state */
	case 0xC0000100: /* IA32_FS_BASE */
		phantom_vmcs_write64(VMCS_GUEST_FS_BASE, val);
		break;
	case 0xC0000101: /* IA32_GS_BASE */
		phantom_vmcs_write64(VMCS_GUEST_GS_BASE, val);
		break;

	/* Syscall MSRs — update shadows */
	case 0xC0000081: /* IA32_STAR */
		state->msr_star = val;
		break;
	case 0xC0000082: /* IA32_LSTAR */
		state->msr_lstar = val;
		break;
	case 0xC0000083: /* IA32_CSTAR */
		state->msr_cstar = val;
		break;
	case 0xC0000084: /* IA32_FMASK / IA32_SFMASK */
		state->msr_sfmask = val;
		break;

	/* KERNEL_GS_BASE and TSC_AUX — update shadows */
	case 0xC0000102: /* IA32_KERNEL_GS_BASE */
		state->msr_kernel_gs_base = val;
		break;
	case 0xC0000103: /* IA32_TSC_AUX */
		state->msr_tsc_aux = val;
		break;

	default:
		pr_warn_ratelimited("phantom: CPU%d: unhandled WRMSR 0x%x val=0x%llx — ignored\n",
				    state->cpu, msr_nr, val);
		break;
	}

	advance_rip();
	return 0;
}

/*
 * set_msr_bitmap_bit - Set one exit bit in the MSR bitmap.
 * @bm:           Base of the 4KB MSR bitmap page.
 * @section_base: Byte offset of the bitmap section (0, 1024, 2048, or 3072).
 * @msr_low:      Bit index within the section (MSR number within range).
 */
static void set_msr_bitmap_bit(u8 *bm, u32 section_base, u32 msr_low)
{
	bm[section_base + msr_low / 8] |= (1u << (msr_low % 8));
}

/**
 * phantom_msr_bitmap_setup_class_b - Configure MSR bitmap for Class B.
 * @msr_bitmap: Pointer to the 4KB MSR bitmap page (kernel virtual address).
 *
 * Sets read and write exit bits for all MSRs emulated by this module.
 * MSRs NOT in the bitmap use hardware passthrough (no exit).
 *
 * The bitmap layout (Intel SDM Vol. 3C §25.6.9):
 *   Bytes    0–1023: read exits for MSRs  0x0000–0x1FFF
 *   Bytes 1024–2047: read exits for MSRs  0xC0000000–0xC0001FFF
 *   Bytes 2048–3071: write exits for MSRs 0x0000–0x1FFF
 *   Bytes 3072–4095: write exits for MSRs 0xC0000000–0xC0001FFF
 */
void phantom_msr_bitmap_setup_class_b(void *msr_bitmap)
{
	u8 *bm = (u8 *)msr_bitmap;
	int i;

	/*
	 * Low MSR read exits (section 0, bytes 0–1023): MSR 0x0000–0x1FFF.
	 * Intercept: TSC(0x10), APICBASE(0x1B), SPEC_CTRL(0x48),
	 *            PRED_CMD(0x49), MISC_ENABLE(0x1A0), ARCH_CAP(0x10A),
	 *            PAT(0x277), MTRR_DEF_TYPE(0x2FF),
	 *            SYSENTER_CS/ESP/EIP(0x174–0x176),
	 *            fixed MTRRs(0x250, 0x258–0x259, 0x268–0x26F).
	 */
	set_msr_bitmap_bit(bm, 0,    0x10);   /* IA32_TSC */
	set_msr_bitmap_bit(bm, 0,    0x1B);   /* IA32_APICBASE */
	set_msr_bitmap_bit(bm, 0,    0x48);   /* IA32_SPEC_CTRL */
	set_msr_bitmap_bit(bm, 0,    0x49);   /* IA32_PRED_CMD */
	set_msr_bitmap_bit(bm, 0,    0x10A);  /* IA32_ARCH_CAPABILITIES */
	set_msr_bitmap_bit(bm, 0,    0x174);  /* IA32_SYSENTER_CS */
	set_msr_bitmap_bit(bm, 0,    0x175);  /* IA32_SYSENTER_ESP */
	set_msr_bitmap_bit(bm, 0,    0x176);  /* IA32_SYSENTER_EIP */
	set_msr_bitmap_bit(bm, 0,    0x1A0);  /* IA32_MISC_ENABLE */
	set_msr_bitmap_bit(bm, 0,    0x250);  /* IA32_MTRR_FIX64K_00000 */
	set_msr_bitmap_bit(bm, 0,    0x258);  /* IA32_MTRR_FIX16K_80000 */
	set_msr_bitmap_bit(bm, 0,    0x259);  /* IA32_MTRR_FIX16K_A0000 */
	set_msr_bitmap_bit(bm, 0,    0x277);  /* IA32_PAT */
	for (i = 0; i <= 7; i++)
		set_msr_bitmap_bit(bm, 0, 0x268 + i); /* FIX4K_C0000–F8000 */
	set_msr_bitmap_bit(bm, 0,    0x2FF);  /* IA32_MTRR_DEF_TYPE */

	/*
	 * High MSR read exits (section 1024, bytes 1024–2047):
	 * MSR 0xC0000000–0xC0001FFF, bit index = msr - 0xC0000000.
	 */
	set_msr_bitmap_bit(bm, 1024, 0x80);   /* IA32_EFER */
	set_msr_bitmap_bit(bm, 1024, 0x81);   /* IA32_STAR */
	set_msr_bitmap_bit(bm, 1024, 0x82);   /* IA32_LSTAR */
	set_msr_bitmap_bit(bm, 1024, 0x83);   /* IA32_CSTAR */
	set_msr_bitmap_bit(bm, 1024, 0x84);   /* IA32_FMASK */
	set_msr_bitmap_bit(bm, 1024, 0x100);  /* IA32_FS_BASE */
	set_msr_bitmap_bit(bm, 1024, 0x101);  /* IA32_GS_BASE */
	set_msr_bitmap_bit(bm, 1024, 0x102);  /* IA32_KERNEL_GS_BASE */
	set_msr_bitmap_bit(bm, 1024, 0x103);  /* IA32_TSC_AUX */

	/*
	 * Low MSR write exits (section 2048, bytes 2048–3071).
	 * Same low MSRs as the read section.
	 */
	set_msr_bitmap_bit(bm, 2048, 0x10);
	set_msr_bitmap_bit(bm, 2048, 0x1B);
	set_msr_bitmap_bit(bm, 2048, 0x48);
	set_msr_bitmap_bit(bm, 2048, 0x49);
	set_msr_bitmap_bit(bm, 2048, 0x10A);
	set_msr_bitmap_bit(bm, 2048, 0x174);
	set_msr_bitmap_bit(bm, 2048, 0x175);
	set_msr_bitmap_bit(bm, 2048, 0x176);
	set_msr_bitmap_bit(bm, 2048, 0x1A0);
	set_msr_bitmap_bit(bm, 2048, 0x250);
	set_msr_bitmap_bit(bm, 2048, 0x258);
	set_msr_bitmap_bit(bm, 2048, 0x259);
	set_msr_bitmap_bit(bm, 2048, 0x277);
	for (i = 0; i <= 7; i++)
		set_msr_bitmap_bit(bm, 2048, 0x268 + i);
	set_msr_bitmap_bit(bm, 2048, 0x2FF);

	/*
	 * High MSR write exits (section 3072, bytes 3072–4095).
	 * Same high MSRs as the read section.
	 */
	set_msr_bitmap_bit(bm, 3072, 0x80);
	set_msr_bitmap_bit(bm, 3072, 0x81);
	set_msr_bitmap_bit(bm, 3072, 0x82);
	set_msr_bitmap_bit(bm, 3072, 0x83);
	set_msr_bitmap_bit(bm, 3072, 0x84);
	set_msr_bitmap_bit(bm, 3072, 0x100);
	set_msr_bitmap_bit(bm, 3072, 0x101);
	set_msr_bitmap_bit(bm, 3072, 0x102);
	set_msr_bitmap_bit(bm, 3072, 0x103);
}
