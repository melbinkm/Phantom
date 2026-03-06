// SPDX-License-Identifier: GPL-2.0-only
/*
 * cpuid_emul.c — CPUID leaf emulation for Phantom Class B guest
 *
 * Emulates a Skylake-compatible (family 6, model 0x5E, stepping 3)
 * virtual CPU for the Linux guest kernel.  All leaves follow Intel SDM
 * Volume 2A §CPUID encoding.
 *
 * Hot-path discipline: no printk, no sleeping functions.
 * trace_printk only under PHANTOM_DEBUG.
 */

#include <linux/types.h>
#include <linux/kernel.h>

#include "vmx_core.h"
#include "cpuid_emul.h"

/* ------------------------------------------------------------------
 * CPU brand string: "Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz"
 * Split across leaves 0x80000002, 0x80000003, 0x80000004.
 * Each leaf returns 16 ASCII bytes in EAX:EBX:ECX:EDX (LE order).
 * ------------------------------------------------------------------ */
static const char phantom_cpu_brand[48] =
	"Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz\0\0\0\0\0\0\0";

/**
 * phantom_handle_cpuid - Emulate CPUID instruction exit.
 * @state: Per-CPU VMX state.
 *
 * Returns 0 (caller should VMRESUME).
 */
int phantom_handle_cpuid(struct phantom_vmx_cpu_state *state)
{
	u32 leaf    = (u32)state->guest_regs.rax;
	u32 subleaf = (u32)state->guest_regs.rcx;
	u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
	u64 rip;

	switch (leaf) {
	case 0x00000000:
		/* Maximum basic leaf + "GenuineIntel" */
		eax = 0x16;
		ebx = 0x756E6547; /* "Genu" */
		edx = 0x49656E69; /* "ineI" */
		ecx = 0x6C65746E; /* "ntel" */
		break;

	case 0x00000001:
		/* Family/model/stepping + feature flags */
		/* Skylake: family 6, model 0x5E, stepping 3 */
		eax = 0x000506E3;
		ebx = 0x00010800; /* APIC ID=1, CLFLUSH=8, MaxLogical=1 */
		/* ECX: features; mask RDRAND (bit 30) for determinism */
		ecx = 0x7FFAFBFF & ~BIT(30);
		edx = 0x0F8BFBFF;
		break;

	case 0x00000002:
		/* Cache/TLB descriptors */
		eax = 0x76036301;
		ebx = 0x00000000;
		ecx = 0x00000000;
		edx = 0x00F0B5FF;
		break;

	case 0x00000004:
		/* Deterministic cache parameters */
		switch (subleaf) {
		case 0: /* L1 data cache */
			eax = 0x1C004121; /* 4-way, 32B line, 64 sets */
			ebx = 0x01C0003F;
			ecx = 0x0000003F; /* 64 sets */
			edx = 0x00000000;
			break;
		case 1: /* L1 instruction cache */
			eax = 0x1C004122;
			ebx = 0x01C0003F;
			ecx = 0x0000003F;
			edx = 0x00000000;
			break;
		case 2: /* L2 unified cache */
			eax = 0x1C004143; /* 8-way, 64B line */
			ebx = 0x03C0003F;
			ecx = 0x000003FF; /* 1024 sets */
			edx = 0x00000001;
			break;
		case 3: /* L3 unified cache */
			eax = 0x2C004163; /* 12-way, 64B line */
			ebx = 0x03C0003F;
			ecx = 0x00001FFF; /* 8192 sets */
			edx = 0x00000006;
			break;
		default:
			eax = 0; /* no more caches */
			break;
		}
		break;

	case 0x00000006:
		/* Thermal and power management */
		/* ARAT (bit 2): APIC timer always running */
		eax = 0x00000004;
		ebx = 0x00000000;
		ecx = 0x00000000;
		edx = 0x00000000;
		break;

	case 0x00000007:
		/* Structured Extended Feature Flags */
		if (subleaf == 0) {
			eax = 0x00000000; /* max sub-leaf */
			/* EBX: mask RDSEED (bit 18) for determinism */
			ebx = 0x209C01A9 & ~BIT(18);
			ecx = 0x00000000;
			edx = 0x00000000;
		}
		break;

	case 0x0000000B:
		/* Extended Topology Enumeration */
		switch (subleaf) {
		case 0: /* SMT level */
			eax = 0x00000001; /* 2^1 = 2 threads per core */
			ebx = 0x00000001; /* 1 logical processor at this level */
			ecx = 0x00000100; /* level type: SMT */
			edx = 0x00000000; /* x2APIC ID */
			break;
		case 1: /* Core level */
			eax = 0x00000004; /* 2^4 = 16 logical per package */
			ebx = 0x00000001; /* 1 core */
			ecx = 0x00000201; /* level type: core */
			edx = 0x00000000;
			break;
		default:
			eax = 0x00000000;
			ebx = 0x00000000;
			ecx = subleaf;
			edx = 0x00000000;
			break;
		}
		break;

	case 0x0000000D:
		/* Processor Extended State Enumeration (XSAVE) */
		switch (subleaf) {
		case 0: /* x87 + SSE + AVX supported */
			eax = 0x00000207; /* x87=bit0, SSE=bit1, AVX=bit2 */
			ebx = 0x00000340; /* XSAVE area size */
			ecx = 0x00000340; /* max XSAVE area size */
			edx = 0x00000000;
			break;
		case 1: /* XSAVEOPT + XSAVEC */
			eax = 0x0000000F;
			ebx = 0x00000000;
			ecx = 0x00000000;
			edx = 0x00000000;
			break;
		default:
			break;
		}
		break;

	case 0x00000015:
		/* TSC/Crystal clock ratio */
		/* Crystal ratio: TSC = crystal × EBX/EAX */
		eax = 0x00000001; /* crystal period denominator */
		ebx = 0x00000048; /* crystal period numerator (72) */
		ecx = 0x016E3600; /* crystal frequency 24MHz */
		edx = 0x00000000;
		break;

	case 0x00000016:
		/* Processor frequency information */
		eax = 0x00000FA0; /* base freq 4000 MHz */
		ebx = 0x00000FA0; /* max freq  4000 MHz */
		ecx = 0x00000064; /* bus freq   100 MHz */
		edx = 0x00000000;
		break;

	case 0x80000000:
		/* Max extended leaf */
		eax = 0x80000008;
		break;

	case 0x80000001:
		/* Extended processor signature and feature flags */
		eax = 0x00000000;
		ebx = 0x00000000;
		ecx = 0x00000121; /* LAHF, CMP_LEGACY, ABM */
		edx = 0x2C100800; /* LM + NX + RDTSCP + FXSR + MMX */
		break;

	case 0x80000002:
	case 0x80000003:
	case 0x80000004: {
		/* CPU brand string — 16 bytes per leaf */
		const u32 *brand_u32 =
			(const u32 *)(phantom_cpu_brand +
				      (leaf - 0x80000002) * 16);
		eax = brand_u32[0];
		ebx = brand_u32[1];
		ecx = brand_u32[2];
		edx = brand_u32[3];
		break;
	}

	case 0x80000007:
		/* Advanced Power Management */
		eax = 0x00000000;
		ebx = 0x00000000;
		ecx = 0x00000000;
		edx = 0x00000100; /* invariant TSC (bit 8) */
		break;

	case 0x80000008:
		/* Address sizes */
		eax = 0x00003030; /* 48-bit VA, 36-bit PA */
		ebx = 0x00000000;
		ecx = 0x00000000;
		edx = 0x00000000;
		break;

	default:
		/* Unsupported leaf: return all zeros */
		eax = 0;
		ebx = 0;
		ecx = 0;
		edx = 0;
		break;
	}

	state->guest_regs.rax = eax;
	state->guest_regs.rbx = ebx;
	state->guest_regs.rcx = ecx;
	state->guest_regs.rdx = edx;

	/* Advance RIP past the 2-byte CPUID instruction (0F A2) */
	rip = phantom_vmcs_read64(VMCS_GUEST_RIP);
	phantom_vmcs_write64(VMCS_GUEST_RIP, rip + 2);

	return 0;
}
EXPORT_SYMBOL_GPL(phantom_handle_cpuid);
