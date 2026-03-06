// SPDX-License-Identifier: GPL-2.0-only
/*
 * cpuid_emul.h — CPUID emulation for Phantom Class B guest
 *
 * Provides full CPUID leaf emulation for a Skylake-compatible virtual CPU.
 * Used when a Linux guest kernel executes CPUID to probe hardware capabilities.
 */
#ifndef PHANTOM_CPUID_EMUL_H
#define PHANTOM_CPUID_EMUL_H

#include "vmx_core.h"

/**
 * phantom_handle_cpuid - Emulate CPUID instruction exit.
 * @state: Per-CPU VMX state (guest_regs.rax = leaf, .rcx = sub-leaf on entry).
 *
 * Reads EAX (leaf) and ECX (sub-leaf) from state->guest_regs.
 * Writes EAX/EBX/ECX/EDX response into state->guest_regs.
 * Advances guest RIP by 2 (CPUID is a 2-byte instruction: 0F A2).
 *
 * Returns 0 (caller should VMRESUME).
 */
int phantom_handle_cpuid(struct phantom_vmx_cpu_state *state);

#endif /* PHANTOM_CPUID_EMUL_H */
