// SPDX-License-Identifier: GPL-2.0-only
/*
 * msr_emul.h — MSR read/write emulation for Phantom Class B guest
 *
 * Provides RDMSR/WRMSR exit handling and MSR bitmap setup for a Linux
 * guest kernel running in Phantom.  Emulates APIC, MTRR, EFER, syscall
 * MSRs, TSC, and other commonly accessed MSRs.
 */
#ifndef PHANTOM_MSR_EMUL_H
#define PHANTOM_MSR_EMUL_H

#include "vmx_core.h"

/**
 * phantom_msr_state_init - Initialise MSR shadow values to hardware defaults.
 * @state: Per-CPU VMX state.
 *
 * Called once during Class B guest setup (before VMCS configuration).
 * Sets sane default values for all emulated MSRs.
 */
void phantom_msr_state_init(struct phantom_vmx_cpu_state *state);

/**
 * phantom_handle_msr_read - Handle RDMSR VM exit (exit reason 31).
 * @state: Per-CPU VMX state (guest_regs.rcx = MSR number on entry).
 *
 * Emulates the requested MSR read.  On return, guest_regs.rax holds
 * the low 32 bits and guest_regs.rdx holds the high 32 bits of the
 * MSR value, matching the RDMSR result convention.
 *
 * Advances guest RIP by 2 (RDMSR is 0F 32).
 * Returns 0 (caller should VMRESUME).
 */
int phantom_handle_msr_read(struct phantom_vmx_cpu_state *state);

/**
 * phantom_handle_msr_write - Handle WRMSR VM exit (exit reason 32).
 * @state: Per-CPU VMX state (guest_regs.rcx = MSR number, rax/rdx = value).
 *
 * Emulates the requested MSR write.  The 64-bit value is constructed
 * from (rdx[31:0] << 32) | rax[31:0] per the WRMSR convention.
 *
 * Advances guest RIP by 2 (WRMSR is 0F 30).
 * Returns 0 (caller should VMRESUME).
 */
int phantom_handle_msr_write(struct phantom_vmx_cpu_state *state);

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
void phantom_msr_bitmap_setup_class_b(void *msr_bitmap);

#endif /* PHANTOM_MSR_EMUL_H */
