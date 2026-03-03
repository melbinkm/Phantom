// SPDX-License-Identifier: GPL-2.0-only
/*
 * nmi.h — NMI-exiting handler for phantom.ko
 *
 * With PIN_BASED_NMI_EXITING set, NMIs during guest execution cause a
 * VM exit (reason 0, interruption-info vector=2, type=2).  The handler
 * re-delivers the NMI to the host via APIC self-NMI — the same
 * technique used by KVM (kvm_inject_nmi / self_nmi).
 *
 * NMI handler is NMI-safe: no spinlocks, no non-reentrant structures
 * are accessed during exit handling.
 */
#ifndef PHANTOM_NMI_H
#define PHANTOM_NMI_H

/**
 * phantom_handle_nmi_exit - Handle an NMI VM exit.
 *
 * Called from the VM exit dispatcher when exit reason is
 * VMX_EXIT_EXCEPTION_NMI and the interruption-info field indicates
 * vector 2 (NMI) with valid bit set.
 *
 * Re-delivers the NMI to the host via APIC self-NMI write so that
 * the host NMI handler runs normally after VM exit returns.
 *
 * Must not hold spinlocks when called.  NMI-safe.
 */
void phantom_handle_nmi_exit(void);

#endif /* PHANTOM_NMI_H */
