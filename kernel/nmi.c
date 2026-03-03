// SPDX-License-Identifier: GPL-2.0-only
/*
 * nmi.c — NMI-exiting handler with APIC self-NMI re-delivery
 *
 * With NMI exiting enabled (pin-based control bit 3), any NMI that
 * arrives while the guest is running causes a VM exit rather than
 * being delivered to the guest.  We re-deliver it to the host using
 * an APIC self-NMI, which is the same approach used by KVM.
 *
 * This is NMI-safe: we do not acquire any locks, do not access any
 * non-reentrant kernel data structures, and the APIC write is
 * inherently reentrant.  The NMI fires through the host IDT normally
 * after the VM exit handler returns.
 *
 * Host configuration note: set nmi_watchdog=0 on dedicated fuzzing
 * cores to prevent the NMI watchdog from flooding the VM exit path.
 */

#include <linux/types.h>
#include <asm/apic.h>

#include "nmi.h"

/**
 * phantom_handle_nmi_exit - Re-deliver an NMI captured during guest execution.
 *
 * Called when VM exit reason is VMX_EXIT_EXCEPTION_NMI (0) and the
 * exit interruption-information field shows vector=2 (NMI), type=2,
 * valid bit set.
 *
 * Posts an NMI to the local APIC self-IPI destination.  The NMI will
 * fire through the host IDT after we return from the VM exit handler.
 */
void phantom_handle_nmi_exit(void)
{
	/*
	 * Re-deliver NMI to host via APIC self-NMI.
	 * APIC_DEST_SELF | APIC_DM_NMI | APIC_INT_ASSERT sets
	 * the ICR to send an NMI to the current APIC.
	 *
	 * KVM uses this same approach in kvm_inject_nmi() /
	 * self_nmi() — see arch/x86/kvm/x86.c.
	 *
	 * Do NOT use INT 2 — it does not set NMI-blocking and
	 * does not follow the NMI delivery path correctly.
	 */
	apic_write(APIC_ICR,
		   APIC_DEST_SELF | APIC_DM_NMI | APIC_INT_ASSERT);
}
