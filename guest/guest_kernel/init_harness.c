// SPDX-License-Identifier: GPL-2.0-only
/*
 * init_harness.c - Phantom Class B guest kernel fuzzing harness.
 *
 * Built into the guest kernel as a late_initcall. Enters the Phantom
 * fuzzing loop by issuing VMCALL hypercalls to the host hypervisor
 * (HC_GET_PAYLOAD, HC_ACQUIRE, HC_RELEASE from the nyx_api ABI).
 *
 * Memory layout (GPAs, as agreed with Phantom host):
 *   0x600000: payload region — first 4 bytes = u32 length,
 *             followed by payload bytes (max 65532 bytes)
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>

/* Phantom nyx_api hypercall numbers (must match hypercall.h) */
#define HC_GET_PAYLOAD  0x11aULL
#define HC_ACQUIRE      0x11cULL
#define HC_RELEASE      0x11dULL
#define HC_PANIC        0x11eULL

/* Payload GPA agreed with host */
#define PHANTOM_PAYLOAD_GPA     0x600000UL
#define PHANTOM_PAYLOAD_MAX     65532U

static __always_inline void phantom_vmcall(u64 nr, u64 arg)
{
	asm volatile(
		"vmcall"
		:
		: "a" (nr), "b" (arg)
		: "memory", "cc"
	);
}

/*
 * Target function — replace with actual fuzzing target.
 * For now, just a no-op placeholder.
 */
static void __init phantom_fuzz_target(const u8 *data, u32 len)
{
	/* TODO: call kernel subsystem under test here */
	(void)data;
	(void)len;
}

static int __init phantom_harness_init(void)
{
	volatile u32 *len_ptr = (volatile u32 *)PHANTOM_PAYLOAD_GPA;
	volatile u8  *payload = (volatile u8 *)(PHANTOM_PAYLOAD_GPA + sizeof(u32));
	u32 len;

	pr_info("phantom-harness: init, registering payload at 0x%lx\n",
		PHANTOM_PAYLOAD_GPA);

	/* Register payload GPA with host, then take snapshot */
	phantom_vmcall(HC_GET_PAYLOAD, PHANTOM_PAYLOAD_GPA);
	phantom_vmcall(HC_ACQUIRE, 0);

	/*
	 * Everything below here runs inside the fuzz loop.
	 * HC_ACQUIRE above is the snapshot point — on each iteration,
	 * Phantom restores guest state to here and injects a new payload.
	 */

	len = *len_ptr;
	if (len == 0 || len > PHANTOM_PAYLOAD_MAX)
		len = 64;

	phantom_fuzz_target((const u8 *)payload, len);

	/* Signal end of iteration to host */
	phantom_vmcall(HC_RELEASE, 0);

	/*
	 * Should never reach here — HC_RELEASE triggers snapshot restore
	 * which rewinds execution back to HC_ACQUIRE above.
	 */
	pr_err("phantom-harness: RELEASE returned unexpectedly!\n");
	phantom_vmcall(HC_PANIC, 0);
	return 0;
}
late_initcall(phantom_harness_init);
