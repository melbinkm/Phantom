// SPDX-License-Identifier: GPL-2.0-only
/*
 * init_harness_nft.c - Phantom Class B nf_tables fuzzing harness.
 *
 * Built into the guest kernel as a late_initcall. Sends fuzz payload
 * as a NETLINK_NETFILTER message to exercise the nf_tables subsystem
 * parsing and validation paths.
 *
 * Attack surface: nfnetlink message dispatch → nf_tables handlers
 * (NFT_MSG_NEWTABLE, NFT_MSG_NEWCHAIN, NFT_MSG_NEWRULE, etc.)
 *
 * This is the same entry point targeted by real-world nf_tables exploits
 * (CVE-2023-32233, CVE-2024-1086, CVE-2022-34918, etc.)
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <linux/netfilter/nfnetlink.h>
#include <asm/page.h>

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

static struct socket *nl_sock;

static int __init phantom_nft_harness_init(void)
{
	volatile u32 *len_ptr = (volatile u32 *)__va(PHANTOM_PAYLOAD_GPA);
	volatile u8  *payload =
		(volatile u8 *)__va(PHANTOM_PAYLOAD_GPA + sizeof(u32));
	struct sockaddr_nl addr;
	struct msghdr msg;
	struct kvec iov;
	u32 len;
	int ret;

	pr_info("phantom-nft: starting nf_tables fuzzing harness\n");

	/* Create NETLINK_NETFILTER socket (kernel-space, equivalent to
	 * userspace socket(AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER)) */
	ret = sock_create_kern(&init_net, AF_NETLINK, SOCK_DGRAM,
			       NETLINK_NETFILTER, &nl_sock);
	if (ret < 0) {
		pr_err("phantom-nft: sock_create failed: %d\n", ret);
		phantom_vmcall(HC_PANIC, (u64)ret);
		return ret;
	}

	/* Bind to get a netlink port ID */
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	ret = kernel_bind(nl_sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		pr_err("phantom-nft: bind failed: %d\n", ret);
		sock_release(nl_sock);
		phantom_vmcall(HC_PANIC, (u64)ret);
		return ret;
	}

	pr_info("phantom-nft: netlink socket ready, entering fuzz loop\n");

	/* Register payload GPA with host, then take snapshot */
	phantom_vmcall(HC_GET_PAYLOAD, PHANTOM_PAYLOAD_GPA);
	phantom_vmcall(HC_ACQUIRE, 0);

	/*
	 * === FUZZ LOOP ===
	 * Everything below runs per iteration. HC_ACQUIRE above is the
	 * snapshot point — on each iteration, Phantom restores state to
	 * here and injects a new payload.
	 *
	 * The payload is treated as a raw netlink message (nlmsghdr +
	 * nfgenmsg + attributes). kernel_sendmsg() delivers it through
	 * the full netlink dispatch path to nfnetlink_rcv_msg(), which
	 * dispatches to the nf_tables callback for the message type.
	 */

	len = *len_ptr;
	if (len > PHANTOM_PAYLOAD_MAX)
		len = PHANTOM_PAYLOAD_MAX;

	/* Need at least nlmsghdr to be a valid netlink message */
	if (len < NLMSG_HDRLEN)
		goto release;

	/* Send fuzz payload as netlink message */
	memset(&msg, 0, sizeof(msg));
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;	/* destination: kernel */
	addr.nl_groups = 0;
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);

	iov.iov_base = (void *)payload;
	iov.iov_len = len;

	/* Errors are expected — malformed messages get rejected.
	 * We're fuzzing the parser, not looking for send errors. */
	kernel_sendmsg(nl_sock, &msg, &iov, 1, len);

release:
	phantom_vmcall(HC_RELEASE, 0);

	/* Should never reach here — HC_RELEASE restores to HC_ACQUIRE */
	pr_err("phantom-nft: RELEASE returned unexpectedly!\n");
	phantom_vmcall(HC_PANIC, 0);
	return 0;
}
late_initcall(phantom_nft_harness_init);
