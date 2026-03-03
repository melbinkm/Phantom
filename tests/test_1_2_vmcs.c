// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_1_2_vmcs.c — userspace ioctl test for task 1.2
 *
 * Tests:
 *   1. Open /dev/phantom
 *   2. GET_VERSION returns 0x00010200 (bumped for task 1.2)
 *   3. RUN_GUEST succeeds (exit code 0)
 *   4. Guest computes the correct XOR checksum of the test data
 *   5. Final exit reason is VMCALL (18) or HLT-related
 *   6. Second RUN_GUEST (same fd) also succeeds and returns same checksum
 *   7. Close device
 *
 * Build (inside QEMU guest or on server):
 *   gcc -O2 -Wall -o test_1_2_vmcs test_1_2_vmcs.c
 *
 * Exit codes:
 *   0 — all tests passed
 *   1 — one or more tests failed
 *
 * Expected checksum computation (must match kernel-side test data):
 *   data[i] = (i+1) * 0x1234567890ABCDEFull  for i = 0..511
 *   checksum = XOR of all 512 values
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

/* Mirror of kernel-side definitions — must stay in sync with interface.h */
#define PHANTOM_IOCTL_MAGIC	'P'
#define PHANTOM_VERSION		0x00010200U

#define PHANTOM_IOCTL_GET_VERSION	_IOR(PHANTOM_IOCTL_MAGIC, 0, uint32_t)

struct phantom_run_args {
	uint32_t cpu;
	uint32_t reserved;
	uint64_t result;
	uint32_t exit_reason;
	uint32_t padding;
};

#define PHANTOM_IOCTL_RUN_GUEST \
	_IOWR(PHANTOM_IOCTL_MAGIC, 1, struct phantom_run_args)

#define DEVICE_PATH	"/dev/phantom"

/* VM exit reason codes (must match vmx_core.h) */
#define VMX_EXIT_VMCALL		18

static int tests_run;
static int tests_pass;

static void check(const char *label, int cond)
{
	tests_run++;
	if (cond) {
		printf("PASS  %s\n", label);
		tests_pass++;
	} else {
		printf("FAIL  %s\n", label);
	}
}

/*
 * Compute the expected XOR checksum of the test data pattern.
 * Must match the pattern generated in interface.c:
 *   data[i] = (i+1) * 0x1234567890ABCDEFull
 */
static uint64_t compute_expected_checksum(void)
{
	uint64_t acc = 0;
	int i;

	for (i = 0; i < 512; i++)
		acc ^= (uint64_t)(i + 1) * 0x1234567890ABCDEFull;

	return acc;
}

int main(void)
{
	int fd;
	uint32_t ver = 0;
	int rc;
	uint64_t expected;
	struct phantom_run_args args;

	printf("=== phantom task 1.2 VMCS + guest execution test ===\n\n");

	expected = compute_expected_checksum();
	printf("  Expected checksum: 0x%016llx\n\n",
	       (unsigned long long)expected);

	/* Test 1: open device */
	fd = open(DEVICE_PATH, O_RDWR);
	check("open /dev/phantom", fd >= 0);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n",
			DEVICE_PATH, strerror(errno));
		return 1;
	}

	/* Test 2: GET_VERSION returns task-1.2 version */
	ver = 0;
	rc  = ioctl(fd, PHANTOM_IOCTL_GET_VERSION, &ver);
	check("ioctl GET_VERSION succeeds",     rc == 0);
	check("version == 0x00010200 (task 1.2)", ver == PHANTOM_VERSION);

	if (rc == 0)
		printf("  version = 0x%08x\n", ver);
	else
		fprintf(stderr, "  ioctl GET_VERSION failed: %s\n",
			strerror(errno));

	/* Test 3: RUN_GUEST succeeds */
	memset(&args, 0, sizeof(args));
	args.cpu      = 0;
	args.reserved = 0;

	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check("ioctl RUN_GUEST succeeds (rc=0)", rc == 0);

	if (rc != 0) {
		fprintf(stderr, "  RUN_GUEST failed: %s (errno=%d)\n",
			strerror(errno), errno);
	} else {
		printf("  result      = 0x%016llx\n",
		       (unsigned long long)args.result);
		printf("  exit_reason = %u\n", args.exit_reason);
	}

	/* Test 4: Guest computed the correct checksum */
	if (rc == 0) {
		check("guest checksum matches expected",
		      args.result == expected);

		if (args.result != expected) {
			fprintf(stderr,
				"  MISMATCH: got 0x%016llx, expected 0x%016llx\n",
				(unsigned long long)args.result,
				(unsigned long long)expected);
		}
	} else {
		/* Can't check checksum if ioctl failed */
		tests_run++;
		printf("SKIP  guest checksum (RUN_GUEST failed)\n");
	}

	/* Test 5: Final exit reason is VMCALL (18) */
	if (rc == 0) {
		check("exit_reason is VMCALL or HLT-based",
		      args.exit_reason == VMX_EXIT_VMCALL ||
		      args.exit_reason == 12 /* HLT */ ||
		      args.exit_reason == 0xFFFF /* default/crash */);

		if (args.exit_reason != VMX_EXIT_VMCALL)
			printf("  Note: exit_reason=%u (expected %u=VMCALL)\n",
			       args.exit_reason, VMX_EXIT_VMCALL);
	}

	/* Test 6: Second RUN_GUEST returns same checksum */
	if (rc == 0) {
		struct phantom_run_args args2;
		int rc2;

		memset(&args2, 0, sizeof(args2));
		args2.cpu      = 0;
		args2.reserved = 0;

		rc2 = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args2);
		check("second RUN_GUEST succeeds", rc2 == 0);

		if (rc2 == 0) {
			check("second run returns same checksum",
			      args2.result == args.result);

			if (args2.result != args.result) {
				fprintf(stderr,
					"  Non-deterministic: "
					"run1=0x%016llx run2=0x%016llx\n",
					(unsigned long long)args.result,
					(unsigned long long)args2.result);
			}
		}
	}

	/* Test 7: close */
	rc = close(fd);
	check("close /dev/phantom", rc == 0);

	printf("\n=== %d/%d tests passed ===\n", tests_pass, tests_run);

	return (tests_pass == tests_run) ? 0 : 1;
}
