// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_1_3_ept.c — userspace ioctl test for task 1.3 (Basic R/W EPT)
 *
 * Tests:
 *   1. Open /dev/phantom
 *   2. GET_VERSION returns 0x00010300 (task 1.3)
 *
 *   Test A: R/W test (test_id=0)
 *   3. RUN_GUEST(test_id=0) succeeds
 *   4. Guest checksum matches expected (XOR of all written values)
 *   5. Second RUN_GUEST(test_id=0) returns same checksum (determinism)
 *
 *   Test B: absent-GPA EPT violation test (test_id=1)
 *   6. RUN_GUEST(test_id=1) succeeds (ioctl returns 0)
 *   7. exit_reason == 48 (EPT violation)
 *
 *   Test C: EPT walker ioctl
 *   8. PHANTOM_IOCTL_DEBUG_DUMP_EPT returns 0
 *
 *   9. Close device
 *
 * Build (inside QEMU guest or on server):
 *   gcc -O2 -Wall -o test_1_3_ept test_1_3_ept.c
 *
 * Exit codes:
 *   0 — all tests passed
 *   1 — one or more tests failed
 *
 * Expected checksum for R/W test:
 *   The guest binary writes: page[p].word[w] = p*512 + w
 *   Then XORs all 10 pages × 512 u64 values = 5120 values.
 *   Checksum = XOR of (p*512+w) for p in 0..9, w in 0..511
 *
 * EPT violation test:
 *   Guest accesses GPA 0x1000000 (first GPA outside 16MB EPT RAM map).
 *   This triggers exit_reason = 48 (VMX_EXIT_EPT_VIOLATION).
 *   The ioctl returns 0 (success) because the violation is a legitimate
 *   guest crash/abort — the exit was handled cleanly.
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
#define PHANTOM_VERSION		0x00010300U

#define PHANTOM_IOCTL_GET_VERSION	_IOR(PHANTOM_IOCTL_MAGIC, 0, uint32_t)

struct phantom_run_args {
	uint32_t cpu;		/* IN: CPU index (0 = default)           */
	uint32_t reserved;	/* IN: test_id (0=RW, 1=absent-GPA)      */
	uint64_t result;	/* OUT: checksum from guest              */
	uint32_t exit_reason;	/* OUT: final VM exit reason             */
	uint32_t padding;
};

#define PHANTOM_IOCTL_RUN_GUEST \
	_IOWR(PHANTOM_IOCTL_MAGIC, 1, struct phantom_run_args)

#define PHANTOM_IOCTL_DEBUG_DUMP_EPT \
	_IO(PHANTOM_IOCTL_MAGIC, 6)

#define DEVICE_PATH	"/dev/phantom"

/* VM exit reason: EPT violation (Intel SDM Vol. 3C, Appendix C) */
#define VMX_EXIT_EPT_VIOLATION	48
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
 * Compute expected checksum for the R/W test.
 *
 * The guest writes: ram_page[p].u64[w] = p * 512 + w
 * for p = 0..9 (10 pages), w = 0..511 (512 u64 per page).
 * Then XORs all 5120 values into a checksum.
 *
 * This must match exactly what phantom_rw_guest_bin does.
 */
static uint64_t compute_rw_checksum(void)
{
	uint64_t acc = 0;
	int p, w;

	for (p = 0; p < 10; p++) {
		for (w = 0; w < 512; w++) {
			uint64_t val = (uint64_t)(p * 512 + w);

			acc ^= val;
		}
	}
	return acc;
}

int main(void)
{
	int fd;
	uint32_t ver = 0;
	int rc;
	uint64_t expected_rw;
	struct phantom_run_args args;

	printf("=== phantom task 1.3 Basic R/W EPT test ===\n\n");

	expected_rw = compute_rw_checksum();
	printf("  Expected R/W checksum: 0x%016llx\n\n",
	       (unsigned long long)expected_rw);

	/* Test 1: open device */
	fd = open(DEVICE_PATH, O_RDWR);
	check("open /dev/phantom", fd >= 0);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n",
			DEVICE_PATH, strerror(errno));
		return 1;
	}

	/* Test 2: GET_VERSION returns task-1.3 version */
	ver = 0;
	rc  = ioctl(fd, PHANTOM_IOCTL_GET_VERSION, &ver);
	check("ioctl GET_VERSION succeeds",       rc == 0);
	check("version == 0x00010300 (task 1.3)", ver == PHANTOM_VERSION);

	if (rc == 0)
		printf("  version = 0x%08x\n", ver);

	/* ------- Test A: R/W test ------- */
	printf("\n--- Test A: R/W test (test_id=0) ---\n");

	memset(&args, 0, sizeof(args));
	args.cpu      = 0;
	args.reserved = 0; /* test_id = 0: R/W checksum test */

	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check("RUN_GUEST(test_id=0) succeeds (rc=0)", rc == 0);

	if (rc == 0) {
		printf("  result      = 0x%016llx\n",
		       (unsigned long long)args.result);
		printf("  exit_reason = %u\n", args.exit_reason);

		check("guest R/W checksum matches expected",
		      args.result == expected_rw);

		if (args.result != expected_rw) {
			fprintf(stderr,
				"  MISMATCH: got  0x%016llx\n"
				"            want 0x%016llx\n",
				(unsigned long long)args.result,
				(unsigned long long)expected_rw);
		}

		check("R/W test exit_reason is VMCALL (18)",
		      args.exit_reason == VMX_EXIT_VMCALL);

		/* Determinism: second run must return same checksum */
		{
			struct phantom_run_args args2;
			int rc2;

			memset(&args2, 0, sizeof(args2));
			args2.cpu      = 0;
			args2.reserved = 0;

			rc2 = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args2);
			check("second RUN_GUEST(test_id=0) succeeds", rc2 == 0);

			if (rc2 == 0) {
				check("second run: same checksum (determinism)",
				      args2.result == args.result);

				if (args2.result != args.result) {
					fprintf(stderr,
						"  Non-deterministic: "
						"run1=0x%016llx "
						"run2=0x%016llx\n",
						(unsigned long long)args.result,
						(unsigned long long)
						args2.result);
				}
			}
		}
	}

	/* ------- Test B: absent-GPA EPT violation test ------- */
	printf("\n--- Test B: absent-GPA test (test_id=1) ---\n");

	memset(&args, 0, sizeof(args));
	args.cpu      = 0;
	args.reserved = 1; /* test_id = 1: absent-GPA test */

	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check("RUN_GUEST(test_id=1) ioctl succeeds (rc=0)", rc == 0);

	if (rc == 0) {
		printf("  exit_reason = %u (expected %u = EPT violation)\n",
		       args.exit_reason, VMX_EXIT_EPT_VIOLATION);

		check("absent-GPA exit_reason == 48 (EPT violation)",
		      args.exit_reason == VMX_EXIT_EPT_VIOLATION);
	}

	/* ------- Test C: EPT walker ioctl ------- */
	printf("\n--- Test C: EPT walker ioctl ---\n");

	rc = ioctl(fd, PHANTOM_IOCTL_DEBUG_DUMP_EPT);
	check("PHANTOM_IOCTL_DEBUG_DUMP_EPT returns 0", rc == 0);

	if (rc != 0) {
		fprintf(stderr,
			"  DEBUG_DUMP_EPT failed: %s (errno=%d)\n",
			strerror(errno), errno);
	} else {
		printf("  EPT walker output in "
		       "/sys/kernel/debug/tracing/trace\n");
	}

	/* Test 9: close */
	rc = close(fd);
	check("close /dev/phantom", rc == 0);

	printf("\n=== %d/%d tests passed ===\n", tests_pass, tests_run);

	return (tests_pass == tests_run) ? 0 : 1;
}
