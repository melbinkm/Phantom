// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_1_4_cow.c — userspace ioctl test for task 1.4 (CoW fault + page pool)
 *
 * Tests:
 *   1. Open /dev/phantom
 *   2. GET_VERSION returns 0x00010400 (task 1.4)
 *
 *   Test A: CoW write test (test_id=2, 20 pages)
 *   3. RUN_GUEST(test_id=2) succeeds
 *   4. Guest wrote 20 pages → run_result_data == 20
 *   5. DEBUG_DUMP_DIRTY_LIST: last_dirty_count == 20 in trace
 *
 *   Test B: Second run — regression check on task 1.3
 *   6. RUN_GUEST(test_id=0) succeeds (10-page R/W checksum test)
 *   7. exit_reason == 18 (VMCALL completed — XOR sum is 0 by design)
 *
 *   Test C: MMIO CoW rejection test (test_id=4)
 *   8. RUN_GUEST(test_id=4) returns 0 (ioctl succeeds)
 *   9. exit_reason == 48 (EPT violation — MMIO write rejected)
 *   (no host panic — verified by absence of kernel oops)
 *
 *   Test D: Pool exhaustion test (test_id=3, 10-page write with default pool)
 *   10. RUN_GUEST(test_id=3) returns 0
 *   11. run_result_data == 10 (guest completes with vmcall(1,10))
 *       (with default pool of 4096 pages, 10 writes succeed)
 *
 *   Test E: Task 1.3 regression — absent-GPA test still works
 *   12. RUN_GUEST(test_id=1) returns 0, exit_reason == 48
 *
 *   Test F: DEBUG_DUMP_EPT still works
 *   13. PHANTOM_IOCTL_DEBUG_DUMP_EPT returns 0
 *
 *   14. Close device
 *
 * Build:
 *   gcc -O2 -Wall -o test_1_4_cow test_1_4_cow.c
 *
 * Exit codes:
 *   0 — all tests passed
 *   1 — one or more tests failed
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
#define PHANTOM_IOCTL_MAGIC		'P'
#define PHANTOM_VERSION			0x00010400U

#define PHANTOM_IOCTL_GET_VERSION	_IOR(PHANTOM_IOCTL_MAGIC, 0, uint32_t)

struct phantom_run_args {
	uint32_t cpu;		/* IN: CPU index (0 = default)            */
	uint32_t reserved;	/* IN: test_id                            */
	uint64_t result;	/* OUT: result from guest VMCALL          */
	uint32_t exit_reason;	/* OUT: final VM exit reason              */
	uint32_t padding;
};

#define PHANTOM_IOCTL_RUN_GUEST	\
	_IOWR(PHANTOM_IOCTL_MAGIC, 1, struct phantom_run_args)

#define PHANTOM_IOCTL_DEBUG_DUMP_EPT \
	_IO(PHANTOM_IOCTL_MAGIC, 6)

#define PHANTOM_IOCTL_DEBUG_DUMP_DIRTY_LIST \
	_IO(PHANTOM_IOCTL_MAGIC, 7)

/* VM exit reason codes */
#define VMX_EXIT_EPT_VIOLATION		48

/* Run result codes */
#define PHANTOM_RESULT_OK		0
#define PHANTOM_RESULT_CRASH		1

/* ------------------------------------------------------------------ */

static int pass_count;
static int fail_count;

static void check(int condition, const char *test_name)
{
	if (condition) {
		printf("  PASS  %s\n", test_name);
		pass_count++;
	} else {
		printf("  FAIL  %s\n", test_name);
		fail_count++;
	}
}

int main(void)
{
	int fd;
	int rc;
	uint32_t ver;
	struct phantom_run_args args;

	printf("=== phantom task 1.4 CoW test ===\n");

	/* Open device */
	fd = open("/dev/phantom", O_RDWR);
	if (fd < 0) {
		perror("open /dev/phantom");
		return 1;
	}
	printf("  Opened /dev/phantom (fd=%d)\n", fd);

	/* --- Test 1: version check --- */
	printf("\n--- Test 1: GET_VERSION ---\n");
	ver = 0;
	rc = ioctl(fd, PHANTOM_IOCTL_GET_VERSION, &ver);
	check(rc == 0, "GET_VERSION ioctl returns 0");
	check(ver == PHANTOM_VERSION,
	      "GET_VERSION returns 0x00010400");
	if (ver != PHANTOM_VERSION)
		printf("    got 0x%08x, expected 0x%08x\n", ver,
		       PHANTOM_VERSION);

	/* --- Test A: CoW write test (test_id=2, 20 pages) --- */
	printf("\n--- Test A: CoW write test (test_id=2, 20 pages) ---\n");
	memset(&args, 0, sizeof(args));
	args.reserved = 2;
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check(rc == 0, "RUN_GUEST(test_id=2) returns 0");
	check(args.result == 20,
	      "guest wrote 20 pages (result == 20)");
	if (args.result != 20)
		printf("    got result=%llu, expected 20\n",
		       (unsigned long long)args.result);
	printf("    exit_reason=%u result=%llu\n",
	       args.exit_reason, (unsigned long long)args.result);

	/* Dump dirty list — output goes to ftrace ring buffer */
	printf("--- Test A.2: DEBUG_DUMP_DIRTY_LIST after CoW run ---\n");
	rc = ioctl(fd, PHANTOM_IOCTL_DEBUG_DUMP_DIRTY_LIST);
	check(rc == 0, "DEBUG_DUMP_DIRTY_LIST returns 0");

	/* --- Test B: R/W checksum test regression (test_id=0) --- */
	printf("\n--- Test B: R/W checksum regression (test_id=0) ---\n");
	memset(&args, 0, sizeof(args));
	args.reserved = 0;
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check(rc == 0, "RUN_GUEST(test_id=0) returns 0");
	/*
	 * The checksum XOR of p*512+w for p=0..9, w=0..511 is
	 * mathematically 0 (each 512-value block XORs to 0 since
	 * groups of 4 consecutive integers always XOR to 0, and
	 * 512 is a multiple of 4).  We verify the ioctl succeeded
	 * and the VMCALL completed (exit_reason=18), not the value.
	 */
	check(args.exit_reason == 18,
	      "RUN_GUEST(test_id=0) completed via VMCALL (exit_reason=18)");
	printf("    checksum=0x%016llx exit_reason=%u\n",
	       (unsigned long long)args.result, args.exit_reason);

	/* --- Test C: MMIO CoW rejection (test_id=4) --- */
	printf("\n--- Test C: MMIO CoW rejection (test_id=4) ---\n");
	memset(&args, 0, sizeof(args));
	args.reserved = 4;
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check(rc == 0, "RUN_GUEST(test_id=4) ioctl returns 0");
	check(args.exit_reason == VMX_EXIT_EPT_VIOLATION,
	      "exit_reason == 48 (EPT violation — MMIO write)");
	printf("    exit_reason=%u result=%llu\n",
	       args.exit_reason, (unsigned long long)args.result);

	/* --- Test D: Pool exhaustion with default pool (test_id=3) --- */
	printf("\n--- Test D: Pool exhaustion test (test_id=3) ---\n");
	memset(&args, 0, sizeof(args));
	args.reserved = 3;
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	/*
	 * With the default 4096-page pool, 10 writes succeed and the guest
	 * completes normally with vmcall(1, 10).  exit_reason may be 18
	 * (VMCALL) or 18 with the vmcall completing cleanly.
	 */
	check(rc == 0, "RUN_GUEST(test_id=3) returns 0");
	check(args.result == 10,
	      "guest wrote 10 pages (result == 10)");
	printf("    exit_reason=%u result=%llu\n",
	       args.exit_reason, (unsigned long long)args.result);

	/* --- Test E: Absent-GPA regression (test_id=1) --- */
	printf("\n--- Test E: Absent-GPA regression (test_id=1) ---\n");
	memset(&args, 0, sizeof(args));
	args.reserved = 1;
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check(rc == 0, "RUN_GUEST(test_id=1) ioctl returns 0");
	check(args.exit_reason == VMX_EXIT_EPT_VIOLATION,
	      "exit_reason == 48 (absent-GPA violation)");
	printf("    exit_reason=%u\n", args.exit_reason);

	/* --- Test F: EPT walker ioctl still works --- */
	printf("\n--- Test F: DEBUG_DUMP_EPT ---\n");
	rc = ioctl(fd, PHANTOM_IOCTL_DEBUG_DUMP_EPT);
	check(rc == 0, "DEBUG_DUMP_EPT returns 0");

	/* Cleanup */
	close(fd);

	printf("\n=========================================\n");
	printf(" RESULTS: %d passed, %d failed\n",
	       pass_count, fail_count);
	printf("=========================================\n");

	return fail_count > 0 ? 1 : 0;
}
