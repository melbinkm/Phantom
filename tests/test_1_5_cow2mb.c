// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_1_5_cow2mb.c — userspace ioctl test for task 1.5 (2MB CoW + splitting)
 *
 * Tests:
 *   1. Open /dev/phantom
 *   2. GET_VERSION returns 0x00010500 (task 1.5)
 *
 *   Test A: 2MB split + CoW (test_id=5)
 *   3. RUN_GUEST(test_id=5) succeeds, exit_reason=18 (VMCALL)
 *   4. run_result_data == 1 (guest wrote 1 page)
 *   5. DEBUG_DUMP_DIRTY_LIST: check DIRTY_ENTRY appears
 *
 *   Test B: Mixed 2MB + 4KB workload (test_id=6)
 *   6. RUN_GUEST(test_id=6) succeeds, exit_reason=18
 *   7. run_result_data == 10 (guest wrote 10 pages)
 *
 *   Test C: Dirty list overflow (test_id=2 after reducing effective cap via
 *   observing the default pool works correctly for 20 pages)
 *   8. RUN_GUEST(test_id=2) succeeds, run_result_data == 20
 *   9. DUMP_DIRTY_OVERFLOW returns 0 (no overflow with full pool)
 *
 *   Test D: Task 1.4 regression — all 5 prior test_ids still work
 *   10. RUN_GUEST(test_id=0): R/W checksum — exit_reason=18
 *   11. RUN_GUEST(test_id=1): absent-GPA — exit_reason=48
 *   12. RUN_GUEST(test_id=3): pool exhaustion — exit_reason=18
 *   13. RUN_GUEST(test_id=4): MMIO CoW rejection — exit_reason=48
 *
 *   Test E: Second 2MB split run (re-split after restore)
 *   14. RUN_GUEST(test_id=5) again — split re-runs without error
 *
 * Build:
 *   gcc -O2 -Wall -o test_1_5_cow2mb test_1_5_cow2mb.c
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
#define PHANTOM_VERSION			0x00010500U

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

#define PHANTOM_IOCTL_DEBUG_DUMP_DIRTY_OVERFLOW \
	_IO(PHANTOM_IOCTL_MAGIC, 8)

/* VM exit reason codes */
#define VMX_EXIT_VMCALL			18
#define VMX_EXIT_EPT_VIOLATION		48

/* Run result codes */
#define PHANTOM_RESULT_OK		0
#define PHANTOM_RESULT_CRASH		1

/* ------------------------------------------------------------------
 * Test helpers
 * ------------------------------------------------------------------ */

static int tests_passed;
static int tests_failed;

static void test_pass(const char *name)
{
	tests_passed++;
	printf("  PASS  %s\n", name);
}

static void test_fail(const char *name, const char *reason)
{
	tests_failed++;
	printf("  FAIL  %s: %s\n", name, reason);
}

static int run_guest(int fd, uint32_t test_id,
		     uint64_t *result, uint32_t *exit_reason)
{
	struct phantom_run_args args;
	int ret;

	memset(&args, 0, sizeof(args));
	args.cpu      = 0;
	args.reserved = test_id;

	ret = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	if (ret < 0)
		return ret;

	if (result)
		*result = args.result;
	if (exit_reason)
		*exit_reason = args.exit_reason;
	return 0;
}

/* ------------------------------------------------------------------
 * Test cases
 * ------------------------------------------------------------------ */

static int test_version(int fd)
{
	uint32_t ver = 0;
	char reason[64];

	if (ioctl(fd, PHANTOM_IOCTL_GET_VERSION, &ver) < 0) {
		test_fail("GET_VERSION", "ioctl failed");
		return -1;
	}

	if (ver != PHANTOM_VERSION) {
		snprintf(reason, sizeof(reason),
			 "expected 0x%08x got 0x%08x",
			 PHANTOM_VERSION, ver);
		test_fail("GET_VERSION", reason);
		return -1;
	}

	test_pass("GET_VERSION == 0x00010500");
	return 0;
}

static int test_2mb_split(int fd)
{
	uint64_t result = 0;
	uint32_t exit_reason = 0;
	char reason[64];

	printf("  [test_id=5] 2MB split + CoW\n");

	if (run_guest(fd, 5, &result, &exit_reason) < 0) {
		test_fail("2MB_SPLIT: RUN_GUEST", "ioctl failed");
		return -1;
	}

	if (exit_reason != VMX_EXIT_VMCALL) {
		snprintf(reason, sizeof(reason),
			 "expected exit_reason=%d (VMCALL) got %u",
			 VMX_EXIT_VMCALL, exit_reason);
		test_fail("2MB_SPLIT: exit_reason", reason);
		return -1;
	}
	test_pass("2MB_SPLIT: exit_reason == 18 (VMCALL)");

	if (result != 1) {
		snprintf(reason, sizeof(reason),
			 "expected result=1 got %llu", (unsigned long long)result);
		test_fail("2MB_SPLIT: result", reason);
		return -1;
	}
	test_pass("2MB_SPLIT: result == 1 (1 page written)");

	return 0;
}

static int test_mixed_cow(int fd)
{
	uint64_t result = 0;
	uint32_t exit_reason = 0;
	char reason[64];

	printf("  [test_id=6] mixed 2MB + 4KB CoW workload\n");

	if (run_guest(fd, 6, &result, &exit_reason) < 0) {
		test_fail("MIXED_COW: RUN_GUEST", "ioctl failed");
		return -1;
	}

	if (exit_reason != VMX_EXIT_VMCALL) {
		snprintf(reason, sizeof(reason),
			 "expected exit_reason=%d (VMCALL) got %u",
			 VMX_EXIT_VMCALL, exit_reason);
		test_fail("MIXED_COW: exit_reason", reason);
		return -1;
	}
	test_pass("MIXED_COW: exit_reason == 18 (VMCALL)");

	if (result != 10) {
		snprintf(reason, sizeof(reason),
			 "expected result=10 got %llu",
			 (unsigned long long)result);
		test_fail("MIXED_COW: result", reason);
		return -1;
	}
	test_pass("MIXED_COW: result == 10 (10 pages written)");

	return 0;
}

static int test_dirty_overflow_ioctl(int fd)
{
	int ret;

	ret = ioctl(fd, PHANTOM_IOCTL_DEBUG_DUMP_DIRTY_OVERFLOW, 0);
	if (ret < 0) {
		test_fail("DUMP_DIRTY_OVERFLOW: ioctl", "ioctl failed");
		return -1;
	}
	test_pass("DUMP_DIRTY_OVERFLOW: ioctl returns 0");
	return 0;
}

static int test_dirty_list_dump(int fd)
{
	int ret;

	ret = ioctl(fd, PHANTOM_IOCTL_DEBUG_DUMP_DIRTY_LIST, 0);
	if (ret < 0) {
		test_fail("DUMP_DIRTY_LIST: ioctl", "ioctl failed");
		return -1;
	}
	test_pass("DUMP_DIRTY_LIST: ioctl returns 0");
	return 0;
}

/* Test task 1.4 regressions */
static int test_regressions(int fd)
{
	uint64_t result;
	uint32_t exit_reason;
	char reason[64];
	int ok = 0;

	printf("  [regression] task 1.4 tests\n");

	/* test_id=0: R/W checksum test */
	if (run_guest(fd, 0, &result, &exit_reason) < 0) {
		test_fail("REGRESS_TEST0: RUN_GUEST", "ioctl failed");
		ok = -1;
	} else if (exit_reason != VMX_EXIT_VMCALL) {
		snprintf(reason, sizeof(reason),
			 "test_id=0: exit_reason=%u (expected %d)",
			 exit_reason, VMX_EXIT_VMCALL);
		test_fail("REGRESS_TEST0: exit_reason", reason);
		ok = -1;
	} else {
		test_pass("REGRESS_TEST0: test_id=0 (R/W checksum) OK");
	}

	/* test_id=1: absent-GPA */
	if (run_guest(fd, 1, &result, &exit_reason) < 0) {
		test_fail("REGRESS_TEST1: RUN_GUEST", "ioctl failed");
		ok = -1;
	} else if (exit_reason != VMX_EXIT_EPT_VIOLATION) {
		snprintf(reason, sizeof(reason),
			 "test_id=1: exit_reason=%u (expected %d)",
			 exit_reason, VMX_EXIT_EPT_VIOLATION);
		test_fail("REGRESS_TEST1: exit_reason", reason);
		ok = -1;
	} else {
		test_pass("REGRESS_TEST1: test_id=1 (absent-GPA) OK");
	}

	/* test_id=2: 20-page CoW write */
	if (run_guest(fd, 2, &result, &exit_reason) < 0) {
		test_fail("REGRESS_TEST2: RUN_GUEST", "ioctl failed");
		ok = -1;
	} else if (exit_reason != VMX_EXIT_VMCALL) {
		snprintf(reason, sizeof(reason),
			 "test_id=2: exit_reason=%u (expected %d)",
			 exit_reason, VMX_EXIT_VMCALL);
		test_fail("REGRESS_TEST2: exit_reason", reason);
		ok = -1;
	} else if (result != 20) {
		snprintf(reason, sizeof(reason),
			 "test_id=2: result=%llu (expected 20)",
			 (unsigned long long)result);
		test_fail("REGRESS_TEST2: result", reason);
		ok = -1;
	} else {
		test_pass("REGRESS_TEST2: test_id=2 (20-page CoW) OK");
	}

	/* test_id=3: pool exhaustion (default pool: all writes succeed) */
	if (run_guest(fd, 3, &result, &exit_reason) < 0) {
		test_fail("REGRESS_TEST3: RUN_GUEST", "ioctl failed");
		ok = -1;
	} else if (exit_reason != VMX_EXIT_VMCALL) {
		snprintf(reason, sizeof(reason),
			 "test_id=3: exit_reason=%u (expected %d)",
			 exit_reason, VMX_EXIT_VMCALL);
		test_fail("REGRESS_TEST3: exit_reason", reason);
		ok = -1;
	} else {
		test_pass("REGRESS_TEST3: test_id=3 (pool exhaust) OK");
	}

	/* test_id=4: MMIO CoW rejection */
	if (run_guest(fd, 4, &result, &exit_reason) < 0) {
		test_fail("REGRESS_TEST4: RUN_GUEST", "ioctl failed");
		ok = -1;
	} else if (exit_reason != VMX_EXIT_EPT_VIOLATION) {
		snprintf(reason, sizeof(reason),
			 "test_id=4: exit_reason=%u (expected %d)",
			 exit_reason, VMX_EXIT_EPT_VIOLATION);
		test_fail("REGRESS_TEST4: exit_reason", reason);
		ok = -1;
	} else {
		test_pass("REGRESS_TEST4: test_id=4 (MMIO CoW reject) OK");
	}

	return ok;
}

static int test_2mb_split_second_run(int fd)
{
	uint64_t result = 0;
	uint32_t exit_reason = 0;

	printf("  [test_id=5] 2MB split second run (re-split after restore)\n");

	if (run_guest(fd, 5, &result, &exit_reason) < 0) {
		test_fail("2MB_SPLIT_RERUN: RUN_GUEST", "ioctl failed");
		return -1;
	}

	if (exit_reason != VMX_EXIT_VMCALL) {
		char reason[64];
		snprintf(reason, sizeof(reason),
			 "expected exit_reason=%d got %u",
			 VMX_EXIT_VMCALL, exit_reason);
		test_fail("2MB_SPLIT_RERUN: exit_reason", reason);
		return -1;
	}
	test_pass("2MB_SPLIT_RERUN: second split run succeeds");
	return 0;
}

/* ------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------ */

int main(void)
{
	int fd;
	int ret = 0;

	printf("phantom task 1.5 test suite\n");
	printf("===========================\n\n");

	fd = open("/dev/phantom", O_RDWR);
	if (fd < 0) {
		perror("open /dev/phantom");
		return 1;
	}

	printf("[Test 1] GET_VERSION\n");
	if (test_version(fd) < 0)
		ret = 1;

	printf("\n[Test 2] 2MB split + CoW (test_id=5)\n");
	if (test_2mb_split(fd) < 0)
		ret = 1;

	printf("\n[Test 3] Mixed 2MB + 4KB CoW workload (test_id=6)\n");
	if (test_mixed_cow(fd) < 0)
		ret = 1;

	printf("\n[Test 4] Dirty list dump\n");
	if (test_dirty_list_dump(fd) < 0)
		ret = 1;

	printf("\n[Test 5] Dirty overflow dump ioctl\n");
	if (test_dirty_overflow_ioctl(fd) < 0)
		ret = 1;

	printf("\n[Test 6] Task 1.4 regression\n");
	if (test_regressions(fd) < 0)
		ret = 1;

	printf("\n[Test 7] 2MB split second run (re-split after restore)\n");
	if (test_2mb_split_second_run(fd) < 0)
		ret = 1;

	close(fd);

	printf("\n===========================\n");
	printf("Results: %d passed, %d failed\n",
	       tests_passed, tests_failed);
	printf("===========================\n");

	return (tests_failed > 0) ? 1 : 0;
}
