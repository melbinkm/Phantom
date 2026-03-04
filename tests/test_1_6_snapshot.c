// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_1_6_snapshot.c — userspace ioctl test for task 1.6
 *                       (snapshot/restore integration)
 *
 * Tests:
 *   1. Open /dev/phantom
 *   2. GET_VERSION returns 0x00010600 (task 1.6)
 *
 *   Test A: Initial run to snapshot point (test_id=7, phase 1)
 *   3. RUN_GUEST(test_id=7): guest loads XMM0 pattern, writes 5 pages,
 *      issues VMCALL(1, 0xAA) → exit_reason=18, result=0xAA
 *
 *   Test B: SNAPSHOT_CREATE
 *   4. SNAPSHOT_CREATE ioctl returns 0
 *
 *   Test C: Run from snapshot → XMM check (test_id=7, phase 2)
 *   5. RUN_GUEST(test_id=7): guest runs from snapshot RIP, checks XMM0,
 *      issues VMCALL(1, 0xBB) → exit_reason=18, result=0xBB (XMM match)
 *
 *   Test D: SNAPSHOT_RESTORE
 *   6. SNAPSHOT_RESTORE ioctl returns 0
 *
 *   Test E: 100-cycle determinism check
 *   7-107. For each of 100 iterations:
 *      RUN_GUEST(test_id=7 continuation): result must be 0xBB
 *      SNAPSHOT_RESTORE
 *      (no drift — same result every iteration)
 *
 *   Test F: Verify EPT RO after restore (via DEBUG_DUMP_EPT)
 *   108. PHANTOM_IOCTL_DEBUG_DUMP_EPT returns 0 (EPT walker succeeds)
 *
 *   Test G: Task 1.5 regression — all prior test_ids still work
 *   109. RUN_GUEST(test_id=0): R/W checksum — exit_reason=18
 *   110. RUN_GUEST(test_id=1): absent-GPA — exit_reason=48
 *   111. RUN_GUEST(test_id=5): 2MB split — exit_reason=18, result=1
 *   112. RUN_GUEST(test_id=6): mixed 2MB+4KB — exit_reason=18, result=10
 *
 * Build:
 *   gcc -O2 -Wall -o test_1_6_snapshot test_1_6_snapshot.c
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
#define PHANTOM_VERSION			0x00010600U

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

#define PHANTOM_IOCTL_SNAPSHOT_CREATE \
	_IO(PHANTOM_IOCTL_MAGIC, 9)

#define PHANTOM_IOCTL_SNAPSHOT_RESTORE \
	_IO(PHANTOM_IOCTL_MAGIC, 10)

/* VM exit reason codes */
#define VMX_EXIT_VMCALL			18
#define VMX_EXIT_EPT_VIOLATION		48

/* Guest signal codes for test_id=7 */
#define GUEST_SNAP_READY	0xAA  /* phase 1 complete, ready for snapshot */
#define GUEST_XMM_PASS		0xBB  /* XMM0 matched after restore */
#define GUEST_XMM_FAIL		0xCC  /* XMM0 did not match after restore */

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

static void check(int condition, const char *name, const char *reason)
{
	if (condition)
		test_pass(name);
	else
		test_fail(name, reason);
}

/* ------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------ */

int main(void)
{
	int fd;
	int rc;
	uint32_t ver;
	struct phantom_run_args args;
	int i;
	int drift_count = 0;

	printf("=== phantom task 1.6 snapshot/restore test ===\n");

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
	check(rc == 0, "GET_VERSION ioctl returns 0", "ioctl failed");
	check(ver == PHANTOM_VERSION,
	      "GET_VERSION returns 0x00010600",
	      "wrong version");
	if (ver != PHANTOM_VERSION)
		printf("    got 0x%08x, expected 0x%08x\n", ver,
		       PHANTOM_VERSION);

	/* --- Test A: Phase 1 — guest runs to snapshot point --- */
	printf("\n--- Test A: RUN_GUEST(test_id=7) phase 1 ---\n");
	memset(&args, 0, sizeof(args));
	args.reserved = 7;
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check(rc == 0, "RUN_GUEST(7) phase 1 returns 0", "ioctl failed");
	check(args.exit_reason == VMX_EXIT_VMCALL,
	      "phase 1 exit_reason == 18 (VMCALL)",
	      "expected VMCALL exit");
	check(args.result == GUEST_SNAP_READY,
	      "phase 1 result == 0xAA (snapshot ready)",
	      "expected 0xAA signal from guest");
	printf("    exit_reason=%u result=0x%llx\n",
	       args.exit_reason, (unsigned long long)args.result);

	if (rc != 0 || args.exit_reason != VMX_EXIT_VMCALL) {
		printf("  ABORT: phase 1 failed — cannot continue snapshot tests\n");
		goto regression;
	}

	/* --- Test B: SNAPSHOT_CREATE --- */
	printf("\n--- Test B: SNAPSHOT_CREATE ---\n");
	rc = ioctl(fd, PHANTOM_IOCTL_SNAPSHOT_CREATE);
	check(rc == 0, "SNAPSHOT_CREATE returns 0", "ioctl failed");
	if (rc != 0) {
		printf("  ABORT: SNAPSHOT_CREATE failed — "
		       "cannot continue\n");
		goto regression;
	}

	/* --- Test C: Run from snapshot → XMM check --- */
	printf("\n--- Test C: RUN_GUEST(test_id=7) phase 2 (XMM check) ---\n");
	memset(&args, 0, sizeof(args));
	args.reserved = 7;
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check(rc == 0, "RUN_GUEST(7) phase 2 returns 0", "ioctl failed");
	check(args.exit_reason == VMX_EXIT_VMCALL,
	      "phase 2 exit_reason == 18 (VMCALL)",
	      "expected VMCALL exit");
	check(args.result == GUEST_XMM_PASS,
	      "phase 2 result == 0xBB (XMM0 pattern matches — XSAVE/XRSTOR OK)",
	      "XMM0 pattern mismatch or FAIL signal (0xCC) from guest");
	printf("    exit_reason=%u result=0x%llx\n",
	       args.exit_reason, (unsigned long long)args.result);

	if (args.result == GUEST_XMM_FAIL)
		printf("    (guest reported XMM0 mismatch — XSAVE/XRSTOR bug)\n");

	/* --- Test D: SNAPSHOT_RESTORE --- */
	printf("\n--- Test D: SNAPSHOT_RESTORE ---\n");
	rc = ioctl(fd, PHANTOM_IOCTL_SNAPSHOT_RESTORE);
	check(rc == 0, "SNAPSHOT_RESTORE returns 0", "ioctl failed");
	if (rc != 0) {
		printf("  ABORT: SNAPSHOT_RESTORE failed\n");
		goto regression;
	}

	/* --- Test E: 100-cycle determinism check --- */
	printf("\n--- Test E: 100-cycle snapshot/restore determinism ---\n");
	drift_count = 0;
	for (i = 0; i < 100; i++) {
		uint64_t expected = GUEST_XMM_PASS;

		memset(&args, 0, sizeof(args));
		args.reserved = 7;

		rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
		if (rc != 0) {
			printf("    iter %d: RUN_GUEST failed (rc=%d)\n",
			       i, rc);
			drift_count++;
			break;
		}

		if (args.result != expected || args.exit_reason != VMX_EXIT_VMCALL) {
			printf("    iter %d: unexpected result=0x%llx "
			       "exit_reason=%u\n",
			       i,
			       (unsigned long long)args.result,
			       args.exit_reason);
			drift_count++;
		}

		rc = ioctl(fd, PHANTOM_IOCTL_SNAPSHOT_RESTORE);
		if (rc != 0) {
			printf("    iter %d: SNAPSHOT_RESTORE failed (rc=%d)\n",
			       i, rc);
			drift_count++;
			break;
		}
	}
	check(drift_count == 0,
	      "100 snapshot/restore cycles: no state drift",
	      "one or more iterations produced unexpected results");
	if (drift_count > 0)
		printf("    drift events: %d / 100\n", drift_count);

	/* --- Test F: EPT walker still works --- */
	printf("\n--- Test F: DEBUG_DUMP_EPT after restore ---\n");
	rc = ioctl(fd, PHANTOM_IOCTL_DEBUG_DUMP_EPT);
	check(rc == 0, "DEBUG_DUMP_EPT returns 0 after restore", "ioctl failed");

regression:
	/* --- Test G: Task 1.5 regression --- */
	printf("\n--- Test G: Task 1.5 regression tests ---\n");

	/* G.1: R/W checksum test (test_id=0) */
	memset(&args, 0, sizeof(args));
	args.reserved = 0;
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check(rc == 0 && args.exit_reason == VMX_EXIT_VMCALL,
	      "regression: RUN_GUEST(0) R/W checksum — exit_reason=18",
	      "test_id=0 failed");
	printf("    exit_reason=%u result=0x%llx\n",
	       args.exit_reason, (unsigned long long)args.result);

	/* G.2: absent-GPA test (test_id=1) */
	memset(&args, 0, sizeof(args));
	args.reserved = 1;
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check(rc == 0 && args.exit_reason == VMX_EXIT_EPT_VIOLATION,
	      "regression: RUN_GUEST(1) absent-GPA — exit_reason=48",
	      "test_id=1 failed");
	printf("    exit_reason=%u\n", args.exit_reason);

	/* G.3: 2MB split + CoW (test_id=5) */
	memset(&args, 0, sizeof(args));
	args.reserved = 5;
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check(rc == 0 && args.exit_reason == VMX_EXIT_VMCALL
	      && args.result == 1,
	      "regression: RUN_GUEST(5) 2MB split — exit_reason=18, result=1",
	      "test_id=5 failed");
	printf("    exit_reason=%u result=%llu\n",
	       args.exit_reason, (unsigned long long)args.result);

	/* G.4: mixed 2MB + 4KB workload (test_id=6) */
	memset(&args, 0, sizeof(args));
	args.reserved = 6;
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	check(rc == 0 && args.exit_reason == VMX_EXIT_VMCALL
	      && args.result == 10,
	      "regression: RUN_GUEST(6) mixed 2MB+4KB — exit_reason=18, result=10",
	      "test_id=6 failed");
	printf("    exit_reason=%u result=%llu\n",
	       args.exit_reason, (unsigned long long)args.result);

	/* --- Summary --- */
	printf("\n=== RESULTS: %d passed, %d failed ===\n",
	       tests_passed, tests_failed);

	close(fd);
	return tests_failed > 0 ? 1 : 0;
}
