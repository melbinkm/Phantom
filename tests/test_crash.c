// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_crash.c — crash detection test suite for phantom.ko
 *
 * Tests:
 *   Test A: PANIC → PHANTOM_RESULT_CRASH with crash_addr == 0xDEADBEEF
 *   Test B: 100× crash + restore — each iteration crashes deterministically
 *   Test C: normal iterations work after crashes (module is healthy)
 *
 * Workflow:
 *   - Use legacy RUN_GUEST(test_id=9) to prime ACQUIRE and take snapshot.
 *     test_id=9 does: ACQUIRE (snapshot) → PANIC(0xDEADBEEF).
 *   - After the first crash, PHANTOM_GET_STATUS gives crash_addr.
 *   - Tests B and C use PHANTOM_IOCTL_RUN_ITERATION (legacy cmd 20) to
 *     re-run from the snapshot point with iterative restore semantics.
 *     For test_id=9 the guest always PANICs immediately after ACQUIRE.
 *   - Test C switches to test_id=8 (normal harness) which does
 *     GET_PAYLOAD → ACQUIRE → read payload → RELEASE.
 *
 * Build:
 *   gcc -O2 -Wall -o test_crash test_crash.c
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
#include <sys/mman.h>

/* ------------------------------------------------------------------
 * Interface definitions (kept in sync with kernel/interface.h)
 * ------------------------------------------------------------------ */

#define PHANTOM_IOC_MAGIC		'P'
#define PHANTOM_PAYLOAD_MAX		(1 << 16)	/* 64KB */

/* Result codes */
#define PHANTOM_RESULT_OK		0
#define PHANTOM_RESULT_CRASH		1
#define PHANTOM_RESULT_TIMEOUT		2
#define PHANTOM_RESULT_KASAN		3

/* Legacy RUN_GUEST: args.reserved = test_id */
struct phantom_run_args {
	uint32_t cpu;
	uint32_t reserved;	/* IN: test_id */
	uint64_t result;	/* OUT: checksum / result data */
	uint32_t exit_reason;	/* OUT: VM exit reason */
	uint32_t padding;
};
#define PHANTOM_IOCTL_RUN_GUEST \
	_IOWR(PHANTOM_IOC_MAGIC, 1, struct phantom_run_args)

/* Legacy RUN_ITERATION (cmd 20) — runs one iteration from snapshot */
struct phantom_iter_params {
	uint32_t payload_len;
	uint32_t timeout_ms;
};
#define PHANTOM_IOCTL_RUN_ITERATION \
	_IOWR(PHANTOM_IOC_MAGIC, 20, struct phantom_iter_params)

/* Legacy GET_RESULT (cmd 21) */
struct phantom_iter_result {
	uint32_t status;
	uint32_t _pad;
	uint64_t crash_addr;
};
#define PHANTOM_IOCTL_GET_RESULT \
	_IOR(PHANTOM_IOC_MAGIC, 21, struct phantom_iter_result)

/* New API: GET_STATUS (cmd 0x34) */
struct phantom_status {
	uint32_t result;
	uint32_t exit_reason;
	uint64_t crash_addr;
	uint64_t checksum;
	uint64_t iterations;
};
#define PHANTOM_GET_STATUS \
	_IOR(PHANTOM_IOC_MAGIC, 0x34, struct phantom_status)

/* Shared memory layout (at mmap offset 0) */
struct phantom_shared_mem {
	uint8_t  payload[PHANTOM_PAYLOAD_MAX];
	uint32_t payload_len;
	uint32_t status;
	uint64_t crash_addr;
};

/* ------------------------------------------------------------------
 * Test harness helpers
 * ------------------------------------------------------------------ */

static int pass_count;
static int fail_count;

static void t_pass(const char *name)
{
	pass_count++;
	printf("  PASS  %s\n", name);
}

static void t_fail(const char *name, const char *reason)
{
	fail_count++;
	printf("  FAIL  %s: %s\n", name, reason);
}

static void t_assert(int cond, const char *name, const char *reason)
{
	if (cond)
		t_pass(name);
	else
		t_fail(name, reason);
}

/* ------------------------------------------------------------------
 * Test A: PANIC → PHANTOM_RESULT_CRASH with crash_addr == 0xDEADBEEF
 *
 * Runs test_id=9 via RUN_GUEST.  The guest binary does:
 *   ACQUIRE (takes snapshot) → PANIC(RCX=0xDEADBEEF)
 * Then reads status via PHANTOM_GET_STATUS.
 * ------------------------------------------------------------------ */
static int test_a_panic_crash(int fd)
{
	struct phantom_run_args rargs;
	struct phantom_status st;
	char buf[128];
	int ret;

	printf("\n--- Test A: PANIC → PHANTOM_RESULT_CRASH ---\n");

	memset(&rargs, 0, sizeof(rargs));
	rargs.cpu      = 0;
	rargs.reserved = 9;	/* test_id=9: deliberate panic */

	ret = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &rargs);
	if (ret != 0) {
		snprintf(buf, sizeof(buf), "RUN_GUEST errno=%d (%s)",
			 errno, strerror(errno));
		t_fail("A: RUN_GUEST(test_id=9) returned 0", buf);
		return -1;
	}
	t_pass("A: RUN_GUEST(test_id=9) returned 0");

	printf("    exit_reason=%u result=0x%llx\n",
	       rargs.exit_reason, (unsigned long long)rargs.result);

	/* Read status via PHANTOM_GET_STATUS */
	memset(&st, 0, sizeof(st));
	ret = ioctl(fd, PHANTOM_GET_STATUS, &st);
	if (ret != 0) {
		snprintf(buf, sizeof(buf), "GET_STATUS errno=%d (%s)",
			 errno, strerror(errno));
		t_fail("A: PHANTOM_GET_STATUS returned 0", buf);
		return -1;
	}
	t_pass("A: PHANTOM_GET_STATUS returned 0");

	printf("    status.result=%u status.crash_addr=0x%llx\n",
	       st.result, (unsigned long long)st.crash_addr);

	t_assert(st.result == PHANTOM_RESULT_CRASH,
		 "A: result == PHANTOM_RESULT_CRASH",
		 "result was not PHANTOM_RESULT_CRASH");

	if (st.crash_addr == 0xDEADBEEF) {
		t_pass("A: crash_addr == 0xDEADBEEF");
	} else {
		snprintf(buf, sizeof(buf),
			 "crash_addr=0x%llx (expected 0xDEADBEEF)",
			 (unsigned long long)st.crash_addr);
		t_fail("A: crash_addr == 0xDEADBEEF", buf);
	}

	return 0;
}

/* ------------------------------------------------------------------
 * Test B: 100× crash + restore
 *
 * After Test A, snap_acquired is set and the snapshot is at the point
 * just before PANIC fires.  Each RUN_ITERATION re-runs from that
 * snapshot: the guest immediately PANICs again.
 *
 * Each iteration must produce:
 *   status == PHANTOM_RESULT_CRASH
 *   crash_addr == 0xDEADBEEF
 * ------------------------------------------------------------------ */
static int test_b_repeated_crash(int fd)
{
	struct phantom_iter_params params;
	struct phantom_iter_result res;
	int failures = 0;
	int i, ret;
	char buf[128];

	printf("\n--- Test B: 100x crash + restore ---\n");

	memset(&params, 0, sizeof(params));
	params.payload_len = 0;
	params.timeout_ms  = 0;

	for (i = 0; i < 100; i++) {
		ret = ioctl(fd, PHANTOM_IOCTL_RUN_ITERATION, &params);
		if (ret != 0) {
			if (failures == 0) {
				snprintf(buf, sizeof(buf),
					 "iter %d: RUN_ITERATION errno=%d (%s)",
					 i, errno, strerror(errno));
				t_fail("B: RUN_ITERATION returned 0", buf);
			}
			failures++;
			if (failures > 5) {
				printf("    ... stopping after 5 consecutive "
				       "RUN_ITERATION failures\n");
				break;
			}
			continue;
		}

		/* Read crash details */
		memset(&res, 0, sizeof(res));
		ret = ioctl(fd, PHANTOM_IOCTL_GET_RESULT, &res);
		if (ret != 0) {
			failures++;
			printf("    iter %d: GET_RESULT errno=%d (%s)\n",
			       i, errno, strerror(errno));
			continue;
		}

		if (res.status != PHANTOM_RESULT_CRASH) {
			failures++;
			printf("    iter %d: status=%u (expected %u CRASH)\n",
			       i, res.status, PHANTOM_RESULT_CRASH);
		} else if (res.crash_addr != 0xDEADBEEF) {
			failures++;
			printf("    iter %d: crash_addr=0x%llx "
			       "(expected 0xDEADBEEF)\n",
			       i, (unsigned long long)res.crash_addr);
		}
	}

	if (failures == 0) {
		t_pass("B: 100 crash iterations: all status == CRASH");
		t_pass("B: 100 crash iterations: all crash_addr == 0xDEADBEEF");
	} else {
		snprintf(buf, sizeof(buf), "%d failures out of 100", failures);
		t_fail("B: 100 crash iterations", buf);
	}

	printf("    completed %d iterations, %d failures\n",
	       (failures > 5 ? failures : 100), failures);

	return failures == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Test C: normal iterations work after crashes
 *
 * After 100 crash iterations the module must still be healthy.
 * Re-prime with RUN_GUEST(test_id=8) so the kAFL harness loads its
 * binary (GET_PAYLOAD → ACQUIRE → read payload → RELEASE) and the
 * snapshot is reset to the normal harness entry.
 * Then run 10 iterations via RUN_ITERATION — each must return OK.
 * ------------------------------------------------------------------ */
static int test_c_normal_after_crash(int fd)
{
	struct phantom_run_args rargs;
	struct phantom_iter_params params;
	struct phantom_iter_result res;
	int failures = 0;
	int i, ret;
	char buf[128];

	printf("\n--- Test C: normal iterations after crashes ---\n");

	/*
	 * Re-prime with test_id=8 (kAFL/Nyx harness).
	 * This loads the normal harness binary, fires GET_PAYLOAD +
	 * ACQUIRE (new snapshot), reads payload[0..7], and RELEASE.
	 */
	memset(&rargs, 0, sizeof(rargs));
	rargs.cpu      = 0;
	rargs.reserved = 8;	/* test_id=8: normal kAFL harness */

	ret = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &rargs);
	if (ret != 0) {
		snprintf(buf, sizeof(buf),
			 "RUN_GUEST(test_id=8) errno=%d (%s)",
			 errno, strerror(errno));
		t_fail("C: RUN_GUEST(test_id=8) returned 0 (re-prime)", buf);
		return -1;
	}
	t_pass("C: RUN_GUEST(test_id=8) re-prime returned 0");

	printf("    re-prime: exit_reason=%u\n", rargs.exit_reason);

	/* 10 normal iterations — all must return PHANTOM_RESULT_OK */
	memset(&params, 0, sizeof(params));
	params.payload_len = 8;
	params.timeout_ms  = 0;

	for (i = 0; i < 10; i++) {
		ret = ioctl(fd, PHANTOM_IOCTL_RUN_ITERATION, &params);
		if (ret != 0) {
			failures++;
			printf("    iter %d: RUN_ITERATION errno=%d (%s)\n",
			       i, errno, strerror(errno));
			continue;
		}

		memset(&res, 0, sizeof(res));
		ret = ioctl(fd, PHANTOM_IOCTL_GET_RESULT, &res);
		if (ret != 0) {
			failures++;
			printf("    iter %d: GET_RESULT errno=%d (%s)\n",
			       i, errno, strerror(errno));
			continue;
		}

		if (res.status != PHANTOM_RESULT_OK) {
			failures++;
			printf("    iter %d: status=%u (expected %u OK)\n",
			       i, res.status, PHANTOM_RESULT_OK);
		}
	}

	if (failures == 0) {
		t_pass("C: 10 normal iterations after crashes: all OK");
	} else {
		snprintf(buf, sizeof(buf), "%d failures out of 10", failures);
		t_fail("C: normal iterations after crashes", buf);
	}

	printf("    completed 10 normal iterations, %d failures\n", failures);

	return failures == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------ */

int main(void)
{
	const char *dev = "/dev/phantom";
	int fd;
	int overall_ret = 0;

	printf("phantom crash detection test\n");
	printf("============================\n");

	fd = open(dev, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "FATAL: cannot open %s: %s\n",
			dev, strerror(errno));
		return 1;
	}
	printf("  opened %s (fd=%d)\n", dev, fd);

	/* Test A: PANIC → PHANTOM_RESULT_CRASH */
	if (test_a_panic_crash(fd) != 0) {
		fprintf(stderr, "ABORT: Test A failed; "
			"cannot proceed with iteration tests\n");
		close(fd);
		printf("\n=== Results: %d passed, %d failed ===\n",
		       pass_count, fail_count);
		return 1;
	}

	/* Test B: 100× crash + restore */
	if (test_b_repeated_crash(fd) != 0)
		overall_ret = 1;

	/* Test C: normal iterations work after crashes */
	if (test_c_normal_after_crash(fd) != 0)
		overall_ret = 1;

	close(fd);

	printf("\n============================\n");
	printf("=== Results: %d passed, %d failed ===\n",
	       pass_count, fail_count);

	if (fail_count > 0)
		overall_ret = 1;

	return overall_ret;
}
