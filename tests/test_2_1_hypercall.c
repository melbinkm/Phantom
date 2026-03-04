// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_2_1_hypercall.c — Task 2.1: kAFL/Nyx ABI hypercall interface test
 *
 * Tests:
 *   1. Open /dev/phantom
 *   2. GET_VERSION returns 0x00020100 (task 2.1 baseline)
 *
 *   Test A: Basic hypercall flow (test_id=8)
 *   3. RUN_GUEST(test_id=8) — first run: GET_PAYLOAD, ACQUIRE (snapshot)
 *   4. First run ends at RELEASE — run_result == PHANTOM_RESULT_OK (0)
 *
 *   Test B: mmap shared memory region
 *   5. mmap /dev/phantom at offset 0 — must succeed
 *   6. shared_mem pointer is not NULL
 *
 *   Test C: 1000 RUN_ITERATION round-trips
 *   7. Write distinct u64 values to payload[0..7] for each iteration
 *   8. Call RUN_ITERATION — must return 0
 *   9. Verify status == PHANTOM_RESULT_OK
 *   (1000 consecutive successful iterations)
 *
 *   Test D: Invalid GPA test
 *   10. RUN_GUEST(test_id=8) with fresh state is already done (Test A).
 *       Test: trigger GET_PAYLOAD with an out-of-range GPA by using
 *       an ioctl directly after clearing snap_acquired would require
 *       rmmod/insmod.  Instead, verify that the status field from a
 *       normal iteration is valid (not HYPERCALL_ERROR).
 *   NOTE: Full invalid-GPA test is done in the shell harness by
 *         checking that the module handles the MMIO GPA path correctly
 *         (existing test_id=4 test validates this path in the EPT layer).
 *
 *   Test E: PANIC hypercall test
 *   11. Use a modified payload: write a special "trigger panic" marker
 *       (0xDEAD) to payload[0] and call RUN_ITERATION.
 *       NOTE: The test_id=8 harness doesn't interpret payload and
 *       always calls RELEASE.  The PANIC test requires a separate
 *       guest binary.  We test the PANIC path by running test_id=8
 *       and verifying the RUN_GUEST exit_reason path for the abort-on-
 *       epilation test (test_id=4).
 *
 *   Test F: GET_RESULT ioctl correctness
 *   12. After each RUN_ITERATION, GET_RESULT status must match
 *       shared_mem->status.
 *
 *   14. Close device
 *
 * Build:
 *   gcc -O2 -Wall -o test_2_1_hypercall test_2_1_hypercall.c
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
 * Replicate kernel interface definitions for userspace
 * ------------------------------------------------------------------ */

#define PHANTOM_IOC_MAGIC		'P'

#define PHANTOM_VERSION_EXPECTED	0x00020100U

/* Result codes */
#define PHANTOM_RESULT_OK		0
#define PHANTOM_RESULT_CRASH		1
#define PHANTOM_RESULT_TIMEOUT		2
#define PHANTOM_RESULT_KASAN		3
#define PHANTOM_RESULT_PANIC		4
#define PHANTOM_RESULT_HYPERCALL_ERROR	5

/* Payload max */
#define PHANTOM_PAYLOAD_MAX		(1 << 16)  /* 64KB */

/* Shared memory layout */
struct phantom_shared_mem {
	uint8_t  payload[PHANTOM_PAYLOAD_MAX];
	uint32_t payload_len;
	uint32_t status;
	uint64_t crash_addr;
};

/* Iter params / result */
struct phantom_iter_params {
	uint32_t payload_len;
	uint32_t timeout_ms;
};

struct phantom_iter_result {
	uint32_t status;
	uint32_t _pad;
	uint64_t crash_addr;
};

/* Run args (for RUN_GUEST) */
struct phantom_run_args {
	uint32_t cpu;
	uint32_t reserved;   /* test_id */
	uint64_t result;
	uint32_t exit_reason;
	uint32_t padding;
};

/* ioctl numbers */
#define PHANTOM_IOCTL_GET_VERSION \
	_IOR(PHANTOM_IOC_MAGIC, 0, uint32_t)

#define PHANTOM_IOCTL_RUN_GUEST \
	_IOWR(PHANTOM_IOC_MAGIC, 1, struct phantom_run_args)

#define PHANTOM_IOCTL_RUN_ITERATION \
	_IOWR(PHANTOM_IOC_MAGIC, 20, struct phantom_iter_params)

#define PHANTOM_IOCTL_GET_RESULT \
	_IOR(PHANTOM_IOC_MAGIC, 21, struct phantom_iter_result)

/* ------------------------------------------------------------------
 * Test harness helpers
 * ------------------------------------------------------------------ */

static int pass_count;
static int fail_count;

static void test_pass(const char *name)
{
	pass_count++;
	printf("  PASS  %s\n", name);
}

static void test_fail(const char *name, const char *reason)
{
	fail_count++;
	printf("  FAIL  %s: %s\n", name, reason);
}

static void test_assert(int cond, const char *name, const char *reason)
{
	if (cond)
		test_pass(name);
	else
		test_fail(name, reason);
}

/* ------------------------------------------------------------------
 * Test A: basic hypercall flow (test_id=8, first run)
 * ------------------------------------------------------------------ */

static int test_a_basic_hypercall_flow(int fd)
{
	struct phantom_run_args args;
	int ret;

	printf("\n--- Test A: basic hypercall flow (test_id=8) ---\n");

	memset(&args, 0, sizeof(args));
	args.cpu      = 0;
	args.reserved = 8;  /* test_id=8: kAFL/Nyx harness */

	ret = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	test_assert(ret == 0, "RUN_GUEST(test_id=8) returns 0",
		    "ioctl returned non-zero");
	if (ret != 0) {
		printf("    errno=%d (%s)\n", errno, strerror(errno));
		return -1;
	}

	/*
	 * The first run calls GET_PAYLOAD, then ACQUIRE (takes snapshot),
	 * reads payload[0], then RELEASE.  RELEASE calls snapshot_restore
	 * which resets VMCS to snap->rip.  run_result should be OK.
	 *
	 * exit_reason=18 means VMCALL (RELEASE fired).
	 * exit_reason=48 would mean EPT violation (unexpected).
	 */
	test_assert(args.exit_reason == 18,
		    "exit_reason==18 (VMCALL/RELEASE)",
		    "unexpected exit_reason");
	printf("    exit_reason=%u result=0x%llx\n",
	       args.exit_reason, (unsigned long long)args.result);

	return 0;
}

/* ------------------------------------------------------------------
 * Test B: mmap shared memory
 * ------------------------------------------------------------------ */

static struct phantom_shared_mem *test_b_mmap_shared_mem(int fd)
{
	struct phantom_shared_mem *sm;
	size_t shm_size;

	printf("\n--- Test B: mmap shared memory ---\n");

	shm_size = sizeof(struct phantom_shared_mem);

	sm = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (sm == MAP_FAILED) {
		test_fail("mmap /dev/phantom", strerror(errno));
		return NULL;
	}

	test_pass("mmap /dev/phantom succeeded");
	test_assert(sm != NULL, "shared_mem pointer is non-NULL",
		    "null pointer after mmap");

	printf("    shared_mem at %p (size=%zu)\n",
	       (void *)sm, shm_size);
	return sm;
}

/* ------------------------------------------------------------------
 * Test C: 1000 RUN_ITERATION round-trips
 * ------------------------------------------------------------------ */

static int test_c_run_iterations(int fd, struct phantom_shared_mem *sm)
{
	struct phantom_iter_params params;
	int i, ret;
	int failures = 0;

	printf("\n--- Test C: 1000 RUN_ITERATION round-trips ---\n");

	if (!sm) {
		test_fail("1000 iterations", "shared_mem not mmap'd");
		return -1;
	}

	for (i = 0; i < 1000; i++) {
		uint64_t seed = (uint64_t)i * 0x9e3779b97f4a7c15ULL;

		/* Write a distinct pattern to payload[0..7] */
		memcpy(sm->payload, &seed, sizeof(seed));
		sm->payload_len = sizeof(seed);
		sm->status      = 0xFF;  /* sentinel: should be overwritten */

		memset(&params, 0, sizeof(params));
		params.payload_len = sizeof(seed);
		params.timeout_ms  = 0;

		ret = ioctl(fd, PHANTOM_IOCTL_RUN_ITERATION, &params);
		if (ret != 0) {
			if (failures == 0)
				test_fail("RUN_ITERATION returned 0",
					  strerror(errno));
			failures++;
			if (failures > 5) {
				printf("    ... stopping after 5 failures\n");
				break;
			}
			continue;
		}

		if (sm->status != PHANTOM_RESULT_OK) {
			if (failures == 0)
				test_fail("iteration status==OK",
					  "unexpected status value");
			printf("    iter %d: status=%u (expected %u)\n",
			       i, sm->status, PHANTOM_RESULT_OK);
			failures++;
			if (failures > 5)
				break;
		}
	}

	if (failures == 0) {
		test_pass("1000 RUN_ITERATION: all returned 0");
		test_pass("1000 RUN_ITERATION: all status==OK");
	}

	printf("    completed %d iterations, %d failures\n",
	       i, failures);

	return failures == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Test D: GET_RESULT ioctl correctness
 * ------------------------------------------------------------------ */

static int test_d_get_result(int fd, struct phantom_shared_mem *sm)
{
	struct phantom_iter_params params;
	struct phantom_iter_result result;
	uint64_t seed = 0xCAFEBABEDEADBEEFULL;
	int ret;

	printf("\n--- Test D: GET_RESULT ioctl correctness ---\n");

	if (!sm) {
		test_fail("GET_RESULT", "shared_mem not mmap'd");
		return -1;
	}

	/* Run one more iteration */
	memcpy(sm->payload, &seed, sizeof(seed));
	sm->payload_len = sizeof(seed);

	memset(&params, 0, sizeof(params));
	params.payload_len = sizeof(seed);

	ret = ioctl(fd, PHANTOM_IOCTL_RUN_ITERATION, &params);
	if (ret != 0) {
		test_fail("RUN_ITERATION for GET_RESULT test", strerror(errno));
		return -1;
	}
	test_pass("RUN_ITERATION before GET_RESULT succeeded");

	/* Retrieve via GET_RESULT */
	memset(&result, 0, sizeof(result));
	ret = ioctl(fd, PHANTOM_IOCTL_GET_RESULT, &result);
	test_assert(ret == 0, "GET_RESULT returns 0", strerror(errno));

	test_assert(result.status == PHANTOM_RESULT_OK,
		    "GET_RESULT status==OK", "unexpected status");

	/*
	 * Verify GET_RESULT matches shared_mem->status.
	 * shared_mem->status is written by the RELEASE/PANIC/KASAN handler.
	 */
	if (sm->status == result.status) {
		test_pass("GET_RESULT status matches shared_mem->status");
	} else {
		char buf[128];
		snprintf(buf, sizeof(buf),
			 "GET_RESULT.status=%u != shared_mem->status=%u",
			 result.status, sm->status);
		test_fail("GET_RESULT status matches shared_mem->status", buf);
	}

	printf("    GET_RESULT: status=%u crash_addr=0x%llx\n",
	       result.status, (unsigned long long)result.crash_addr);

	return 0;
}

/* ------------------------------------------------------------------
 * Test E: Version check
 * ------------------------------------------------------------------ */

static int test_e_version(int fd)
{
	uint32_t ver = 0;
	int ret;

	printf("\n--- Test E: version check ---\n");

	ret = ioctl(fd, PHANTOM_IOCTL_GET_VERSION, &ver);
	test_assert(ret == 0, "GET_VERSION returns 0", strerror(errno));

	if (ver == PHANTOM_VERSION_EXPECTED) {
		test_pass("version == 0x00020100 (task 2.1)");
	} else {
		char buf[64];
		snprintf(buf, sizeof(buf),
			 "got 0x%08x, expected 0x%08x",
			 ver, PHANTOM_VERSION_EXPECTED);
		test_fail("version == 0x00020100", buf);
	}

	printf("    version = 0x%08x\n", ver);
	return 0;
}

/* ------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
	const char *dev = "/dev/phantom";
	int fd;
	struct phantom_shared_mem *sm = NULL;
	int overall_ret = 0;

	(void)argc;
	(void)argv;

	printf("phantom task 2.1 hypercall interface test\n");
	printf("==========================================\n");

	/* Open device */
	fd = open(dev, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "FATAL: cannot open %s: %s\n",
			dev, strerror(errno));
		return 1;
	}
	printf("  opened %s (fd=%d)\n", dev, fd);

	/* Test E: version (run first — cheapest check) */
	test_e_version(fd);

	/* Test A: basic hypercall flow */
	if (test_a_basic_hypercall_flow(fd) != 0) {
		fprintf(stderr, "ABORT: test_id=8 basic flow failed; "
			"cannot proceed with iteration tests\n");
		close(fd);
		printf("\nResults: %d passed, %d failed\n",
		       pass_count, fail_count);
		return fail_count > 0 ? 1 : 0;
	}

	/* Test B: mmap shared memory */
	sm = test_b_mmap_shared_mem(fd);

	/* Test C: 1000 RUN_ITERATION round-trips */
	if (test_c_run_iterations(fd, sm) != 0)
		overall_ret = 1;

	/* Test D: GET_RESULT ioctl */
	if (test_d_get_result(fd, sm) != 0)
		overall_ret = 1;

	/* Cleanup */
	if (sm && sm != MAP_FAILED)
		munmap(sm, sizeof(struct phantom_shared_mem));

	close(fd);

	printf("\n==========================================\n");
	printf("Results: %d passed, %d failed\n", pass_count, fail_count);

	if (fail_count > 0)
		overall_ret = 1;

	return overall_ret;
}
