// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_2_3_api.c — Task 2.3: Final ioctl API + mmap bounds enforcement
 *
 * Tests:
 *   Test A: Version == 0x00020300
 *   Test B: PHANTOM_CREATE_VM returns 0, instance_id == 0
 *   Test C: Out-of-range mmap offset returns EINVAL
 *   Test D: PHANTOM_MMAP_PAYLOAD (0x00000) mmap succeeds (RW)
 *   Test E: SET_SNAPSHOT → RUN_ITERATION → GET_STATUS flow
 *   Test F: Legacy ioctl numbers still work (regression)
 *   Test G: PHANTOM_LOAD_TARGET copies payload into shared memory
 *   Test H: PHANTOM_DESTROY_VM returns 0
 *
 * Build:
 *   gcc -O2 -Wall -o test_2_3_api test_2_3_api.c
 *
 * Exit codes:
 *   0 — all tests passed
 *   1 — one or more tests failed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/types.h>
#include <linux/ioctl.h>

/* ------------------------------------------------------------------ */
/* Duplicate the kernel header definitions for userspace               */
/* ------------------------------------------------------------------ */

#define PHANTOM_VERSION_EXPECTED  0x00020300U

#define PHANTOM_PAYLOAD_MAX       (1 << 16)   /* 64KB */

/* Legacy ioctl magic (same as new) */
#define PHANTOM_IOCTL_MAGIC       'P'

/* Legacy ioctls */
#define PHANTOM_IOCTL_GET_VERSION \
	_IOR(PHANTOM_IOCTL_MAGIC, 0, __u32)

struct phantom_run_args_legacy {
	__u32 cpu;
	__u32 reserved;   /* test_id */
	__u64 result;
	__u32 exit_reason;
	__u32 padding;
};
#define PHANTOM_IOCTL_RUN_GUEST \
	_IOWR(PHANTOM_IOCTL_MAGIC, 1, struct phantom_run_args_legacy)

struct phantom_iter_params {
	__u32 payload_len;
	__u32 timeout_ms;
};
#define PHANTOM_IOCTL_RUN_ITERATION \
	_IOWR(PHANTOM_IOCTL_MAGIC, 20, struct phantom_iter_params)

struct phantom_iter_result {
	__u32 status;
	__u32 _pad;
	__u64 crash_addr;
};
#define PHANTOM_IOCTL_GET_RESULT \
	_IOR(PHANTOM_IOCTL_MAGIC, 21, struct phantom_iter_result)

#define PHANTOM_IOCTL_SNAPSHOT_CREATE  _IO(PHANTOM_IOCTL_MAGIC, 9)
#define PHANTOM_IOCTL_SNAPSHOT_RESTORE _IO(PHANTOM_IOCTL_MAGIC, 10)

/* New Task 2.3 ioctl API */
#define PHANTOM_IOC_MAGIC  PHANTOM_IOCTL_MAGIC

struct phantom_create_args {
	__u32 pinned_cpu;
	__u32 cow_pool_pages;
	__u32 topa_size_mb;
	__u32 guest_mem_mb;
	__u32 instance_id;
	__u32 _pad;
};

struct phantom_load_args {
	__u64 gpa;
	__u64 userspace_ptr;
	__u64 size;
};

struct phantom_run_args2 {
	__u64 payload_ptr;
	__u32 payload_size;
	__u32 timeout_ms;
	__u32 result;
	__u32 exit_reason;
	__u64 checksum;
};

struct phantom_status {
	__u32 result;
	__u32 exit_reason;
	__u64 crash_addr;
	__u64 checksum;
	__u64 iterations;
};

#define PHANTOM_CREATE_VM \
	_IOWR(PHANTOM_IOC_MAGIC, 0x30, struct phantom_create_args)
#define PHANTOM_LOAD_TARGET \
	_IOW(PHANTOM_IOC_MAGIC,  0x31, struct phantom_load_args)
#define PHANTOM_SET_SNAPSHOT \
	_IO(PHANTOM_IOC_MAGIC,   0x32)
#define PHANTOM_RUN_ITERATION \
	_IOWR(PHANTOM_IOC_MAGIC, 0x33, struct phantom_run_args2)
#define PHANTOM_GET_STATUS \
	_IOR(PHANTOM_IOC_MAGIC,  0x34, struct phantom_status)
#define PHANTOM_DESTROY_VM \
	_IO(PHANTOM_IOC_MAGIC,   0x35)

/* mmap region offsets */
#define PHANTOM_MMAP_PAYLOAD     0x00000UL
#define PHANTOM_MMAP_BITMAP      0x10000UL
#define PHANTOM_MMAP_TOPA_BUF_A  0x20000UL
#define PHANTOM_MMAP_TOPA_BUF_B  0x30000UL
#define PHANTOM_MMAP_STATUS      0x40000UL

/* Result codes */
#define PHANTOM_RESULT_OK     0
#define PHANTOM_RESULT_CRASH  1

/* shared_mem layout */
struct phantom_shared_mem {
	uint8_t  payload[PHANTOM_PAYLOAD_MAX];
	uint32_t payload_len;
	uint32_t status;
	uint64_t crash_addr;
};

/* ------------------------------------------------------------------ */

static int pass_count;
static int fail_count;
static const char *device = "/dev/phantom";

static void pass(const char *name)
{
	printf("PASS  %s\n", name);
	pass_count++;
}

static void fail(const char *name, const char *reason)
{
	printf("FAIL  %s — %s\n", name, reason);
	fail_count++;
}

int main(void)
{
	int fd;
	int ret;
	__u32 ver;
	struct phantom_create_args cargs;
	struct phantom_load_args largs;
	struct phantom_run_args_legacy rargs_legacy;
	struct phantom_run_args2 rargs2;
	struct phantom_status st;
	struct phantom_iter_result legacy_result;
	struct phantom_shared_mem *sm;
	void *map_ptr;
	uint8_t payload_data[16];
	int i;

	printf("=== Task 2.3: Final ioctl API + mmap bounds test ===\n");

	fd = open(device, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "FATAL: open(%s): %s\n", device, strerror(errno));
		return 1;
	}

	/* ---- Test A: Version ------------------------------------------ */
	ver = 0;
	ret = ioctl(fd, PHANTOM_IOCTL_GET_VERSION, &ver);
	if (ret != 0) {
		fail("A: GET_VERSION ioctl returned error", strerror(errno));
	} else if (ver != PHANTOM_VERSION_EXPECTED) {
		char buf[64];
		snprintf(buf, sizeof(buf), "got 0x%08x, want 0x%08x",
			 ver, PHANTOM_VERSION_EXPECTED);
		fail("A: version mismatch", buf);
	} else {
		pass("A: PHANTOM_VERSION == 0x00020300");
	}

	/* ---- Test B: PHANTOM_CREATE_VM -------------------------------- */
	memset(&cargs, 0, sizeof(cargs));
	cargs.pinned_cpu     = 0;
	cargs.cow_pool_pages = 0;
	cargs.topa_size_mb   = 0;
	cargs.guest_mem_mb   = 0;
	cargs.instance_id    = 0xFFFFFFFF; /* will be overwritten by kernel */

	ret = ioctl(fd, PHANTOM_CREATE_VM, &cargs);
	if (ret != 0) {
		fail("B: PHANTOM_CREATE_VM returned non-zero", strerror(errno));
	} else if (cargs.instance_id != 0) {
		char buf[32];
		snprintf(buf, sizeof(buf), "instance_id=%u", cargs.instance_id);
		fail("B: instance_id not 0", buf);
	} else {
		pass("B: PHANTOM_CREATE_VM returns 0, instance_id=0");
	}

	/* ---- Test C: Out-of-range mmap offset returns EINVAL ---------- */
	map_ptr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0x50000);
	if (map_ptr == MAP_FAILED && errno == EINVAL) {
		pass("C: mmap(offset=0x50000) returns EINVAL");
	} else if (map_ptr != MAP_FAILED) {
		munmap(map_ptr, 4096);
		fail("C: mmap(offset=0x50000) succeeded (expected EINVAL)", "");
	} else {
		char buf[64];
		snprintf(buf, sizeof(buf), "errno=%s", strerror(errno));
		fail("C: mmap(offset=0x50000) wrong error", buf);
	}

	/* Also check a completely bogus offset */
	map_ptr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0x99000);
	if (map_ptr == MAP_FAILED && errno == EINVAL) {
		pass("C2: mmap(offset=0x99000) returns EINVAL");
	} else {
		if (map_ptr != MAP_FAILED)
			munmap(map_ptr, 4096);
		fail("C2: mmap(offset=0x99000) wrong result", strerror(errno));
	}

	/* ---- Test D: PHANTOM_MMAP_PAYLOAD (0x00000) succeeds (RW) ---- */
	/*
	 * First prime the state by running the kAFL harness guest
	 * (test_id=8) so that shared_mem is allocated and ACQUIRE fires.
	 */
	memset(&rargs_legacy, 0, sizeof(rargs_legacy));
	rargs_legacy.reserved = 8; /* test_id=8: kAFL harness */
	ret = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &rargs_legacy);

	if (ret != 0) {
		fail("D-setup: RUN_GUEST(test_id=8) failed", strerror(errno));
		/* Cannot proceed without shared_mem */
		goto skip_d;
	}

	sm = mmap(NULL, PHANTOM_PAYLOAD_MAX, PROT_READ | PROT_WRITE,
		  MAP_SHARED, fd, PHANTOM_MMAP_PAYLOAD);
	if (sm == MAP_FAILED) {
		fail("D: mmap(PHANTOM_MMAP_PAYLOAD) failed", strerror(errno));
	} else {
		/* Write to it — should succeed (RW) */
		sm->payload[0] = 0xAB;
		if (sm->payload[0] == 0xAB) {
			pass("D: PHANTOM_MMAP_PAYLOAD maps RW, write succeeded");
		} else {
			fail("D: payload write not reflected", "readback mismatch");
		}
		munmap(sm, PHANTOM_PAYLOAD_MAX);
	}

skip_d:

	/* ---- Test E: SET_SNAPSHOT → RUN_ITERATION → GET_STATUS ------- */
	/*
	 * snap_acquired is set after the ACQUIRE hypercall in test_id=8
	 * above.  We can now call PHANTOM_SET_SNAPSHOT directly
	 * (equivalent to PHANTOM_IOCTL_SNAPSHOT_CREATE).
	 */
	ret = ioctl(fd, PHANTOM_SET_SNAPSHOT);
	if (ret != 0 && errno != EINVAL) {
		char buf[64];
		snprintf(buf, sizeof(buf), "ret=%d errno=%s", ret, strerror(errno));
		fail("E: PHANTOM_SET_SNAPSHOT failed", buf);
		goto skip_e;
	}
	if (ret == 0) {
		pass("E1: PHANTOM_SET_SNAPSHOT succeeded");
	} else {
		/* EINVAL means snapshot already taken — acceptable */
		pass("E1: PHANTOM_SET_SNAPSHOT returned EINVAL "
		     "(already snapshotted — OK)");
	}

	/* RUN_ITERATION with new API */
	memset(payload_data, 0, sizeof(payload_data));
	for (i = 0; i < 8; i++)
		payload_data[i] = (uint8_t)(i + 1);

	memset(&rargs2, 0, sizeof(rargs2));
	rargs2.payload_ptr  = (uint64_t)(uintptr_t)payload_data;
	rargs2.payload_size = 8;
	rargs2.timeout_ms   = 0;

	ret = ioctl(fd, PHANTOM_RUN_ITERATION, &rargs2);
	if (ret != 0) {
		char buf[64];
		snprintf(buf, sizeof(buf), "ret=%d errno=%s", ret, strerror(errno));
		fail("E2: PHANTOM_RUN_ITERATION (new API) failed", buf);
	} else {
		pass("E2: PHANTOM_RUN_ITERATION (new API) returned 0");
		if (rargs2.result == PHANTOM_RESULT_OK) {
			pass("E3: result == PHANTOM_RESULT_OK");
		} else {
			char buf[32];
			snprintf(buf, sizeof(buf), "result=%u", rargs2.result);
			fail("E3: unexpected result", buf);
		}
	}

	/* GET_STATUS */
	memset(&st, 0xFF, sizeof(st));
	ret = ioctl(fd, PHANTOM_GET_STATUS, &st);
	if (ret != 0) {
		fail("E4: PHANTOM_GET_STATUS failed", strerror(errno));
	} else {
		pass("E4: PHANTOM_GET_STATUS returned 0");
		if (st.result == PHANTOM_RESULT_OK) {
			pass("E5: GET_STATUS result == OK");
		} else {
			char buf[32];
			snprintf(buf, sizeof(buf), "result=%u", st.result);
			fail("E5: GET_STATUS result unexpected", buf);
		}
	}

skip_e:

	/* ---- Test F: Legacy ioctl regression -------------------------- */
	/*
	 * Verify that legacy ioctl command numbers still dispatch correctly.
	 * GET_VERSION (cmd 0) was already tested in Test A.
	 * Test GET_RESULT (cmd 21) here.
	 */
	memset(&legacy_result, 0xFF, sizeof(legacy_result));
	ret = ioctl(fd, PHANTOM_IOCTL_GET_RESULT, &legacy_result);
	if (ret != 0) {
		fail("F: legacy GET_RESULT (cmd 21) returned error",
		     strerror(errno));
	} else {
		pass("F: legacy GET_RESULT (cmd 21) still works");
	}

	/* ---- Test G: PHANTOM_LOAD_TARGET ------------------------------ */
	{
		uint8_t load_buf[32];
		void *verify_sm;

		for (i = 0; i < 32; i++)
			load_buf[i] = (uint8_t)(0xC0 + i);

		memset(&largs, 0, sizeof(largs));
		largs.gpa          = 0;
		largs.userspace_ptr = (uint64_t)(uintptr_t)load_buf;
		largs.size         = 32;

		ret = ioctl(fd, PHANTOM_LOAD_TARGET, &largs);
		if (ret != 0) {
			fail("G: PHANTOM_LOAD_TARGET failed", strerror(errno));
			goto skip_g;
		}

		/* Verify payload was written to shared_mem */
		verify_sm = mmap(NULL, PHANTOM_PAYLOAD_MAX,
				 PROT_READ | PROT_WRITE,
				 MAP_SHARED, fd, PHANTOM_MMAP_PAYLOAD);
		if (verify_sm == MAP_FAILED) {
			fail("G: mmap for verify failed", strerror(errno));
			goto skip_g;
		}

		{
			const uint8_t *p = (const uint8_t *)verify_sm;
			int match = 1;

			for (i = 0; i < 32; i++) {
				if (p[i] != (uint8_t)(0xC0 + i)) {
					match = 0;
					break;
				}
			}
			if (match) {
				pass("G: PHANTOM_LOAD_TARGET payload visible "
				     "in mmap region");
			} else {
				fail("G: payload mismatch after LOAD_TARGET",
				     "bytes don't match");
			}
		}
		munmap(verify_sm, PHANTOM_PAYLOAD_MAX);
	}
skip_g:

	/* ---- Test H: PHANTOM_DESTROY_VM ------------------------------- */
	ret = ioctl(fd, PHANTOM_DESTROY_VM);
	if (ret != 0) {
		fail("H: PHANTOM_DESTROY_VM returned error", strerror(errno));
	} else {
		pass("H: PHANTOM_DESTROY_VM returned 0");
	}

	close(fd);

	printf("\n=== Results: %d passed, %d failed ===\n",
	       pass_count, fail_count);

	return (fail_count > 0) ? 1 : 0;
}
