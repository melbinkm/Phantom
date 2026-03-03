// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_ioctl.c — userspace ioctl validation for /dev/phantom
 *
 * Tests:
 *   1. Open /dev/phantom
 *   2. PHANTOM_IOCTL_GET_VERSION → expect 0x00010100
 *   3. Unknown ioctl → expect ENOTTY
 *   4. Close device
 *
 * Build (inside guest):
 *   gcc -O2 -Wall -o test_ioctl test_ioctl.c
 *
 * Exit codes:
 *   0  — all tests passed
 *   1  — one or more tests failed
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdint.h>

/* Mirror of kernel-side definitions — must stay in sync with interface.h */
#define PHANTOM_IOCTL_MAGIC		'P'
#define PHANTOM_VERSION			0x00010100U
#define PHANTOM_IOCTL_GET_VERSION	_IOR(PHANTOM_IOCTL_MAGIC, 0, uint32_t)

/* Unknown command used to verify -ENOTTY path */
#define PHANTOM_IOCTL_UNKNOWN		_IOR(PHANTOM_IOCTL_MAGIC, 255, uint32_t)

#define DEVICE_PATH	"/dev/phantom"

static int tests_run  = 0;
static int tests_pass = 0;

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

int main(void)
{
	int fd;
	uint32_t ver = 0;
	int rc;

	printf("=== phantom ioctl test ===\n");

	/* Test 1: open device */
	fd = open(DEVICE_PATH, O_RDWR);
	check("open /dev/phantom", fd >= 0);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n",
			DEVICE_PATH, strerror(errno));
		return 1;
	}

	/* Test 2: GET_VERSION returns correct version */
	ver = 0;
	rc  = ioctl(fd, PHANTOM_IOCTL_GET_VERSION, &ver);
	check("ioctl GET_VERSION succeeds", rc == 0);
	check("version == 0x00010100",       ver == PHANTOM_VERSION);

	if (rc == 0)
		printf("      version = 0x%08x\n", ver);
	else
		fprintf(stderr, "      ioctl failed: %s\n", strerror(errno));

	/* Test 3: unknown ioctl returns ENOTTY */
	rc = ioctl(fd, PHANTOM_IOCTL_UNKNOWN, &ver);
	check("unknown ioctl returns ENOTTY",
	      rc == -1 && errno == ENOTTY);

	/* Test 4: close */
	rc = close(fd);
	check("close /dev/phantom", rc == 0);

	printf("\n=== %d/%d tests passed ===\n", tests_pass, tests_run);
	return (tests_pass == tests_run) ? 0 : 1;
}
