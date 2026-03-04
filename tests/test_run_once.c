// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_run_once.c — minimal RUN_GUEST test (no rmmod)
 * Just runs the guest once and prints result + exit_reason.
 * Does NOT call rmmod so we can read dmesg afterward.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

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

int main(void)
{
	int fd, rc;
	struct phantom_run_args args;
	uint64_t expected = 0;
	int i;

	for (i = 0; i < 512; i++)
		expected ^= (uint64_t)(i + 1) * 0x1234567890ABCDEFull;

	printf("Expected checksum: 0x%016llx\n",
	       (unsigned long long)expected);

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	memset(&args, 0, sizeof(args));
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	printf("RUN_GUEST rc=%d errno=%d\n", rc, errno);
	printf("result      = 0x%016llx\n", (unsigned long long)args.result);
	printf("exit_reason = %u\n", args.exit_reason);
	printf("checksum %s\n",
	       args.result == expected ? "MATCH" : "MISMATCH");

	/* Run again */
	printf("--- Second run ---\n");
	memset(&args, 0, sizeof(args));
	rc = ioctl(fd, PHANTOM_IOCTL_RUN_GUEST, &args);
	printf("RUN_GUEST rc=%d errno=%d\n", rc, errno);
	printf("result      = 0x%016llx\n", (unsigned long long)args.result);
	printf("exit_reason = %u\n", args.exit_reason);

	close(fd);
	printf("Done. Check dmesg for exception details.\n");
	return 0;
}
