// SPDX-License-Identifier: GPL-2.0-only
/*
 * afl_phantom.h — shared types and ioctl wrappers for AFL++ fork-server shim
 *
 * Included by both afl_phantom.c and any test harness that wants to drive
 * /dev/phantom directly without the AFL++ pipe protocol.
 */
#ifndef AFL_PHANTOM_H
#define AFL_PHANTOM_H

#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

/*
 * Pull in the kernel interface header.  We replicate the minimal subset here
 * (the types it needs from <linux/types.h>) so this file compiles in userspace
 * without a kernel build tree.
 */
#include <linux/types.h>
#include "../../kernel/interface.h"

/* ------------------------------------------------------------------
 * Iteration result codes — mirror of PHANTOM_RESULT_* from phantom.h.
 *
 * phantom.h is a kernel-only header (includes linux/cdev.h etc.) so
 * we redeclare the result codes here for userspace consumers.
 * These values are part of the ioctl ABI and must stay in sync.
 * ------------------------------------------------------------------ */
#define PHANTOM_RESULT_OK		0
#define PHANTOM_RESULT_CRASH		1
#define PHANTOM_RESULT_TIMEOUT		2
#define PHANTOM_RESULT_KASAN		3
#define PHANTOM_RESULT_PANIC		4
#define PHANTOM_RESULT_HYPERCALL_ERROR	5

/* ------------------------------------------------------------------
 * AFL++ fork-server protocol constants
 * ------------------------------------------------------------------ */

/* File descriptors used by AFL++ for the fork-server pipe */
#define FORKSRV_FD		198

/* AFL++ edge bitmap size: 64KB */
#define AFL_MAP_SIZE		(64 * 1024)

/* Environment variable AFL++ sets with the shmid of its bitmap */
#define SHM_ENV_VAR		"__AFL_SHM_ID"

/* ------------------------------------------------------------------
 * AFL++ shmem fuzz protocol constants
 *
 * FS_OPT_* flags are written in the 4-byte "hello" from the fork
 * server to AFL++, then confirmed back.  When both sides agree on
 * FS_OPT_SHDMEM_FUZZ, the testcase is delivered via shared memory
 * instead of file I/O — this is the key to high-speed fuzzing.
 * ------------------------------------------------------------------ */
#define FS_OPT_ENABLED		0x80000001U
#define FS_OPT_MAPSIZE		0x40000000U
#define FS_OPT_SHDMEM_FUZZ	0x01000000U

/* Env var AFL++ sets with the shmid for testcase delivery shmem */
#define SHM_FUZZ_ENV_VAR	"__AFL_SHM_FUZZ_ID"

/* ------------------------------------------------------------------
 * Signal codes used to communicate iteration outcome to AFL++
 *
 * AFL++ interprets the 4-byte status written to FORKSRV_FD+1 as a
 * Unix wait(2) status: a non-zero low byte means signal death.
 * ------------------------------------------------------------------ */
#define AFL_STATUS_OK		0   /* normal completion              */
#define AFL_STATUS_CRASH	11  /* SIGSEGV — guest fault/panic    */
#define AFL_STATUS_TIMEOUT	9   /* SIGKILL — VMX preemption timer */
#define AFL_STATUS_KASAN	6   /* SIGABRT — KASAN violation      */

/* ------------------------------------------------------------------
 * Inline ioctl helpers
 * ------------------------------------------------------------------ */

static inline int phantom_get_version(int fd, uint32_t *ver)
{
	return ioctl(fd, PHANTOM_IOCTL_GET_VERSION, ver);
}

static inline int phantom_create_vm(int fd, struct phantom_create_args *args)
{
	return ioctl(fd, PHANTOM_CREATE_VM, args);
}

static inline int phantom_set_snapshot(int fd)
{
	return ioctl(fd, PHANTOM_SET_SNAPSHOT);
}

static inline int phantom_run_iteration(int fd, struct phantom_run_args2 *args)
{
	return ioctl(fd, PHANTOM_RUN_ITERATION, args);
}

static inline int phantom_get_status(int fd, struct phantom_status *st)
{
	return ioctl(fd, PHANTOM_GET_STATUS, st);
}

static inline int phantom_destroy_vm(int fd)
{
	return ioctl(fd, PHANTOM_DESTROY_VM);
}

#endif /* AFL_PHANTOM_H */
