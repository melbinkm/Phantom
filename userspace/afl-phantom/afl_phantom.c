// SPDX-License-Identifier: GPL-2.0-only
/*
 * afl_phantom.c — AFL++ persistent-mode fork-server replacement for Phantom
 *
 * Drives /dev/phantom instead of fork().  In persistent mode the process
 * never forks; it calls PHANTOM_RUN_ITERATION in a tight loop, copying the
 * coverage bitmap into AFL++'s shared memory after each iteration.
 *
 * Usage (with AFL++):
 *   AFL_SKIP_CPUFREQ=1 afl-fuzz -i corpus/ -o out/ -- ./afl-phantom
 *
 * Usage (standalone test):
 *   ./afl-phantom --test [--payload-file /tmp/in.bin] [--iterations N]
 */

#include "afl_phantom.h"

#include <getopt.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

/* ------------------------------------------------------------------
 * Global state
 * ------------------------------------------------------------------ */

static int   phantom_fd    = -1;
static void *payload_map   = NULL;  /* PHANTOM_MMAP_PAYLOAD (RW, 64KB)  */
static void *bitmap_map    = NULL;  /* PHANTOM_MMAP_BITMAP  (RO, 64KB)  */
static void *afl_bitmap    = NULL;  /* AFL++ shm bitmap pointer         */

/* Set when --bzimage is used (Class B boot, skip bootstrap_test_guest) */
static int g_bzimage_mode = 0;

/* Multi-core state (-j N) */
#define PHANTOM_MAX_CORES 8

struct core_state {
	int      fd;
	void    *payload_map;
	void    *bitmap_map;
	int      core_id;
	uint32_t iterations;
	uint32_t timeout_ms;
	/* results */
	uint64_t ok;
	uint64_t crash;
	uint64_t timeout_cnt;
	uint64_t kasan;
	uint64_t other;
	double   exec_per_sec;
};

static struct core_state g_cores[PHANTOM_MAX_CORES];
static int g_num_cores = 0;

/* ------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------ */

static void die(const char *msg)
{
	perror(msg);
	exit(1);
}

/*
 * open_phantom - open /dev/phantom and verify version.
 */
static void open_phantom(void)
{
	uint32_t ver;

	phantom_fd = open("/dev/phantom", O_RDWR);
	if (phantom_fd < 0)
		die("open /dev/phantom");

	if (phantom_get_version(phantom_fd, &ver) < 0)
		die("PHANTOM_IOCTL_GET_VERSION");

	if ((ver >> 16) < 2) {
		fprintf(stderr, "afl-phantom: kernel version 0x%08x < 2.x.x, "
			"need task 2.3+\n", ver);
		exit(1);
	}
}

/*
 * setup_mmap - mmap payload (RW) and bitmap (RO) regions.
 */
static void setup_mmap(void)
{
	/* Payload buffer: RW, 64KB */
	payload_map = mmap(NULL, AFL_MAP_SIZE,
			   PROT_READ | PROT_WRITE,
			   MAP_SHARED,
			   phantom_fd,
			   PHANTOM_MMAP_PAYLOAD);
	if (payload_map == MAP_FAILED)
		die("mmap PHANTOM_MMAP_PAYLOAD");

	/* Coverage bitmap: RO, 64KB */
	bitmap_map = mmap(NULL, AFL_MAP_SIZE,
			  PROT_READ,
			  MAP_SHARED,
			  phantom_fd,
			  PHANTOM_MMAP_BITMAP);
	if (bitmap_map == MAP_FAILED)
		die("mmap PHANTOM_MMAP_BITMAP");
}

/*
 * setup_afl_shm - attach to AFL++ shared bitmap via __AFL_SHM_ID env var.
 *
 * In standalone test mode this is not called; afl_bitmap remains NULL
 * and bitmap copying is skipped.
 */
static int setup_afl_shm(void)
{
	const char *shm_str = getenv(SHM_ENV_VAR);
	int shm_id;

	if (!shm_str)
		return -1;

	shm_id = atoi(shm_str);
	afl_bitmap = shmat(shm_id, NULL, 0);
	if (afl_bitmap == (void *)-1) {
		perror("shmat AFL shmem");
		return -1;
	}

	memset(afl_bitmap, 0, AFL_MAP_SIZE);
	return 0;
}

/*
 * create_vm - create a Phantom VM instance pinned to CPU 0.
 */
static void create_vm(void)
{
	struct phantom_create_args args;

	memset(&args, 0, sizeof(args));
	args.pinned_cpu    = 0;
	args.cow_pool_pages = 0;  /* use module default */
	args.topa_size_mb  = 0;  /* use module default */
	args.guest_mem_mb  = 0;  /* use module default */

	if (phantom_create_vm(phantom_fd, &args) < 0)
		die("PHANTOM_CREATE_VM");
}

/*
 * bootstrap_test_guest - launch the built-in kAFL fuzzing guest (test_id=8).
 *
 * This uses the legacy PHANTOM_IOCTL_RUN_GUEST ioctl to launch the
 * built-in test guest that implements the ACQUIRE/RELEASE hypercall
 * harness.  The guest fires ACQUIRE (which sets snap_acquired=true) and
 * then waits.  After this call returns, PHANTOM_SET_SNAPSHOT and
 * PHANTOM_RUN_ITERATION can be used.
 *
 * This is only used in --test mode to self-bootstrap without an
 * external target binary.
 */
static int bootstrap_test_guest(void)
{
	struct phantom_run_args args;

	memset(&args, 0, sizeof(args));
	args.cpu      = 0;
	args.reserved = 8;  /* test_id=8: kAFL ACQUIRE/RELEASE harness */

	if (ioctl(phantom_fd, PHANTOM_IOCTL_RUN_GUEST, &args) < 0) {
		fprintf(stderr, "afl-phantom: RUN_GUEST(test_id=8) failed: %s\n",
			strerror(errno));
		return -1;
	}

	/*
	 * After ACQUIRE fires the ioctl returns with the guest parked at
	 * the snapshot point.  Now take the snapshot.
	 */
	return 0;
}

/*
 * take_snapshot - call PHANTOM_SET_SNAPSHOT.
 *
 * The guest must already have reached its snapshot point (ACQUIRE hypercall)
 * before the first RUN_ITERATION.  In the production workflow the loader sets
 * this up.  In standalone test mode we just try; the ioctl may return -EINVAL
 * if the guest hasn't been set up, which the caller handles gracefully.
 */
static int take_snapshot(void)
{
	if (phantom_set_snapshot(phantom_fd) < 0) {
		if (errno == EINVAL) {
			fprintf(stderr, "afl-phantom: warning: "
				"PHANTOM_SET_SNAPSHOT returned -EINVAL "
				"(no snapshot point reached yet)\n");
			return -1;
		}
		die("PHANTOM_SET_SNAPSHOT");
	}
	return 0;
}

/*
 * map_result_to_afl_status - convert PHANTOM_RESULT_* to AFL signal code.
 */
static int map_result_to_afl_status(uint32_t result)
{
	switch (result) {
	case PHANTOM_RESULT_OK:
		return AFL_STATUS_OK;
	case PHANTOM_RESULT_CRASH:
	case PHANTOM_RESULT_PANIC:
		return AFL_STATUS_CRASH;
	case PHANTOM_RESULT_TIMEOUT:
		return AFL_STATUS_TIMEOUT;
	case PHANTOM_RESULT_KASAN:
		return AFL_STATUS_KASAN;
	default:
		/* Unknown / hypercall error: treat as crash */
		return AFL_STATUS_CRASH;
	}
}

/*
 * run_one_iteration - inject payload and run one Phantom iteration.
 *
 * payload/len: fuzz input buffer and length.
 * Returns the AFL++ status code to report.
 */
static int run_one_iteration(const uint8_t *payload, uint32_t len)
{
	struct phantom_run_args2 args;
	int afl_status;

	if (len > AFL_MAP_SIZE)
		len = AFL_MAP_SIZE;

	memset(&args, 0, sizeof(args));
	args.payload_ptr  = (uint64_t)(uintptr_t)payload;
	args.payload_size = len;
	args.timeout_ms   = 1000;

	if (phantom_run_iteration(phantom_fd, &args) < 0) {
		/*
		 * ioctl itself failed — likely the VM was destroyed after a
		 * crash.  Treat as crash so AFL++ records it.
		 */
		return AFL_STATUS_CRASH;
	}

	afl_status = map_result_to_afl_status(args.result);

	/* Copy Phantom bitmap → AFL++ shared memory */
	if (afl_bitmap)
		memcpy(afl_bitmap, bitmap_map, AFL_MAP_SIZE);

	return afl_status;
}

/* ------------------------------------------------------------------
 * AFL++ fork-server protocol (shmem fuzz mode)
 *
 * When AFL++ and our fork server agree on FS_OPT_SHDMEM_FUZZ,
 * testcases are delivered via shared memory instead of file I/O.
 * This eliminates the ~2.5ms per-iteration disk round-trip.
 *
 * Shmem layout: [u32 length][u8 data[...]]
 * AFL++ writes the testcase here before each "go" signal.
 * ------------------------------------------------------------------ */

/* Pointer to AFL++ shmem fuzz region (NULL if not using shmem) */
static uint8_t *afl_shmem_fuzz = NULL;

/*
 * setup_afl_shmem_fuzz - attach to AFL++ testcase delivery shmem.
 *
 * AFL++ creates this shmem and sets __AFL_SHM_FUZZ_ID in the
 * environment before spawning us.  If the env var is present,
 * we attach and use it for zero-copy testcase delivery.
 */
static int setup_afl_shmem_fuzz(void)
{
	const char *shm_str = getenv(SHM_FUZZ_ENV_VAR);
	int shm_id;
	void *ptr;

	if (!shm_str)
		return -1;

	shm_id = atoi(shm_str);
	ptr = shmat(shm_id, NULL, 0);
	if (ptr == (void *)-1) {
		perror("shmat AFL shmem fuzz");
		return -1;
	}

	afl_shmem_fuzz = (uint8_t *)ptr;
	return 0;
}

/*
 * run_forkserver - enter the AFL++ fork-server loop.
 *
 * Negotiates shmem fuzz mode with AFL++ if available.  In shmem
 * mode, testcases come from shared memory (zero I/O overhead).
 * Falls back to stdin file I/O if shmem is not available.
 *
 * Per-iteration protocol:
 *   1. Read 4 bytes from FORKSRV_FD (AFL++ says "go")
 *   2. Write 4 bytes to FORKSRV_FD+1 (fake child PID)
 *   3. Run one Phantom iteration
 *   4. Write 4 bytes to FORKSRV_FD+1 (waitpid-style exit status)
 */
static void run_forkserver(void)
{
	uint32_t hello;
	uint32_t cmd;
	int afl_status;
	uint32_t fake_pid = (uint32_t)getpid();
	int use_shmem = 0;

	/* Try to attach to AFL++ shmem fuzz region */
	if (setup_afl_shmem_fuzz() == 0)
		use_shmem = 1;

	/*
	 * Handshake: send hello with our supported options.
	 *
	 * If we have the shmem fuzz region, advertise FS_OPT_SHDMEM_FUZZ
	 * so AFL++ knows to write testcases there instead of to a file.
	 */
	if (use_shmem) {
		hello = FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ;
		if (write(FORKSRV_FD + 1, &hello, 4) != 4)
			die("write hello to FORKSRV_FD+1");

		/* Read AFL++ confirmation */
		if (read(FORKSRV_FD, &cmd, 4) != 4)
			die("read AFL++ confirmation");

		if (!(cmd & FS_OPT_SHDMEM_FUZZ)) {
			/* AFL++ rejected shmem fuzz — fall back */
			use_shmem = 0;
		}
	} else {
		/* No shmem available — legacy hello (no options) */
		hello = 0;
		if (write(FORKSRV_FD + 1, &hello, 4) != 4)
			die("write hello to FORKSRV_FD+1");
	}

	if (use_shmem)
		fprintf(stderr, "afl-phantom: shmem fuzz mode active "
			"(zero-copy testcase delivery)\n");
	else
		fprintf(stderr, "afl-phantom: file-based testcase delivery "
			"(slower)\n");

	for (;;) {
		/* Block until AFL++ sends the "run" command */
		if (read(FORKSRV_FD, &cmd, 4) != 4)
			break;  /* AFL++ closed the pipe — normal exit */

		/* Write fake child PID */
		if (write(FORKSRV_FD + 1, &fake_pid, 4) != 4)
			break;

		if (use_shmem) {
			/*
			 * Shmem fuzz: testcase is already in shared memory.
			 * Layout: [u32 length][u8 data[...]]
			 * AFL++ wrote it before sending the "go" signal.
			 */
			uint32_t tc_len;
			memcpy(&tc_len, afl_shmem_fuzz, sizeof(tc_len));
			if (tc_len > AFL_MAP_SIZE)
				tc_len = AFL_MAP_SIZE;
			afl_status = run_one_iteration(
				afl_shmem_fuzz + sizeof(uint32_t), tc_len);
		} else {
			/*
			 * File-based: re-read stdin (.cur_input) each iter.
			 */
			uint8_t stdin_buf[4096];
			ssize_t stdin_len;

			lseek(STDIN_FILENO, 0, SEEK_SET);
			stdin_len = read(STDIN_FILENO, stdin_buf,
					 sizeof(stdin_buf));
			if (stdin_len > 0)
				afl_status = run_one_iteration(
					stdin_buf, (uint32_t)stdin_len);
			else
				afl_status = run_one_iteration(stdin_buf, 0);
		}

		/*
		 * Write waitpid-style status.
		 * Normal: status = 0.  Crash: status = signal number.
		 */
		uint32_t afl_result;
		if (afl_status == AFL_STATUS_OK)
			afl_result = 0;
		else
			afl_result = (uint32_t)(uint8_t)afl_status;

		if (write(FORKSRV_FD + 1, &afl_result, 4) != 4)
			break;
	}
}

/* ------------------------------------------------------------------
 * Multi-core helpers
 * ------------------------------------------------------------------ */

/*
 * open_core - open /dev/phantom for a single core, create VM, mmap regions.
 *
 * Each core gets an independent fd so that the kernel can track per-instance
 * state separately.  pinned_cpu=core_id binds the VM exit thread.
 */
static int open_core(struct core_state *cs)
{
	uint32_t ver;
	struct phantom_create_args args;

	cs->fd = open("/dev/phantom", O_RDWR);
	if (cs->fd < 0) {
		perror("open /dev/phantom (core)");
		return -1;
	}

	if (phantom_get_version(cs->fd, &ver) < 0) {
		perror("PHANTOM_IOCTL_GET_VERSION (core)");
		close(cs->fd);
		cs->fd = -1;
		return -1;
	}

	memset(&args, 0, sizeof(args));
	args.pinned_cpu    = (uint32_t)cs->core_id;
	args.cow_pool_pages = 0;
	args.topa_size_mb  = 0;
	args.guest_mem_mb  = 0;

	if (phantom_create_vm(cs->fd, &args) < 0) {
		fprintf(stderr, "afl-phantom: CREATE_VM(core=%d) failed: %s\n",
			cs->core_id, strerror(errno));
		close(cs->fd);
		cs->fd = -1;
		return -1;
	}

	cs->payload_map = mmap(NULL, AFL_MAP_SIZE,
			       PROT_READ | PROT_WRITE,
			       MAP_SHARED, cs->fd, PHANTOM_MMAP_PAYLOAD);
	if (cs->payload_map == MAP_FAILED) {
		perror("mmap payload (core)");
		close(cs->fd);
		cs->fd = -1;
		return -1;
	}

	cs->bitmap_map = mmap(NULL, AFL_MAP_SIZE,
			      PROT_READ,
			      MAP_SHARED, cs->fd, PHANTOM_MMAP_BITMAP);
	if (cs->bitmap_map == MAP_FAILED) {
		perror("mmap bitmap (core)");
		munmap(cs->payload_map, AFL_MAP_SIZE);
		close(cs->fd);
		cs->fd = -1;
		return -1;
	}

	return 0;
}

/*
 * thread_worker - pthreads entry point for one core in multi-core test mode.
 */
static void *thread_worker(void *arg)
{
	struct core_state *cs = (struct core_state *)arg;
	struct timespec t_start, t_end;
	uint8_t *payload;
	uint32_t i;
	double elapsed_s;

	/* Bootstrap: run built-in kAFL harness guest to ACQUIRE point */
	{
		struct phantom_run_args rg;
		memset(&rg, 0, sizeof(rg));
		rg.cpu     = (uint32_t)cs->core_id;
		rg.reserved = 8;
		if (ioctl(cs->fd, PHANTOM_IOCTL_RUN_GUEST, &rg) < 0) {
			fprintf(stderr,
				"afl-phantom: core %d: RUN_GUEST failed: %s\n",
				cs->core_id, strerror(errno));
		}
	}

	payload = calloc(1, AFL_MAP_SIZE);
	if (!payload)
		return NULL;

	clock_gettime(CLOCK_MONOTONIC, &t_start);

	for (i = 0; i < cs->iterations; i++) {
		struct phantom_run_args2 iter;

		memset(&iter, 0, sizeof(iter));
		iter.payload_ptr  = (uint64_t)(uintptr_t)payload;
		iter.payload_size = 64;
		iter.timeout_ms   = cs->timeout_ms;

		if (phantom_run_iteration(cs->fd, &iter) < 0) {
			cs->other++;
			continue;
		}

		switch (iter.result) {
		case PHANTOM_RESULT_OK:       cs->ok++;          break;
		case PHANTOM_RESULT_CRASH:    cs->crash++;       break;
		case PHANTOM_RESULT_TIMEOUT:  cs->timeout_cnt++; break;
		case PHANTOM_RESULT_KASAN:    cs->kasan++;       break;
		case PHANTOM_RESULT_PANIC:    cs->crash++;       break;
		default:                      cs->other++;       break;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &t_end);
	elapsed_s = (t_end.tv_sec  - t_start.tv_sec) +
		    (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
	cs->exec_per_sec = cs->iterations / elapsed_s;

	free(payload);
	return NULL;
}

/*
 * run_multicore_test - run N threads in parallel (one per core).
 *
 * Called from standalone --test mode when -j N > 1.
 */
static void run_multicore_test(uint32_t iterations, uint32_t timeout_ms)
{
	pthread_t threads[PHANTOM_MAX_CORES];
	uint64_t total_ok = 0, total_crash = 0, total_timeout = 0;
	uint64_t total_kasan = 0, total_other = 0;
	double total_exec_sec = 0.0;
	int i;

	for (i = 0; i < g_num_cores; i++) {
		g_cores[i].iterations = iterations / g_num_cores;
		g_cores[i].timeout_ms = timeout_ms;
		g_cores[i].ok = g_cores[i].crash = 0;
		g_cores[i].timeout_cnt = g_cores[i].kasan = 0;
		g_cores[i].other = 0;
	}

	for (i = 0; i < g_num_cores; i++) {
		if (pthread_create(&threads[i], NULL, thread_worker,
				   &g_cores[i]) != 0) {
			fprintf(stderr, "afl-phantom: pthread_create core %d: %s\n",
				i, strerror(errno));
		}
	}

	for (i = 0; i < g_num_cores; i++)
		pthread_join(threads[i], NULL);

	fprintf(stderr, "afl-phantom: multi-core results:\n");
	for (i = 0; i < g_num_cores; i++) {
		fprintf(stderr,
			"  core %d: %.0f exec/sec | ok=%lu crash=%lu "
			"timeout=%lu kasan=%lu other=%lu\n",
			g_cores[i].core_id,
			g_cores[i].exec_per_sec,
			(unsigned long)g_cores[i].ok,
			(unsigned long)g_cores[i].crash,
			(unsigned long)g_cores[i].timeout_cnt,
			(unsigned long)g_cores[i].kasan,
			(unsigned long)g_cores[i].other);
		total_ok      += g_cores[i].ok;
		total_crash   += g_cores[i].crash;
		total_timeout += g_cores[i].timeout_cnt;
		total_kasan   += g_cores[i].kasan;
		total_other   += g_cores[i].other;
		total_exec_sec += g_cores[i].exec_per_sec;
	}

	fprintf(stderr,
		"afl-phantom: aggregate: %.0f exec/sec | ok=%lu crash=%lu "
		"timeout=%lu kasan=%lu other=%lu\n",
		total_exec_sec,
		(unsigned long)total_ok,
		(unsigned long)total_crash,
		(unsigned long)total_timeout,
		(unsigned long)total_kasan,
		(unsigned long)total_other);

	if (total_ok + total_crash + total_timeout + total_kasan == iterations) {
		fprintf(stderr, "afl-phantom: PASS (%u/%u)\n",
			(uint32_t)(total_ok + total_crash +
				   total_timeout + total_kasan),
			iterations);
		exit(0);
	} else {
		fprintf(stderr, "afl-phantom: FAIL (%lu/%u failed)\n",
			(unsigned long)total_other, iterations);
		exit(1);
	}
}

/* ------------------------------------------------------------------
 * Standalone test mode
 * ------------------------------------------------------------------ */

/*
 * boot_kernel - boot a Linux kernel guest via PHANTOM_IOCTL_BOOT_KERNEL.
 *
 * Reads the bzImage from disk, calls the BOOT_KERNEL ioctl, and waits
 * for the guest harness to initialise (reach HC_ACQUIRE).
 * After this function returns, RUN_ITERATION can be called directly.
 */
static void boot_kernel(const char *bzimage_path, int cpu, int guest_mem_mb,
			int boot_wait_sec)
{
	FILE *f;
	long fsize;
	uint8_t *buf;
	struct phantom_boot_kernel_args args;

	f = fopen(bzimage_path, "rb");
	if (!f)
		die("fopen bzimage");

	fseek(f, 0, SEEK_END);
	fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (fsize <= 0 || fsize > 64 * 1024 * 1024) {
		fprintf(stderr, "afl-phantom: bzImage size %ld invalid\n",
			fsize);
		exit(1);
	}

	buf = malloc(fsize);
	if (!buf)
		die("malloc bzimage");

	if (fread(buf, 1, fsize, f) != (size_t)fsize) {
		fprintf(stderr, "afl-phantom: short read on bzImage\n");
		exit(1);
	}
	fclose(f);

	memset(&args, 0, sizeof(args));
	args.bzimage_uaddr = (uint64_t)(uintptr_t)buf;
	args.bzimage_size  = (uint64_t)fsize;
	args.cpu           = (uint32_t)cpu;
	args.guest_mem_mb  = (uint32_t)guest_mem_mb;

	fprintf(stderr, "afl-phantom: booting %s (%ld bytes) on cpu %d, "
		"%d MB guest RAM\n", bzimage_path, fsize, cpu, guest_mem_mb);

	if (ioctl(phantom_fd, PHANTOM_IOCTL_BOOT_KERNEL, &args) < 0)
		die("PHANTOM_IOCTL_BOOT_KERNEL");

	fprintf(stderr, "afl-phantom: boot OK, waiting %ds for harness...\n",
		boot_wait_sec);
	sleep(boot_wait_sec);

	free(buf);

	fprintf(stderr, "afl-phantom: kernel ready\n");
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n\n"
		"  Without options: run as AFL++ fork-server\n\n"
		"  --test                  Run standalone (no AFL++ pipes)\n"
		"  --bzimage PATH          Boot a Linux kernel guest (Class B)\n"
		"  --boot-wait N           Seconds to wait after boot (default: 15)\n"
		"  --guest-mem N           Guest memory in MB (default: 256)\n"
		"  --cpu N                 Phantom CPU index (default: 0)\n"
		"  --payload-file FILE     Use FILE as fuzz input (default: zero-fill)\n"
		"  --payload-size N        Payload length in bytes (default: 64)\n"
		"  --iterations N          Number of iterations (default: 100)\n"
		"  --timeout-ms N          Per-iteration timeout (default: 1000)\n"
		"  -j N                    Open N phantom fds (cores 0..N-1), "
		"run N threads in --test mode\n",
		prog);
	exit(1);
}

static void run_standalone_test(const char *payload_file,
				uint32_t payload_size,
				uint32_t iterations,
				uint32_t timeout_ms)
{
	uint8_t *payload;
	struct timespec t_start, t_end;
	uint64_t ok = 0, crash = 0, timeout = 0, kasan = 0, other = 0;
	double elapsed_s, exec_per_sec;
	uint32_t i;
	int non_zero_bytes = 0;

	payload = calloc(1, payload_size);
	if (!payload)
		die("calloc payload");

	if (payload_file) {
		FILE *f = fopen(payload_file, "rb");
		if (!f)
			die("fopen payload_file");
		payload_size = (uint32_t)fread(payload, 1, payload_size, f);
		fclose(f);
	}

	fprintf(stderr, "afl-phantom: standalone test mode\n");
	fprintf(stderr, "  payload_size=%u iterations=%u timeout_ms=%u\n",
		payload_size, iterations, timeout_ms);

	/*
	 * Bootstrap: launch the built-in test guest (test_id=8).
	 *
	 * Skip if --bzimage was used — BOOT_KERNEL already ran the guest
	 * to HC_ACQUIRE.  Otherwise, RUN_GUEST(test_id=8) runs the kAFL
	 * ACQUIRE/RELEASE harness.
	 */
	if (!g_bzimage_mode) {
		if (bootstrap_test_guest() < 0) {
			fprintf(stderr, "afl-phantom: bootstrap failed — "
				"iterations will report EINVAL\n");
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &t_start);

	for (i = 0; i < iterations; i++) {
		struct phantom_run_args2 args;

		memset(&args, 0, sizeof(args));
		args.payload_ptr  = (uint64_t)(uintptr_t)payload;
		args.payload_size = payload_size;
		args.timeout_ms   = timeout_ms;

		if (phantom_run_iteration(phantom_fd, &args) < 0) {
			fprintf(stderr, "afl-phantom: iteration %u: "
				"ioctl failed: %s\n", i, strerror(errno));
			other++;
			continue;
		}

		switch (args.result) {
		case PHANTOM_RESULT_OK:       ok++;      break;
		case PHANTOM_RESULT_CRASH:    crash++;   break;
		case PHANTOM_RESULT_TIMEOUT:  timeout++; break;
		case PHANTOM_RESULT_KASAN:    kasan++;   break;
		case PHANTOM_RESULT_PANIC:    crash++;   break;
		default:                      other++;   break;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &t_end);

	elapsed_s = (t_end.tv_sec  - t_start.tv_sec) +
		    (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
	exec_per_sec = iterations / elapsed_s;

	/* Check for non-zero bitmap bytes */
	{
		const uint8_t *bm = (const uint8_t *)bitmap_map;
		for (i = 0; i < AFL_MAP_SIZE; i++) {
			if (bm[i]) {
				non_zero_bytes++;
				break;
			}
		}
	}

	fprintf(stderr,
		"afl-phantom: results: ok=%lu crash=%lu timeout=%lu "
		"kasan=%lu other=%lu\n",
		ok, crash, timeout, kasan, other);
	fprintf(stderr,
		"afl-phantom: elapsed=%.3fs iterations=%u exec/sec=%.0f\n",
		elapsed_s, iterations, exec_per_sec);
	fprintf(stderr,
		"afl-phantom: bitmap non-zero=%s\n",
		non_zero_bytes ? "yes" : "no");

	/* Exit with 0 only if all iterations completed (ok or expected results) */
	if (ok + crash + timeout + kasan == iterations) {
		fprintf(stderr, "afl-phantom: PASS (%u/%u)\n",
			(uint32_t)(ok + crash + timeout + kasan), iterations);
		exit(0);
	} else {
		fprintf(stderr, "afl-phantom: FAIL (%lu/%u failed)\n",
			other, iterations);
		exit(1);
	}
}

/* ------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
	int test_mode    = 0;
	int num_cores    = 0;  /* 0 = single-core (legacy path) */
	const char *payload_file = NULL;
	const char *bzimage_path = NULL;
	int boot_wait    = 15;
	int guest_mem_mb = 256;
	int cpu_id       = 0;
	uint32_t payload_size    = 64;
	uint32_t iterations      = 100;
	uint32_t timeout_ms      = 1000;

	static const struct option longopts[] = {
		{ "test",         no_argument,       NULL, 't' },
		{ "bzimage",      required_argument, NULL, 'b' },
		{ "boot-wait",    required_argument, NULL, 'w' },
		{ "guest-mem",    required_argument, NULL, 'm' },
		{ "cpu",          required_argument, NULL, 'c' },
		{ "payload-file", required_argument, NULL, 'f' },
		{ "payload-size", required_argument, NULL, 's' },
		{ "iterations",   required_argument, NULL, 'n' },
		{ "timeout-ms",   required_argument, NULL, 'd' },
		{ "help",         no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "tb:w:m:c:j:f:s:n:d:h",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 't': test_mode = 1;               break;
		case 'b': bzimage_path = optarg;       break;
		case 'w': boot_wait = atoi(optarg);    break;
		case 'm': guest_mem_mb = atoi(optarg); break;
		case 'c': cpu_id = atoi(optarg);       break;
		case 'j': num_cores = atoi(optarg);    break;
		case 'f': payload_file = optarg;       break;
		case 's': payload_size = atoi(optarg); break;
		case 'n': iterations   = atoi(optarg); break;
		case 'd': timeout_ms   = atoi(optarg); break;
		case 'h': /* fall-through */
		default:  usage(argv[0]);
		}
	}

	if (num_cores < 0 || num_cores > PHANTOM_MAX_CORES) {
		fprintf(stderr, "afl-phantom: -j must be 1..%d\n",
			PHANTOM_MAX_CORES);
		exit(1);
	}

	/*
	 * Multi-core mode (-j N > 1): open N independent fds, one per core.
	 * In AFL++ fork-server mode only the first fd is used for the
	 * fork-server loop.  Full multi-instance AFL++ is handled externally
	 * via phantom-multi.sh.
	 */
	if (num_cores > 1 && test_mode) {
		int i;

		g_num_cores = num_cores;
		for (i = 0; i < num_cores; i++) {
			g_cores[i].core_id = i;
			if (open_core(&g_cores[i]) < 0) {
				fprintf(stderr,
					"afl-phantom: failed to open core %d\n",
					i);
				exit(1);
			}
		}
		run_multicore_test(iterations, timeout_ms);
		/* run_multicore_test calls exit() */
	}

	/* Single-core path (default) */
	open_phantom();

	if (bzimage_path) {
		/*
		 * Class B (Linux kernel guest): boot bzImage, wait for
		 * harness to reach HC_ACQUIRE.  No create_vm/bootstrap
		 * needed — BOOT_KERNEL handles everything.
		 */
		g_bzimage_mode = 1;
		boot_kernel(bzimage_path, cpu_id, guest_mem_mb, boot_wait);

		/*
		 * mmap payload region so fork-server fallback can read
		 * from shared memory.  PHANTOM_MMAP_BITMAP may not have
		 * a real coverage bitmap yet (stub for now).
		 */
		payload_map = mmap(NULL, AFL_MAP_SIZE,
				   PROT_READ | PROT_WRITE,
				   MAP_SHARED,
				   phantom_fd,
				   PHANTOM_MMAP_PAYLOAD);
		if (payload_map == MAP_FAILED)
			payload_map = NULL;  /* non-fatal for bzimage mode */

		bitmap_map = mmap(NULL, AFL_MAP_SIZE,
				  PROT_READ,
				  MAP_SHARED,
				  phantom_fd,
				  PHANTOM_MMAP_BITMAP);
		if (bitmap_map == MAP_FAILED)
			bitmap_map = NULL;
	} else {
		create_vm();
		setup_mmap();
	}

	if (test_mode) {
		run_standalone_test(payload_file, payload_size,
				    iterations, timeout_ms);
		/* run_standalone_test calls exit() */
	}

	/* AFL++ fork-server mode */
	if (setup_afl_shm() < 0) {
		fprintf(stderr, "afl-phantom: __AFL_SHM_ID not set, "
			"running standalone test (100 iterations)\n");
		if (!bzimage_path)
			take_snapshot();
		run_standalone_test(NULL, 64, 100, 1000);
	}

	if (!bzimage_path)
		take_snapshot();
	run_forkserver();

	/* Cleanup (reached only when AFL++ closes the pipe) */
	phantom_destroy_vm(phantom_fd);
	munmap(bitmap_map, AFL_MAP_SIZE);
	munmap(payload_map, AFL_MAP_SIZE);
	close(phantom_fd);

	return 0;
}
