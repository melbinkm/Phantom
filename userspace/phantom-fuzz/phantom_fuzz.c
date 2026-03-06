// SPDX-License-Identifier: GPL-2.0-only
/*
 * phantom_fuzz.c — In-process coverage-guided fuzzer for Phantom
 *
 * Eliminates AFL++ fork-server overhead by running mutations, coverage
 * tracking, and Phantom ioctls in a single tight loop.  Reads the
 * Intel PT coverage bitmap directly from Phantom's mmap'd region.
 *
 * Expected throughput: 30,000–80,000 exec/s (vs ~400 with AFL++).
 *
 * Usage:
 *   ./phantom-fuzz --bzimage /path/to/bzImage --seeds /path/to/corpus \
 *       --duration 300 --output /tmp/findings
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>
#include <getopt.h>
#include <linux/types.h>

#include "../../kernel/interface.h"

/* ------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------ */

#define MAP_SIZE		(64 * 1024)	/* 64KB coverage bitmap  */
#define MAX_PAYLOAD		(64 * 1024)	/* max fuzz input size   */
#define MAX_CORPUS		4096		/* max corpus entries    */
#define MAX_CRASHES		1024		/* max saved crashes     */
#define CALIBRATE_RUNS		8		/* runs for calibration  */

/* Iteration result codes (mirror of PHANTOM_RESULT_*) */
#define RESULT_OK		0
#define RESULT_CRASH		1
#define RESULT_TIMEOUT		2
#define RESULT_KASAN		3
#define RESULT_PANIC		4

/* ------------------------------------------------------------------
 * Corpus entry
 * ------------------------------------------------------------------ */

struct corpus_entry {
	uint8_t *data;
	uint32_t len;
	uint32_t exec_count;
	uint32_t new_bits;	/* new bits found when this entry was added */
	uint8_t  favored;
};

/* ------------------------------------------------------------------
 * Global state
 * ------------------------------------------------------------------ */

static int   phantom_fd   = -1;
static const uint8_t *bitmap_mmap = NULL;	/* PHANTOM_MMAP_BITMAP (RO) */

/* Coverage tracking */
static uint8_t virgin_bits[MAP_SIZE];	/* bits never seen = 0xFF  */
static uint64_t total_edges = 0;

/* Corpus */
static struct corpus_entry corpus[MAX_CORPUS];
static int corpus_count = 0;

/* Mutation buffer */
static uint8_t mutbuf[MAX_PAYLOAD];

/* Stats */
static uint64_t total_execs   = 0;
static uint64_t total_crashes  = 0;
static uint64_t total_timeouts = 0;
static uint64_t total_new_cov  = 0;
static uint64_t last_new_cov_exec = 0;

/* RNG state (xorshift64) */
static uint64_t rng_state;

/* ------------------------------------------------------------------
 * Fast RNG (xorshift64)
 * ------------------------------------------------------------------ */

static inline uint64_t rng_next(void)
{
	uint64_t x = rng_state;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	rng_state = x;
	return x;
}

static inline uint32_t rng_below(uint32_t limit)
{
	return (uint32_t)(rng_next() % limit);
}

/* ------------------------------------------------------------------
 * Coverage bitmap operations
 * ------------------------------------------------------------------ */

/*
 * classify_counts - collapse hit counts into AFL-style buckets.
 *
 * Transforms raw edge hit counts into power-of-2 buckets:
 *   1→1, 2→2, 3→4, 4-7→8, 8-15→16, 16-31→32, 32-127→64, 128+→128
 */
static const uint8_t count_class[256] = {
	[0] = 0,
	[1] = 1,
	[2] = 2,
	[3] = 4,
	[4 ... 7] = 8,
	[8 ... 15] = 16,
	[16 ... 31] = 32,
	[32 ... 127] = 64,
	[128 ... 255] = 128,
};

static void classify_bitmap(uint8_t *dst, const uint8_t *src)
{
	for (int i = 0; i < MAP_SIZE; i++)
		dst[i] = count_class[src[i]];
}

/*
 * has_new_bits - check if the classified bitmap has new coverage.
 *
 * Returns the number of new bytes (edges or count transitions) found.
 * Updates virgin_bits to mark them as seen.
 */
static uint32_t has_new_bits(const uint8_t *classified)
{
	uint32_t new_bits = 0;
	const uint64_t *current = (const uint64_t *)classified;
	uint64_t *virgin = (uint64_t *)virgin_bits;

	for (int i = 0; i < MAP_SIZE / 8; i++) {
		if (current[i] && (current[i] & virgin[i])) {
			/* Found new bits — update virgin and count */
			uint64_t diff = current[i] & virgin[i];
			virgin[i] &= ~current[i];

			/* Count new bytes */
			while (diff) {
				if (diff & 0xFF) new_bits++;
				diff >>= 8;
			}
		}
	}

	return new_bits;
}

/*
 * count_total_edges - count non-zero bytes in inverse of virgin map.
 */
static uint64_t count_total_edges(void)
{
	uint64_t count = 0;
	for (int i = 0; i < MAP_SIZE; i++)
		if (virgin_bits[i] != 0xFF)
			count++;
	return count;
}

/* ------------------------------------------------------------------
 * nfnetlink dictionary tokens for structure-aware mutation
 * ------------------------------------------------------------------ */

static const uint8_t nft_dict_data[] = {
	/* NFT_MSG_NEWTABLE: (NFNL_SUBSYS_NFTABLES<<8)|0 */
	0x00, 0x0a, 0x00, 0x00,
	/* NFT_MSG_GETTABLE */
	0x01, 0x0a, 0x00, 0x00,
	/* NFT_MSG_DELTABLE */
	0x02, 0x0a, 0x00, 0x00,
	/* NFT_MSG_NEWCHAIN */
	0x03, 0x0a, 0x00, 0x00,
	/* NFT_MSG_NEWRULE */
	0x06, 0x0a, 0x00, 0x00,
	/* NFT_MSG_NEWSET */
	0x09, 0x0a, 0x00, 0x00,
	/* NFT_MSG_NEWSETELEM */
	0x0c, 0x0a, 0x00, 0x00,
	/* NFTA_TABLE_NAME (NLA u16 LE) */
	0x01, 0x00,
	/* NFTA_TABLE_FLAGS */
	0x02, 0x00,
	/* NFTA_CHAIN_TABLE */
	0x03, 0x00,
	/* NF_INET_PRE_ROUTING */
	0x00, 0x00, 0x00, 0x00,
	/* NF_INET_LOCAL_IN */
	0x01, 0x00, 0x00, 0x00,
	/* NF_INET_POST_ROUTING */
	0x04, 0x00, 0x00, 0x00,
	/* AF_INET */
	0x02,
	/* AF_INET6 */
	0x0a,
	/* NFPROTO_INET */
	0x01,
};

/* Dict entry: offset into nft_dict_data + length */
struct dict_entry {
	uint8_t off;
	uint8_t len;
};

static const struct dict_entry nft_dict[] = {
	{ 0,  4}, { 4,  4}, { 8,  4}, {12, 4}, {16, 4}, {20, 4}, {24, 4},
	{28, 2}, {30, 2}, {32, 2},
	{34, 4}, {38, 4}, {42, 4},
	{46, 1}, {47, 1}, {48, 1},
};
#define NFT_DICT_COUNT	(sizeof(nft_dict) / sizeof(nft_dict[0]))

/* ------------------------------------------------------------------
 * Crash deduplication via coverage bitmap hash
 * ------------------------------------------------------------------ */

static uint32_t crash_hashes[MAX_CRASHES];
static int crash_hash_count = 0;

static uint32_t bitmap_hash(const uint8_t *bmap)
{
	const uint32_t *p = (const uint32_t *)bmap;
	uint32_t h = 0;
	for (int i = 0; i < MAP_SIZE / 4; i++)
		h ^= p[i];
	return h;
}

static int crash_hash_seen(uint32_t h)
{
	for (int i = 0; i < crash_hash_count; i++)
		if (crash_hashes[i] == h)
			return 1;
	return 0;
}

static void crash_hash_add(uint32_t h)
{
	if (crash_hash_count < MAX_CRASHES)
		crash_hashes[crash_hash_count++] = h;
}

/* ------------------------------------------------------------------
 * Mutations (AFL-style havoc)
 * ------------------------------------------------------------------ */

static uint32_t mutate_havoc(const uint8_t *src, uint32_t src_len,
			     uint8_t *dst, uint32_t max_len)
{
	uint32_t len = src_len;

	if (len == 0) {
		dst[0] = (uint8_t)rng_next();
		return 1;
	}

	if (len > max_len)
		len = max_len;
	memcpy(dst, src, len);

	/* Number of stacked mutations: 1–16 */
	uint32_t n_muts = 1 + rng_below(16);

	for (uint32_t m = 0; m < n_muts; m++) {
		uint32_t op = rng_below(13);

		switch (op) {
		case 0: /* flip random bit */
			if (len > 0) {
				uint32_t pos = rng_below(len);
				dst[pos] ^= (1 << rng_below(8));
			}
			break;

		case 1: /* set random byte to interesting value */
			if (len > 0) {
				static const uint8_t interesting8[] = {
					0, 1, 16, 32, 64, 100, 127, 128,
					255, 0xFF, 0x7F, 0x80
				};
				uint32_t pos = rng_below(len);
				dst[pos] = interesting8[
					rng_below(sizeof(interesting8))];
			}
			break;

		case 2: /* random byte */
			if (len > 0)
				dst[rng_below(len)] = (uint8_t)rng_next();
			break;

		case 3: /* delete bytes */
			if (len > 4) {
				uint32_t del_from = rng_below(len - 1);
				uint32_t del_len = 1 + rng_below(
					(len - del_from < 16) ?
					len - del_from : 16);
				memmove(dst + del_from,
					dst + del_from + del_len,
					len - del_from - del_len);
				len -= del_len;
			}
			break;

		case 4: /* insert random bytes */
			if (len < max_len - 16) {
				uint32_t ins_at = rng_below(len + 1);
				uint32_t ins_len = 1 + rng_below(16);
				if (len + ins_len > max_len)
					ins_len = max_len - len;
				memmove(dst + ins_at + ins_len,
					dst + ins_at, len - ins_at);
				for (uint32_t i = 0; i < ins_len; i++)
					dst[ins_at + i] = (uint8_t)rng_next();
				len += ins_len;
			}
			break;

		case 5: /* overwrite with random chunk */
			if (len > 4) {
				uint32_t cpy_len = 1 + rng_below(
					(len < 16) ? len : 16);
				uint32_t cpy_to = rng_below(len - cpy_len + 1);
				for (uint32_t i = 0; i < cpy_len; i++)
					dst[cpy_to + i] = (uint8_t)rng_next();
			}
			break;

		case 6: /* set 16-bit interesting value */
			if (len >= 2) {
				static const uint16_t interesting16[] = {
					0, 128, 255, 256, 512, 1000,
					1024, 4096, 32767, 32768, 65535
				};
				uint32_t pos = rng_below(len - 1);
				uint16_t val = interesting16[
					rng_below(sizeof(interesting16) /
						  sizeof(interesting16[0]))];
				memcpy(dst + pos, &val, 2);
			}
			break;

		case 7: /* set 32-bit interesting value */
			if (len >= 4) {
				static const uint32_t interesting32[] = {
					0, 1, 32768, 65535, 65536,
					100663045, 2147483647, 4294967295U
				};
				uint32_t pos = rng_below(len - 3);
				uint32_t val = interesting32[
					rng_below(sizeof(interesting32) /
						  sizeof(interesting32[0]))];
				memcpy(dst + pos, &val, 4);
			}
			break;

		case 8: /* arithmetic on byte */
			if (len > 0) {
				uint32_t pos = rng_below(len);
				dst[pos] += (uint8_t)(1 + rng_below(35));
			}
			break;

		case 9: /* arithmetic on 16-bit */
			if (len >= 2) {
				uint32_t pos = rng_below(len - 1);
				uint16_t val;
				memcpy(&val, dst + pos, 2);
				val += (uint16_t)(1 + rng_below(35));
				memcpy(dst + pos, &val, 2);
			}
			break;

		case 10: /* splice from another corpus entry */
			if (corpus_count > 1 && len > 4) {
				int other = rng_below(corpus_count);
				struct corpus_entry *ce = &corpus[other];
				if (ce->len > 4) {
					uint32_t split = 1 + rng_below(len - 1);
					uint32_t other_split =
						rng_below(ce->len);
					uint32_t cpy = ce->len - other_split;
					if (split + cpy > max_len)
						cpy = max_len - split;
					memcpy(dst + split,
					       ce->data + other_split, cpy);
					len = split + cpy;
				}
			}
			break;

		case 11: /* clone bytes from same input */
			if (len > 8) {
				uint32_t from = rng_below(len);
				uint32_t to = rng_below(len);
				uint32_t cpy = 1 + rng_below(
					((len - from) < 16) ?
					(len - from) : 16);
				if (to + cpy <= max_len) {
					memmove(dst + to, dst + from, cpy);
				}
			}
			break;

		case 12: /* insert dictionary token */
			if (len < max_len - 4) {
				uint32_t di = rng_below(NFT_DICT_COUNT);
				const struct dict_entry *de = &nft_dict[di];
				uint32_t ins_at = rng_below(len + 1);
				if (len + de->len <= max_len) {
					memmove(dst + ins_at + de->len,
						dst + ins_at,
						len - ins_at);
					memcpy(dst + ins_at,
					       nft_dict_data + de->off,
					       de->len);
					len += de->len;
				}
			}
			break;
		}
	}

	return len;
}

/* ------------------------------------------------------------------
 * Phantom interaction
 * ------------------------------------------------------------------ */

static int run_one(const uint8_t *payload, uint32_t len, uint32_t timeout_ms)
{
	struct phantom_run_args2 args;

	if (len > MAX_PAYLOAD)
		len = MAX_PAYLOAD;

	memset(&args, 0, sizeof(args));
	args.payload_ptr  = (uint64_t)(uintptr_t)payload;
	args.payload_size = len;
	args.timeout_ms   = timeout_ms;

	if (ioctl(phantom_fd, PHANTOM_RUN_ITERATION, &args) < 0)
		return -1;

	return (int)args.result;
}

/* ------------------------------------------------------------------
 * Corpus management
 * ------------------------------------------------------------------ */

static int add_to_corpus(const uint8_t *data, uint32_t len, uint32_t new_bits)
{
	if (corpus_count >= MAX_CORPUS)
		return -1;

	struct corpus_entry *ce = &corpus[corpus_count];
	ce->data = malloc(len);
	if (!ce->data)
		return -1;
	memcpy(ce->data, data, len);
	ce->len = len;
	ce->exec_count = 0;
	ce->new_bits = new_bits;
	ce->favored = (new_bits > 0);
	corpus_count++;
	return 0;
}

static int load_seeds(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *ent;
	char path[1024];
	int count = 0;

	if (!d) {
		perror("opendir seeds");
		return -1;
	}

	while ((ent = readdir(d)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);

		struct stat st;
		if (stat(path, &st) < 0 || !S_ISREG(st.st_mode))
			continue;
		if (st.st_size == 0 || st.st_size > MAX_PAYLOAD)
			continue;

		FILE *f = fopen(path, "rb");
		if (!f)
			continue;

		uint8_t *buf = malloc(st.st_size);
		if (!buf) {
			fclose(f);
			continue;
		}
		size_t n = fread(buf, 1, st.st_size, f);
		fclose(f);

		if (n > 0) {
			struct corpus_entry *ce = &corpus[corpus_count];
			ce->data = buf;
			ce->len = (uint32_t)n;
			ce->exec_count = 0;
			ce->new_bits = 0;
			ce->favored = 1;
			corpus_count++;
			count++;
		} else {
			free(buf);
		}

		if (corpus_count >= MAX_CORPUS)
			break;
	}

	closedir(d);
	return count;
}

static int save_crash(const char *outdir, const uint8_t *data, uint32_t len,
		      int result, uint64_t exec_id, uint32_t hash)
{
	char path[1024];
	const char *type = (result == RESULT_CRASH) ? "crash" :
			   (result == RESULT_KASAN) ? "kasan" :
			   (result == RESULT_PANIC) ? "panic" : "other";

	snprintf(path, sizeof(path), "%s/%s_%08x_%06lu.bin", outdir, type,
		 hash, (unsigned long)exec_id);

	FILE *f = fopen(path, "wb");
	if (!f)
		return -1;
	fwrite(data, 1, len, f);
	fclose(f);
	return 0;
}

/* ------------------------------------------------------------------
 * Main fuzzing loop
 * ------------------------------------------------------------------ */

static void fuzz_loop(int duration_sec, uint32_t timeout_ms,
		      const char *outdir)
{
	struct timespec t_start, t_now, t_last_print;
	uint8_t classified[MAP_SIZE];

	clock_gettime(CLOCK_MONOTONIC, &t_start);
	t_last_print = t_start;

	/* Calibrate seeds: run each seed to populate initial coverage */
	fprintf(stderr, "Calibrating %d seeds...\n", corpus_count);
	for (int i = 0; i < corpus_count; i++) {
		struct corpus_entry *ce = &corpus[i];

		for (int r = 0; r < CALIBRATE_RUNS; r++) {
			run_one(ce->data, ce->len, timeout_ms);
			total_execs++;

			classify_bitmap(classified, bitmap_mmap);
			uint32_t nb = has_new_bits(classified);
			if (nb > 0) {
				ce->new_bits += nb;
				total_new_cov++;
				last_new_cov_exec = total_execs;
			}
		}
	}

	total_edges = count_total_edges();
	fprintf(stderr, "Calibration done: %lu edges from %d seeds\n",
		(unsigned long)total_edges, corpus_count);

	/* Main fuzzing loop */
	for (;;) {
		/* Time check */
		clock_gettime(CLOCK_MONOTONIC, &t_now);
		double elapsed = (t_now.tv_sec - t_start.tv_sec) +
				 (t_now.tv_nsec - t_start.tv_nsec) / 1e9;

		if (duration_sec > 0 && elapsed >= duration_sec)
			break;

		/* Status line every 5 seconds */
		double since_print = (t_now.tv_sec - t_last_print.tv_sec) +
				     (t_now.tv_nsec - t_last_print.tv_nsec) / 1e9;
		if (since_print >= 5.0) {
			double exec_s = total_execs / elapsed;
			total_edges = count_total_edges();
			fprintf(stderr,
				"\r[%5.0fs] exec/s: %.0f | total: %lu | "
				"corpus: %d | edges: %lu | "
				"crashes: %lu | new_cov: %lu   ",
				elapsed, exec_s,
				(unsigned long)total_execs,
				corpus_count,
				(unsigned long)total_edges,
				(unsigned long)total_crashes,
				(unsigned long)total_new_cov);
			t_last_print = t_now;
		}

		/* Pick a corpus entry (favor entries with new coverage) */
		int idx;
		if (rng_below(100) < 75 && corpus_count > 0) {
			/* 75%: pick a favored entry */
			int tries = 10;
			do {
				idx = rng_below(corpus_count);
			} while (!corpus[idx].favored && --tries > 0);
		} else {
			idx = rng_below(corpus_count);
		}

		struct corpus_entry *ce = &corpus[idx];
		ce->exec_count++;

		/* Mutate */
		uint32_t mutlen = mutate_havoc(ce->data, ce->len,
					       mutbuf, MAX_PAYLOAD);

		/* Execute */
		int result = run_one(mutbuf, mutlen, timeout_ms);
		total_execs++;

		if (result < 0) {
			fprintf(stderr, "\nioctl failed: %s\n",
				strerror(errno));
			break;
		}

		/* Check coverage */
		classify_bitmap(classified, bitmap_mmap);
		uint32_t new_bits = has_new_bits(classified);

		if (new_bits > 0) {
			/* New coverage! Add to corpus */
			total_new_cov++;
			last_new_cov_exec = total_execs;
			add_to_corpus(mutbuf, mutlen, new_bits);
		}

		/* Handle crashes (deduplicate by coverage bitmap hash) */
		if (result == RESULT_CRASH || result == RESULT_KASAN ||
		    result == RESULT_PANIC) {
			total_crashes++;
			if (outdir) {
				uint32_t ch = bitmap_hash(bitmap_mmap);
				if (!crash_hash_seen(ch)) {
					crash_hash_add(ch);
					save_crash(outdir, mutbuf, mutlen,
						   result, total_execs, ch);
				}
			}
		}

		if (result == RESULT_TIMEOUT)
			total_timeouts++;
	}

	/* Final stats */
	clock_gettime(CLOCK_MONOTONIC, &t_now);
	double elapsed = (t_now.tv_sec - t_start.tv_sec) +
			 (t_now.tv_nsec - t_start.tv_nsec) / 1e9;
	double exec_s = total_execs / elapsed;
	total_edges = count_total_edges();

	fprintf(stderr, "\n\n=== phantom-fuzz results ===\n");
	fprintf(stderr, "  duration:   %.1fs\n", elapsed);
	fprintf(stderr, "  execs:      %lu\n", (unsigned long)total_execs);
	fprintf(stderr, "  exec/s:     %.0f\n", exec_s);
	fprintf(stderr, "  corpus:     %d entries\n", corpus_count);
	fprintf(stderr, "  edges:      %lu\n", (unsigned long)total_edges);
	fprintf(stderr, "  new_cov:    %lu\n", (unsigned long)total_new_cov);
	fprintf(stderr, "  crashes:    %lu (unique: %d)\n",
		(unsigned long)total_crashes, crash_hash_count);
	fprintf(stderr, "  timeouts:   %lu\n", (unsigned long)total_timeouts);
}

/* ------------------------------------------------------------------
 * Setup and main
 * ------------------------------------------------------------------ */

static void die(const char *msg)
{
	perror(msg);
	exit(1);
}

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
		fprintf(stderr, "phantom-fuzz: invalid bzImage size\n");
		exit(1);
	}

	buf = malloc(fsize);
	if (!buf)
		die("malloc");
	if ((ssize_t)fread(buf, 1, fsize, f) != fsize)
		die("fread bzimage");
	fclose(f);

	memset(&args, 0, sizeof(args));
	args.bzimage_uaddr = (uint64_t)(uintptr_t)buf;
	args.bzimage_size  = (uint64_t)fsize;
	args.cpu           = (uint32_t)cpu;
	args.guest_mem_mb  = (uint32_t)guest_mem_mb;

	fprintf(stderr, "Booting %s (%ld bytes, cpu=%d, %dMB)...\n",
		bzimage_path, fsize, cpu, guest_mem_mb);

	if (ioctl(phantom_fd, PHANTOM_IOCTL_BOOT_KERNEL, &args) < 0)
		die("PHANTOM_IOCTL_BOOT_KERNEL");

	fprintf(stderr, "Boot OK, waiting %ds for harness...\n", boot_wait_sec);
	sleep(boot_wait_sec);
	free(buf);
}

int main(int argc, char *argv[])
{
	const char *bzimage_path = NULL;
	const char *seeds_dir = NULL;
	const char *output_dir = NULL;
	int duration = 60;
	int boot_wait = 12;
	int guest_mem = 256;
	int cpu_id = 0;
	uint32_t timeout_ms = 1000;

	static const struct option longopts[] = {
		{ "bzimage",   required_argument, NULL, 'b' },
		{ "seeds",     required_argument, NULL, 's' },
		{ "output",    required_argument, NULL, 'o' },
		{ "duration",  required_argument, NULL, 'd' },
		{ "boot-wait", required_argument, NULL, 'w' },
		{ "guest-mem", required_argument, NULL, 'm' },
		{ "cpu",       required_argument, NULL, 'c' },
		{ "timeout",   required_argument, NULL, 't' },
		{ "help",      no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "b:s:o:d:w:m:c:t:h",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'b': bzimage_path = optarg;       break;
		case 's': seeds_dir = optarg;          break;
		case 'o': output_dir = optarg;         break;
		case 'd': duration = atoi(optarg);     break;
		case 'w': boot_wait = atoi(optarg);    break;
		case 'm': guest_mem = atoi(optarg);    break;
		case 'c': cpu_id = atoi(optarg);       break;
		case 't': timeout_ms = atoi(optarg);   break;
		default:
			fprintf(stderr,
				"Usage: %s --bzimage PATH --seeds DIR "
				"[--output DIR] [--duration N]\n",
				argv[0]);
			return 1;
		}
	}

	if (!bzimage_path || !seeds_dir) {
		fprintf(stderr, "Required: --bzimage and --seeds\n");
		return 1;
	}

	/* Seed RNG */
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	rng_state = (uint64_t)ts.tv_nsec ^ (uint64_t)getpid();
	if (rng_state == 0) rng_state = 1;

	/* Init virgin bits */
	memset(virgin_bits, 0xFF, MAP_SIZE);

	/* Open /dev/phantom */
	phantom_fd = open("/dev/phantom", O_RDWR);
	if (phantom_fd < 0)
		die("open /dev/phantom");

	/* Boot kernel */
	boot_kernel(bzimage_path, cpu_id, guest_mem, boot_wait);

	/* mmap bitmap (the coverage data from Intel PT) */
	bitmap_mmap = mmap(NULL, MAP_SIZE, PROT_READ, MAP_SHARED,
			   phantom_fd, PHANTOM_MMAP_BITMAP);
	if (bitmap_mmap == MAP_FAILED)
		die("mmap PHANTOM_MMAP_BITMAP");

	/* Load seeds */
	int n_seeds = load_seeds(seeds_dir);
	if (n_seeds <= 0) {
		fprintf(stderr, "No seeds loaded from %s\n", seeds_dir);
		return 1;
	}
	fprintf(stderr, "Loaded %d seeds\n", n_seeds);

	/* Create output dir for crashes */
	if (output_dir) {
		mkdir(output_dir, 0755);
		fprintf(stderr, "Crashes saved to %s/\n", output_dir);
	}

	/* Run */
	fprintf(stderr, "Starting %ds fuzzing campaign...\n\n", duration);
	fuzz_loop(duration, timeout_ms, output_dir);

	/* Cleanup */
	munmap((void *)bitmap_mmap, MAP_SIZE);
	close(phantom_fd);

	return (total_crashes > 0) ? 1 : 0;
}
