/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * guest/libxml2_harness.c — Phantom guest harness for libxml2 2.9.4 fuzzing.
 *
 * Compiled with musl-gcc as a static non-PIE executable.
 * Loaded at GPA 0x400000 (via PHANTOM_LOAD_TARGET); a tiny trampoline at
 * GUEST_CODE_GPA (0x10000) jumps here.
 *
 * Memory layout (EPT guest RAM: GPA 0x000000–0xFFFFFF, 16MB total):
 *   0x010000  libxml2_trampoline.S (≤ 4KB, jumps to 0x400000)
 *   0x013000  guest PML4 (kernel-managed, do NOT overwrite)
 *   0x400000  this binary (-Ttext=0x400000)
 *   ~0x575000 end of binary (~1.4MB)
 *   0x600000  inject buffer (64KB):
 *               [0..3]   uint32_t payload length
 *               [4..]    XML payload bytes
 *   0x610000  bump-allocator heap (up to ~0xFF0000)
 *
 * Bare guest — no OS.  EFER_SCE is cleared so 'syscall' raises #UD.
 * The hypervisor's #UD exit handler intercepts 'syscall' (0F 05) and
 * implements SYS_mmap/SYS_munmap/SYS_brk/SYS_mprotect/SYS_write via a
 * kernel-side bump allocator (phantom_vmx_cpu_state.guest_heap_ptr).
 * malloc/calloc/realloc/free are also wrapped (--wrap=malloc etc.) so
 * libxml2's allocation never reaches musl's internal brk-based path.
 *
 * Protocol:
 *   1. HC_GET_PAYLOAD(PAYLOAD_GPA) — register payload buffer GPA
 *   2. HC_ACQUIRE(0)               — snapshot; restored each iteration
 *   3. xmlReadMemory() on payload
 *   4. HC_RELEASE(0)               — end of iteration
 */

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Phantom hypercall numbers (kAFL/Nyx ABI)
 * ---------------------------------------------------------------------- */
#define HC_GET_PAYLOAD  0x11a
#define HC_ACQUIRE      0x11c
#define HC_RELEASE      0x11d

/* -------------------------------------------------------------------------
 * Guest memory layout
 * ---------------------------------------------------------------------- */
#define PAYLOAD_GPA     0x600000UL
#define INJECT_TOTAL    65536U          /* == PHANTOM_PAYLOAD_MAX */
#define HEAP_BASE       (PAYLOAD_GPA + INJECT_TOTAL) /* 0x610000 */
#define HEAP_LIMIT      0xFF0000UL

/* -------------------------------------------------------------------------
 * Bump allocator — replaces musl malloc/mmap without any syscalls.
 *
 * Strategy: intercept musl's __mmap / __munmap (used by malloc) and
 * sbrk/brk (used by older allocators) with a simple linear bump
 * allocator.  Freeing is a no-op; the heap pointer resets automatically
 * on each snapshot restore.
 *
 * Alignment: all allocations are rounded up to 16 bytes (sufficient
 * for SIMD types used inside libxml2).
 * ---------------------------------------------------------------------- */
static unsigned long _heap_ptr = HEAP_BASE;

static void *bump_alloc(unsigned long size)
{
	unsigned long aligned_size = (size + 15UL) & ~15UL;
	unsigned long ptr = _heap_ptr;

	if (ptr + aligned_size > HEAP_LIMIT)
		return (void *)0; /* NULL */

	_heap_ptr += aligned_size;
	return (void *)ptr;
}

/*
 * __wrap___mmap / __wrap___munmap
 *
 * musl's malloc calls __mmap(NULL, size, PROT_READ|PROT_WRITE,
 *   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) for large allocations and for
 *   the initial heap.  We return memory from our bump allocator instead.
 *
 * The linker flag is -Wl,--wrap=__mmap,--wrap=__munmap
 */
void *__wrap___mmap(void *addr, unsigned long length, int prot, int flags,
		    int fd, long offset)
{
	(void)addr; (void)prot; (void)flags; (void)fd; (void)offset;
	if (length == 0)
		return (void *)(uintptr_t)-1; /* MAP_FAILED */
	return bump_alloc(length);
}

int __wrap___munmap(void *addr, unsigned long length)
{
	(void)addr; (void)length;
	return 0; /* no-op */
}

/* sbrk/brk fallback (some versions of musl malloc may use these) */
void *__wrap_sbrk(long increment)
{
	if (increment == 0)
		return (void *)_heap_ptr;
	return bump_alloc((unsigned long)increment);
}

int __wrap_brk(void *addr)
{
	unsigned long a = (unsigned long)addr;

	if (a < HEAP_BASE || a > HEAP_LIMIT)
		return -1;
	_heap_ptr = a;
	return 0;
}

/* -------------------------------------------------------------------------
 * malloc/free/realloc/calloc wrappers — prevent musl's allocator from
 * ever issuing a raw syscall instruction.
 *
 * musl's internal __malloc_alloc_meta calls brk(0) via __syscall(SYS_brk)
 * directly, bypassing the --wrap=brk shim.  Wrapping malloc/free/realloc/
 * calloc at the libc API level replaces the entire musl allocator path.
 *
 * Strategy: bump allocator for malloc/calloc.  free/realloc are no-ops
 * (snapshot restore reclaims all heap automatically each iteration).
 *
 * Alignment: 16 bytes (sufficient for SIMD types used by libxml2).
 * ---------------------------------------------------------------------- */
/*
 * Prefix-tagged allocations: store the allocation size in the 8 bytes
 * immediately before the returned pointer.  Allows realloc to copy the
 * correct number of bytes.  Overhead: 8 bytes per allocation (acceptable
 * for libxml2's allocation pattern of a few hundred allocs per iteration).
 */
static void *bump_alloc_tagged(unsigned long size)
{
	unsigned long *header;
	void *ptr;

	/* Allocate 8-byte header + requested size, 16-byte aligned */
	ptr = bump_alloc(8 + size);
	if (!ptr)
		return (void *)0;
	header    = (unsigned long *)ptr;
	*header   = size;  /* store size in header */
	return (void *)((unsigned char *)ptr + 8);
}

void *__wrap_malloc(size_t size)
{
	return bump_alloc_tagged((unsigned long)size);
}

void __wrap_free(void *ptr)
{
	(void)ptr; /* no-op: heap is reset by snapshot restore */
}

void *__wrap_realloc(void *ptr, size_t size)
{
	void *newptr;
	unsigned long old_size;

	newptr = bump_alloc_tagged((unsigned long)size);
	if (!newptr)
		return (void *)0;
	if (ptr && (unsigned long)ptr >= HEAP_BASE + 8 &&
	    (unsigned long)ptr < HEAP_LIMIT) {
		/* Read old size from 8-byte header preceding the pointer */
		old_size = *((unsigned long *)((unsigned char *)ptr - 8));
		if (old_size > (unsigned long)size)
			old_size = (unsigned long)size;
		/* Copy old content into new block */
		{
			unsigned char *src = (unsigned char *)ptr;
			unsigned char *dst = (unsigned char *)newptr;
			unsigned long i;
			for (i = 0; i < old_size; i++)
				dst[i] = src[i];
		}
	}
	return newptr;
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
	/*
	 * Bump allocator returns memory from zero-initialised snapshot pages,
	 * so calloc is semantically correct without an explicit memset.
	 */
	return bump_alloc_tagged((unsigned long)nmemb * (unsigned long)size);
}

/* -------------------------------------------------------------------------
 * write() stub: libxml2 error handlers write to stderr.
 * Bare guest has no file descriptors — swallow silently.
 * ---------------------------------------------------------------------- */
long __wrap_write(int fd, const void *buf, unsigned long count)
{
	(void)fd; (void)buf;
	return (long)count;
}

/* -------------------------------------------------------------------------
 * vmcall helper
 * ---------------------------------------------------------------------- */
static void vmcall(uint64_t nr, uint64_t arg)
{
	__asm__ volatile(
		"vmcall"
		: : "a"(nr), "b"(arg)  /* kAFL ABI: RAX=nr, RBX=arg */
		: "memory"
	);
}

/* -------------------------------------------------------------------------
 * Minimal libxml2 API declarations
 * ---------------------------------------------------------------------- */
typedef struct _xmlDoc xmlDoc;
typedef xmlDoc *xmlDocPtr;

extern void      xmlInitParser(void);
extern xmlDocPtr xmlReadMemory(const char *buffer, int size,
			       const char *URL, const char *encoding,
			       int options);
extern void      xmlFreeDoc(xmlDocPtr cur);
extern void      xmlCleanupParser(void);

#define XML_PARSE_NOERROR   0x20
#define XML_PARSE_NOWARNING 0x40
#define XML_PARSE_RECOVER   0x01
#define XML_PARSE_NONET     0x800  /* disable network access (no DNS/HTTP) */
#define XML_PARSE_NODICT    0x200  /* disable string dictionary (reduces alloc) */
#define XML_PARSE_NOENT     0x02   /* substitute entities */

/* -------------------------------------------------------------------------
 * _start — ELF entry point, called by libxml2_trampoline.S
 * ---------------------------------------------------------------------- */
void _start(void)
{
	/* inject buffer: [uint32_t len][XML data ...] */
	volatile uint32_t *len_ptr = (volatile uint32_t *)PAYLOAD_GPA;
	volatile uint8_t  *payload =
		(volatile uint8_t *)(PAYLOAD_GPA + sizeof(uint32_t));
	uint32_t  len;
	xmlDocPtr doc;

	/* Step 1: register payload GPA */
	vmcall(HC_GET_PAYLOAD, PAYLOAD_GPA);

	/*
	 * Step 2: ACQUIRE snapshot.
	 * On restore the heap pointer (_heap_ptr) is reset to the snapshotted
	 * value, so libxml2's allocations are automatically reclaimed.
	 */
	vmcall(HC_ACQUIRE, 0);

	/* Step 3: read payload length */
	len = *len_ptr;
	if (len == 0 || len > INJECT_TOTAL - (uint32_t)sizeof(uint32_t))
		len = 64;

	/* Step 4: parse XML */
	xmlInitParser();
	doc = xmlReadMemory((const char *)payload, (int)len,
			    "fuzz.xml", NULL,
			    XML_PARSE_NOERROR | XML_PARSE_NOWARNING |
			    XML_PARSE_RECOVER | XML_PARSE_NONET);
	if (doc)
		xmlFreeDoc(doc);
	xmlCleanupParser();

	/* Step 5: end of iteration */
	vmcall(HC_RELEASE, 0);

	/* Should not be reached */
	__asm__ volatile("hlt");
	__builtin_unreachable();
}
