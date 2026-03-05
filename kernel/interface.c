// SPDX-License-Identifier: GPL-2.0-only
/*
 * interface.c — /dev/phantom chardev: open, release, ioctl
 *
 * Responsibilities:
 *   - Allocate dynamic device number
 *   - Register character device with the kernel
 *   - Create device class and device node (triggers udev/mdev)
 *   - Dispatch PHANTOM_IOCTL_GET_VERSION
 *   - Dispatch PHANTOM_IOCTL_RUN_GUEST (task 1.2)
 *
 * The RUN_GUEST ioctl:
 *   1. Calls phantom_vmcs_setup() — allocates all pages (process context,
 *      GFP_KERNEL OK).  Idempotent; no-op after first call.
 *   2. Prepares guest memory (binary + data pattern).
 *   3. Resets guest VMCS state for relaunches (not first run).
 *   4. Signals the per-CPU vCPU kernel thread to run the guest.
 *   5. Waits for the vCPU thread to complete.
 *   6. Copies result back to userspace.
 *
 * Why use a dedicated vCPU kernel thread:
 *   smp_call_function_single delivers the callback with local IRQs
 *   disabled.  In a nested KVM environment (L0=KVM, L1=phantom,
 *   L2=guest), after the first VMLAUNCH/VMRESUME cycle KVM's internal
 *   state for the target vCPU does not properly deliver generic IPIs
 *   on subsequent smp_call_function_single calls — causing an infinite
 *   wait.  Task migration via set_cpus_allowed_ptr+schedule() causes
 *   immediate kernel panics in nested VMX context.
 *
 *   A dedicated kernel thread pinned to the target CPU is the correct
 *   production design (used by KVM itself for vCPU execution).  The
 *   thread runs as a normal schedulable task; the scheduler places it
 *   on the pinned CPU without triggering the nested VMX IPI issue.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/mman.h>
#include <linux/version.h>
#include <linux/eventfd.h>
#include <linux/vmalloc.h>

#include "phantom.h"
#include "interface.h"
#include "vmx_core.h"
#include "ept.h"
#include "ept_cow.h"
#include "snapshot.h"
#include "hypercall.h"
#include "debug.h"
#include "compat.h"
#include "pt_config.h"
#include "msr_emul.h"
#include "guest_boot.h"

/* ------------------------------------------------------------------
 * Guest binary 1 (test_id=0): R/W test
 *
 * Reads 10 pages at GPA 0x30000–0x39000 (80 u64 values each page),
 * writes a pattern, re-reads, XORs all u64 values into a checksum,
 * and submits it via VMCALL(1, checksum, 0, 0, 0).
 *
 * 10 pages × 512 u64 values = 5120 u64 values XOR'd.
 *
 * Assembly (64-bit long mode):
 *
 *   ; Phase 1: Write pattern to 10 pages at GPA 0x30000–0x39000
 *   mov  $0x30000, %rbx       ; base GPA
 *   xor  %rcx, %rcx           ; page index = 0
 * .write_loop:
 *   ; Write 512 u64 values to page rcx
 *   mov  %rbx, %rdi           ; page base
 *   xor  %rsi, %rsi           ; word index = 0
 * .write_word:
 *   mov  %rcx, %rax            ; page_idx
 *   shl  $9, %rax              ; × 512
 *   add  %rsi, %rax            ; + word_idx → unique value
 *   mov  %rax, (%rdi,%rsi,8)
 *   inc  %rsi
 *   cmp  $512, %rsi
 *   jl   .write_word
 *   add  $0x1000, %rbx
 *   inc  %rcx
 *   cmp  $10, %rcx
 *   jl   .write_loop
 *
 *   ; Phase 2: XOR all 10×512 values into checksum
 *   mov  $0x30000, %rbx
 *   mov  $5120, %rcx          ; total u64 count
 *   xor  %rdx, %rdx           ; checksum = 0
 * .xor_loop:
 *   sub  $1, %rcx
 *   mov  (%rbx,%rcx,8), %rax
 *   xor  %rax, %rdx
 *   test %rcx, %rcx
 *   jnz  .xor_loop
 *
 *   ; Submit checksum
 *   mov  %rdx, %rbx
 *   mov  $1, %rax
 *   vmcall
 * .halt:
 *   hlt
 *   jmp  .halt
 *
 * Hand-assembled bytes below.  Offsets verified by manual byte count.
 *
 * Byte layout (key labels):
 *   Byte  0: mov $0x30000, %rbx  (10 bytes)
 *   Byte 10: xor %rcx, %rcx      (3 bytes)
 *   Byte 13: .write_loop
 *   Byte 13: mov %rbx, %rdi      (3 bytes)
 *   Byte 16: xor %rsi, %rsi      (3 bytes)
 *   Byte 19: .write_word
 *   Byte 19: mov %rcx, %rax      (3 bytes)
 *   Byte 22: shl $9, %rax        (4 bytes)
 *   Byte 26: add %rsi, %rax      (3 bytes)
 *   Byte 29: mov %rax, (...)     (4 bytes)
 *   Byte 33: inc %rsi            (3 bytes)
 *   Byte 36: cmp $512, %rsi      (7 bytes)
 *   Byte 43: jl .write_word  → next_instr=45, target=19, offset=-26=0xE6
 *   Byte 45: add $0x1000, %rbx   (7 bytes)
 *   Byte 52: inc %rcx            (3 bytes)
 *   Byte 55: cmp $10, %rcx       (4 bytes)
 *   Byte 59: jl .write_loop  → next_instr=61, target=13, offset=-48=0xD0
 * ------------------------------------------------------------------ */
static const u8 phantom_rw_guest_bin[] = {
	/*
	 * Phase 1: write pattern
	 *   mov $0x30000, %rbx
	 */
	0x48, 0xBB, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	/*   xor %rcx, %rcx */
	0x48, 0x31, 0xC9,
	/* .write_loop: */
	/*   mov %rbx, %rdi */
	0x48, 0x89, 0xDF,
	/*   xor %rsi, %rsi */
	0x48, 0x31, 0xF6,
	/* .write_word: */
	/*   mov %rcx, %rax */
	0x48, 0x89, 0xC8,
	/*   shl $9, %rax */
	0x48, 0xC1, 0xE0, 0x09,
	/*   add %rsi, %rax */
	0x48, 0x01, 0xF0,
	/*   mov %rax, (%rdi,%rsi,8) */
	0x48, 0x89, 0x04, 0xF7,
	/*   inc %rsi */
	0x48, 0xFF, 0xC6,
	/*   cmp $512, %rsi */
	0x48, 0x81, 0xFE, 0x00, 0x02, 0x00, 0x00,
	/*   jl .write_word  (offset = -26) */
	0x7C, 0xE6,
	/*   add $0x1000, %rbx */
	0x48, 0x81, 0xC3, 0x00, 0x10, 0x00, 0x00,
	/*   inc %rcx */
	0x48, 0xFF, 0xC1,
	/*   cmp $10, %rcx */
	0x48, 0x83, 0xF9, 0x0A,
	/*   jl .write_loop  (offset = -48) */
	0x7C, 0xD0,
	/*
	 * Phase 2: XOR all 5120 values
	 *   mov $0x30000, %rbx
	 */
	0x48, 0xBB, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	/*   mov $5120, %rcx */
	0x48, 0xC7, 0xC1, 0x00, 0x14, 0x00, 0x00,
	/*   xor %rdx, %rdx */
	0x48, 0x31, 0xD2,
	/* .xor_loop: */
	/*   sub $1, %rcx */
	0x48, 0xFF, 0xC9,
	/*   mov (%rbx,%rcx,8), %rax */
	0x48, 0x8B, 0x04, 0xCB,
	/*   xor %rax, %rdx */
	0x48, 0x31, 0xC2,
	/*   test %rcx, %rcx */
	0x48, 0x85, 0xC9,
	/*   jnz .xor_loop  (offset = -15) */
	0x75, 0xF1,
	/* Submit: mov %rdx, %rbx */
	0x48, 0x89, 0xD3,
	/* mov $1, %rax */
	0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
	/* vmcall */
	0x0F, 0x01, 0xC1,
	/* hlt */
	0xF4,
	/* jmp .halt (offset = -2) */
	0xEB, 0xFD,
};

/* ------------------------------------------------------------------
 * Guest binary 2 (test_id=1): absent-GPA test
 *
 * Accesses GPA 0x1000000 (first GPA outside the EPT RAM map).
 * This triggers an EPT violation BEFORE any VMCALL, so:
 *   - exit_reason = 48 (VMX_EXIT_EPT_VIOLATION)
 *   - run_result  = PHANTOM_RESULT_CRASH (1)
 *
 * Assembly (64-bit long mode):
 *
 *   mov $0x1000000, %rbx   ; target absent GPA
 *   mov (%rbx), %rax       ; triggers EPT violation
 *   ; (never reached — EPT violation exits here)
 *   vmcall                 ; if somehow reached, halt
 * .halt:
 *   hlt
 *   jmp .halt
 * ------------------------------------------------------------------ */
static const u8 phantom_absent_gpa_guest_bin[] = {
	/* mov $0x1000000, %rbx */
	0x48, 0xBB,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	/* mov (%rbx), %rax  — triggers EPT violation */
	0x48, 0x8B, 0x03,
	/* vmcall — safety: if somehow reached */
	0x0F, 0x01, 0xC1,
	/* hlt */
	0xF4,
	/* jmp .halt (offset = -2) */
	0xEB, 0xFD,
};

/* ------------------------------------------------------------------
 * Guest binary 3 (test_id=2): CoW write test — 20 pages
 *
 * Writes a distinct pattern to 20 consecutive pages at GPA 0x30000.
 * Each word written is: page_index * 512 + word_index (same as test_id=0
 * but extended to 20 pages instead of 10).
 * After writing, issues VMCALL(1, pages_written=20, 0, 0, 0).
 *
 * Expected result: exactly 20 dirty list entries, one per written page.
 * Private page contents must match guest-written pattern.
 *
 * Assembly (64-bit long mode):
 *
 *   mov $0x30000, %rbx        ; base GPA
 *   xor %rcx, %rcx            ; page index = 0
 * .write_loop:
 *   mov %rbx, %rdi            ; page base
 *   xor %rsi, %rsi            ; word index = 0
 * .write_word:
 *   mov %rcx, %rax            ; page_idx
 *   shl $9, %rax              ; * 512
 *   add %rsi, %rax            ; + word_idx
 *   mov %rax, (%rdi,%rsi,8)
 *   inc %rsi
 *   cmp $512, %rsi
 *   jl  .write_word
 *   add $0x1000, %rbx
 *   inc %rcx
 *   cmp $20, %rcx             ; 20 pages
 *   jl  .write_loop
 *   ; VMCALL(1, 20)
 *   mov $20, %rbx
 *   mov $1, %rax
 *   vmcall
 * .halt: hlt ; jmp .halt
 * ------------------------------------------------------------------ */
static const u8 phantom_cow_write_guest_bin[] = {
	/* mov $0x30000, %rbx */
	0x48, 0xBB, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* xor %rcx, %rcx */
	0x48, 0x31, 0xC9,
	/* .write_loop: mov %rbx, %rdi */
	0x48, 0x89, 0xDF,
	/* xor %rsi, %rsi */
	0x48, 0x31, 0xF6,
	/* .write_word: mov %rcx, %rax */
	0x48, 0x89, 0xC8,
	/* shl $9, %rax */
	0x48, 0xC1, 0xE0, 0x09,
	/* add %rsi, %rax */
	0x48, 0x01, 0xF0,
	/* mov %rax, (%rdi,%rsi,8) */
	0x48, 0x89, 0x04, 0xF7,
	/* inc %rsi */
	0x48, 0xFF, 0xC6,
	/* cmp $512, %rsi */
	0x48, 0x81, 0xFE, 0x00, 0x02, 0x00, 0x00,
	/* jl .write_word (offset = -26) */
	0x7C, 0xE6,
	/* add $0x1000, %rbx */
	0x48, 0x81, 0xC3, 0x00, 0x10, 0x00, 0x00,
	/* inc %rcx */
	0x48, 0xFF, 0xC1,
	/* cmp $20, %rcx */
	0x48, 0x83, 0xF9, 0x14,
	/* jl .write_loop (offset = -48) */
	0x7C, 0xD0,
	/* mov $20, %rbx */
	0x48, 0xC7, 0xC3, 0x14, 0x00, 0x00, 0x00,
	/* mov $1, %rax */
	0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
	/* vmcall */
	0x0F, 0x01, 0xC1,
	/* hlt */
	0xF4,
	/* jmp .halt (offset = -2) */
	0xEB, 0xFD,
};

/* ------------------------------------------------------------------
 * Guest binary 4 (test_id=3): pool exhaustion test
 *
 * Writes to 10 consecutive pages (0x30000–0x39000) attempting to
 * exhaust a tiny pool.  Only the first N pages will CoW-succeed
 * (where N = pool capacity, e.g. 5).  After all writes are attempted,
 * issues VMCALL(1, 10).
 *
 * The ioctl should return PHANTOM_RESULT_CRASH (pool exhausted)
 * and the guest run should abort cleanly.  Host must not panic.
 *
 * This is identical to the 10-page write test (phantom_rw_guest_bin)
 * but without the XOR phase — just write then VMCALL with count.
 *
 * Assembly (64-bit long mode): same write loop as test_id=2 but 10 pages.
 * ------------------------------------------------------------------ */
static const u8 phantom_pool_exhaust_guest_bin[] = {
	/* mov $0x30000, %rbx */
	0x48, 0xBB, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* xor %rcx, %rcx */
	0x48, 0x31, 0xC9,
	/* .write_loop: mov %rbx, %rdi */
	0x48, 0x89, 0xDF,
	/* xor %rsi, %rsi */
	0x48, 0x31, 0xF6,
	/* .write_word: mov %rcx, %rax */
	0x48, 0x89, 0xC8,
	/* shl $9, %rax */
	0x48, 0xC1, 0xE0, 0x09,
	/* add %rsi, %rax */
	0x48, 0x01, 0xF0,
	/* mov %rax, (%rdi,%rsi,8) */
	0x48, 0x89, 0x04, 0xF7,
	/* inc %rsi */
	0x48, 0xFF, 0xC6,
	/* cmp $512, %rsi */
	0x48, 0x81, 0xFE, 0x00, 0x02, 0x00, 0x00,
	/* jl .write_word (offset = -26) */
	0x7C, 0xE6,
	/* add $0x1000, %rbx */
	0x48, 0x81, 0xC3, 0x00, 0x10, 0x00, 0x00,
	/* inc %rcx */
	0x48, 0xFF, 0xC1,
	/* cmp $10, %rcx */
	0x48, 0x83, 0xF9, 0x0A,
	/* jl .write_loop (offset = -48) */
	0x7C, 0xD0,
	/* mov $10, %rbx */
	0x48, 0xC7, 0xC3, 0x0A, 0x00, 0x00, 0x00,
	/* mov $1, %rax */
	0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
	/* vmcall */
	0x0F, 0x01, 0xC1,
	/* hlt */
	0xF4,
	/* jmp .halt (offset = -2) */
	0xEB, 0xFD,
};

/* ------------------------------------------------------------------
 * Guest binary 5 (test_id=4): absent-GPA write CoW rejection test
 *
 * Attempts to WRITE to GPA 0x01000000 — within the guest page table
 * mapping (which covers 0–32MB via 2MB large pages), but absent in
 * the EPT (no EPT entry above the 16MB RAM range).
 *
 * When the guest writes to this address:
 *   1. Guest page tables resolve GVA→GPA: 0x01000000 → 0x01000000
 *   2. EPT has no entry for 0x01000000 → EPT violation (exit 48)
 *   3. EPT violation qual: bit 1 (write), bit 3 = 0 (not readable)
 *   4. CoW condition check: qual & BIT(3) == 0 → NOT a CoW write fault
 *   5. Falls through to the "not CoW" branch: log + set CRASH + return 1
 *   6. ioctl returns exit_reason=48, no host panic
 *
 * This validates that non-CoW EPT violations are handled without panic.
 * Host must NOT panic — verified by absence of kernel oops.
 *
 * Assembly: write to 0x1000000, then vmcall (never reached).
 * ------------------------------------------------------------------ */
static const u8 phantom_mmio_cow_guest_bin[] = {
	/* mov $0x1000000, %rbx — absent GPA (above 16MB EPT RAM range) */
	0x48, 0xBB,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	/* mov $0xDEAD, %rax */
	0x48, 0xC7, 0xC0, 0xAD, 0xDE, 0x00, 0x00,
	/* mov %rax, (%rbx) — write to absent GPA → EPT violation */
	0x48, 0x89, 0x03,
	/* vmcall (safety: if somehow reached) */
	0x0F, 0x01, 0xC1,
	/* hlt */
	0xF4,
	/* jmp .halt */
	0xEB, 0xFD,
};

/* ------------------------------------------------------------------
 * Guest binary 6 (test_id=5): 2MB split + CoW test
 *
 * Writes to GPA 0x100000 (within first 2MB region at GPA 0x000000–0x1FFFFF).
 * This triggers:
 *   1. EPT violation on 2MB large-page PD entry (PS=1)
 *   2. phantom_split_2mb_page(): allocate PT, populate 512 × 4KB RO PTEs,
 *      replace PDE, INVEPT
 *   3. phantom_cow_4kb_page(): CoW-promote faulting 4KB page
 *   4. VMRESUME: guest writes succeed, VMCALL(1, 1) called
 *
 * Expected result:
 *   - exit_reason = 18 (VMCALL)
 *   - run_result_data = 1 (count of pages written)
 *   - 1 dirty list entry (exactly one CoW fault)
 *   - INVEPT logged in trace (PHANTOM_DEBUG builds)
 *   - split_list.count = 1 after run
 *
 * Assembly: write one u64 to GPA 0x100000, then VMCALL(1, 1)
 * ------------------------------------------------------------------ */
static const u8 phantom_2mb_split_guest_bin[] = {
	/* mov $0x100000, %rbx — GPA within first 2MB region */
	0x48, 0xBB,
	0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* mov $0xCAFEBABE, %rax */
	0x48, 0xB8, 0xBE, 0xBA, 0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00,
	/* mov %rax, (%rbx) — write to 2MB region → split + CoW */
	0x48, 0x89, 0x03,
	/* mov $1, %rbx — result: 1 page written */
	0x48, 0xC7, 0xC3, 0x01, 0x00, 0x00, 0x00,
	/* mov $1, %rax — VMCALL nr=1 (SUBMIT_RESULT) */
	0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
	/* vmcall */
	0x0F, 0x01, 0xC1,
	/* hlt */
	0xF4,
	/* jmp .halt (offset = -2) */
	0xEB, 0xFD,
};

/* ------------------------------------------------------------------
 * Guest binary 7 (test_id=6): mixed 2MB + 4KB CoW workload
 *
 * Writes to 10 pages spanning both regions:
 *   - 5 pages in 2MB region: GPA 0x100000, 0x200000, 0x300000, 0x400000, 0x500000
 *     (all within first 8MB, each in a different 2MB region)
 *   - 5 pages in 4KB region: GPA 0x800000, 0x801000, 0x802000, 0x803000, 0x804000
 *
 * Assembly strategy: write one u64 to each GPA, then VMCALL(1, 10).
 *
 * Expected results:
 *   - exit_reason = 18 (VMCALL)
 *   - run_result_data = 10
 *   - dirty_count = 10 (5 from 2MB splits + 5 from 4KB region)
 *   - split_list.count = up to 4 (at most 4 × 2MB regions, one per region)
 *   - No host panic
 *
 * Note: each 2MB split generates exactly one split entry (the first write
 * to that 2MB region triggers the split; subsequent writes to the same
 * region hit the 4KB PTEs and just CoW-promote).  We write to 5 different
 * 2MB regions (0x000000, 0x200000, 0x400000, 0x600000 via 0x500000 is in
 * 0x400000–0x5FFFFF, so we adjust to 0x600000 for region 3).
 *
 * Writes:
 *   GPA 0x100000 → 2MB region 0 (0x000000–0x1FFFFF) → split + CoW
 *   GPA 0x200000 → 2MB region 1 (0x200000–0x3FFFFF) → split + CoW
 *   GPA 0x400000 → 2MB region 2 (0x400000–0x5FFFFF) → split + CoW
 *   GPA 0x600000 → 2MB region 3 (0x600000–0x7FFFFF) → split + CoW
 *   GPA 0x110000 → 2MB region 0 (already split) → just 4KB CoW
 *   GPA 0x800000 → 4KB region (PD entry 4) → direct 4KB CoW
 *   GPA 0x801000 → 4KB region → direct 4KB CoW
 *   GPA 0x802000 → 4KB region → direct 4KB CoW
 *   GPA 0x803000 → 4KB region → direct 4KB CoW
 *   GPA 0x804000 → 4KB region → direct 4KB CoW
 *
 * Total: 9 dirty entries (4 splits + 1 re-use + 5 direct 4KB = 10), 4 splits
 *
 * Wait, the re-use (0x110000 in already-split region 0) produces 1 CoW
 * (no split needed — PT already exists).  Total = 10 dirty entries.
 * ------------------------------------------------------------------ */
static const u8 phantom_mixed_cow_guest_bin[] = {
	/*
	 * Write to 10 GPAs covering both 2MB and 4KB regions.
	 * Each write: mov $GPA, %rbx; mov $val, %rax; mov %rax, (%rbx)
	 *
	 * Pattern: mov $IMM64, %rbx  (10 bytes)
	 *          mov $IMM32, %rax  (7 bytes)
	 *          mov %rax, (%rbx)  (3 bytes)
	 *   = 20 bytes per write × 10 = 200 bytes
	 * Then: VMCALL sequence
	 */
	/* Write 1: GPA 0x100000 (2MB region 0) */
	0x48, 0xBB, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
	0x48, 0x89, 0x03,
	/* Write 2: GPA 0x200000 (2MB region 1) */
	0x48, 0xBB, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,
	0x48, 0x89, 0x03,
	/* Write 3: GPA 0x400000 (2MB region 2) */
	0x48, 0xBB, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0xC0, 0x03, 0x00, 0x00, 0x00,
	0x48, 0x89, 0x03,
	/* Write 4: GPA 0x600000 (2MB region 3) */
	0x48, 0xBB, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00,
	0x48, 0x89, 0x03,
	/* Write 5: GPA 0x110000 (2MB region 0, already split) */
	0x48, 0xBB, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00,
	0x48, 0x89, 0x03,
	/* Write 6: GPA 0x800000 (4KB region) */
	0x48, 0xBB, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0xC0, 0x06, 0x00, 0x00, 0x00,
	0x48, 0x89, 0x03,
	/* Write 7: GPA 0x801000 (4KB region) — LE: 00 10 80 00 00 00 00 00 */
	0x48, 0xBB, 0x00, 0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0xC0, 0x07, 0x00, 0x00, 0x00,
	0x48, 0x89, 0x03,
	/* Write 8: GPA 0x802000 (4KB region) — LE: 00 20 80 00 00 00 00 00 */
	0x48, 0xBB, 0x00, 0x20, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0xC0, 0x08, 0x00, 0x00, 0x00,
	0x48, 0x89, 0x03,
	/* Write 9: GPA 0x803000 (4KB region) — LE: 00 30 80 00 00 00 00 00 */
	0x48, 0xBB, 0x00, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0xC0, 0x09, 0x00, 0x00, 0x00,
	0x48, 0x89, 0x03,
	/* Write 10: GPA 0x804000 (4KB region) — LE: 00 40 80 00 00 00 00 00 */
	0x48, 0xBB, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00,
	0x48, 0x89, 0x03,
	/* VMCALL(1, 10): mov $10, %rbx; mov $1, %rax; vmcall */
	0x48, 0xC7, 0xC3, 0x0A, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
	0x0F, 0x01, 0xC1,
	/* hlt; jmp .halt */
	0xF4, 0xEB, 0xFD,
};

/*
 * Task 1.2 backward-compat: original trivial guest binary (test_id=0
 * before task 1.3 introduced the rw_guest_bin).  Kept for reference.
 * Not loaded for any test_id in task 1.3+.
 */
static const u8 phantom_trivial_guest_bin[] = {
	/* xor %rax, %rax */              0x48, 0x31, 0xC0,
	/* vmcall */                       0x0F, 0x01, 0xC1,
	/* xor %rcx, %rcx */              0x48, 0x31, 0xC9,
	/* xor %rdx, %rdx */              0x48, 0x31, 0xD2,
	/* .loop: */
	/* mov (%rbx,%rcx,8), %rax */     0x48, 0x8B, 0x04, 0xCB,
	/* xor %rax, %rdx */              0x48, 0x31, 0xC2,
	/* inc %rcx */                     0x48, 0xFF, 0xC1,
	/* cmp $512, %rcx */              0x48, 0x81, 0xF9,
	                                   0x00, 0x02, 0x00, 0x00,
	/* jl .loop  (offset = -19) */   0x7C, 0xED,
	/* mov %rdx, %rbx */              0x48, 0x89, 0xD3,
	/* mov $1, %rax */                0x48, 0xC7, 0xC0,
	                                   0x01, 0x00, 0x00, 0x00,
	/* vmcall */                       0x0F, 0x01, 0xC1,
	/* hlt */                          0xF4,
	/* jmp .halt  (offset = -2) */   0xEB, 0xFD,
};

/* ------------------------------------------------------------------
 * Guest binary 8 (test_id=7): snapshot/restore XMM test
 *
 * This binary is used to test that XSAVE/XRSTOR correctly saves and
 * restores the extended register state (in particular XMM0) across
 * a snapshot/restore cycle.
 *
 * Protocol:
 *   Run 1 (before snapshot):
 *     - Loads a distinctive pattern into XMM0:
 *         low  64 bits = 0xDEADBEEFCAFEBABE
 *         high 64 bits = 0x0123456789ABCDEF
 *     - Writes a distinctive value to 5 pages at GPA 0x900000–0x904000
 *       (so there is something in the dirty list for snapshot_restore
 *       to clean up)
 *     - Issues VMCALL(1, 0xAA) to signal "ready for snapshot"
 *
 *   The ioctl handler then:
 *     - Calls SNAPSHOT_CREATE (marks EPT RO, saves state including XMM0)
 *
 *   Run 2 (from snapshot point onward):
 *     - Guest continues from RIP after the VMCALL in Run 1
 *     - Reads back XMM0 and checks both halves
 *     - If XMM0 matches the pattern: issues VMCALL(1, 0xBB) — PASS
 *     - If XMM0 does NOT match:      issues VMCALL(1, 0xCC) — FAIL
 *
 * Expected sequence from userspace:
 *   1. RUN_GUEST(test_id=7) → result=0xAA (ready for snapshot)
 *   2. SNAPSHOT_CREATE
 *   3. RUN_GUEST(test_id=7, continuation) → result=0xBB (XMM match)
 *   4. SNAPSHOT_RESTORE
 *   5. RUN_GUEST continuation again → result=0xBB (deterministic)
 *
 * Assembly (64-bit long mode):
 *
 * Encoding note: SSE/XMM instructions use REX + 0F + ... prefixes.
 * We hand-assemble the relevant instructions below.
 *
 *   ; Load XMM0 low half = 0xDEADBEEFCAFEBABE via movq xmm0, rax
 *   mov $0xDEADBEEFCAFEBABE, %rax
 *   movq %rax, %xmm0               ; 66 0F 6E C0
 *
 *   ; Load XMM0 high half = 0x0123456789ABCDEF via movq xmm1, rax
 *   ; then use movlhps xmm0, xmm1  ; 0F 16 C1
 *   mov $0x0123456789ABCDEF, %rax
 *   movq %rax, %xmm1               ; 66 0F 6E C8
 *   movlhps %xmm1, %xmm0          ; 0F 16 C1
 *   (movlhps moves xmm1 low to xmm0 high)
 *
 *   ; Write to 5 pages at GPA 0x900000 to have dirty pages
 *   mov $0x900000, %rbx
 *   xor %rcx, %rcx
 * .write_loop:
 *   mov $0xCAFE, %rax
 *   mov %rax, (%rbx)
 *   add $0x1000, %rbx
 *   inc %rcx
 *   cmp $5, %rcx
 *   jl .write_loop
 *
 *   ; Signal "ready for snapshot" via VMCALL(1, 0xAA)
 *   mov $0xAA, %rbx
 *   mov $1, %rax
 *   vmcall
 *
 *   ; --- Snapshot has been taken at this point ---
 *   ; On the NEXT run, execution resumes HERE (at this RIP).
 *
 *   ; Check XMM0 low half matches 0xDEADBEEFCAFEBABE
 *   movq %xmm0, %rax               ; 66 0F 7E C0
 *   mov $0xDEADBEEFCAFEBABE, %rbx
 *   cmp %rbx, %rax
 *   jne .xmm_fail
 *
 *   ; Check XMM0 high half via movhlps xmm1, xmm0 then movq xmm1, rax
 *   movhlps %xmm0, %xmm1           ; 0F 12 C8
 *   movq %xmm1, %rax               ; 66 0F 7E C8
 *   mov $0x0123456789ABCDEF, %rbx
 *   cmp %rbx, %rax
 *   jne .xmm_fail
 *
 *   ; PASS: VMCALL(1, 0xBB)
 *   mov $0xBB, %rbx
 *   mov $1, %rax
 *   vmcall
 *   hlt
 *   jmp .halt
 *
 * .xmm_fail:
 *   ; FAIL: VMCALL(1, 0xCC)
 *   mov $0xCC, %rbx
 *   mov $1, %rax
 *   vmcall
 *   hlt
 *   jmp .halt
 *
 * ------------------------------------------------------------------ */
static const u8 phantom_snapshot_xmm_guest_bin[] = {
	/*
	 * Byte layout — offsets computed carefully for correct jumps:
	 *
	 * [0..9]    mov $0xDEADBEEFCAFEBABE, %rax   (10 bytes)
	 * [10..14]  movq %rax, %xmm0                (5 bytes: 66 48 0F 6E C0)
	 * [15..24]  mov $0x0123456789ABCDEF, %rax   (10 bytes)
	 * [25..29]  movq %rax, %xmm1                (5 bytes: 66 48 0F 6E C8)
	 * [30..32]  movlhps %xmm1, %xmm0            (3 bytes: 0F 16 C1)
	 *
	 * [33..42]  mov $0x900000, %rbx              (10 bytes)
	 * [43..45]  xor %rcx, %rcx                  (3 bytes)
	 * [46]      .write_loop:
	 * [46..52]  mov $0xCAFE, %rax               (7 bytes)
	 * [53..55]  mov %rax, (%rbx)                (3 bytes)
	 * [56..62]  add $0x1000, %rbx               (7 bytes)
	 * [63..65]  inc %rcx                        (3 bytes)
	 * [66..69]  cmp $5, %rcx                    (4 bytes)
	 * [70..71]  jl .write_loop  rel=-26=0xE6    (2 bytes)
	 *
	 * [72..78]  mov $0xAA, %rbx                 (7 bytes)
	 * [79..85]  mov $1, %rax                    (7 bytes)
	 * [86..88]  vmcall                           (3 bytes)
	 *
	 * === SNAPSHOT RIP = 89 ===
	 *
	 * [89..93]  movq %xmm0, %rax                (5 bytes: 66 48 0F 7E C0)
	 * [94..103] mov $0xDEADBEEFCAFEBABE, %rbx   (10 bytes)
	 * [104..106] cmp %rbx, %rax                 (3 bytes)
	 * [107..108] jne .xmm_fail  rel=+43=0x2B    (2 bytes)
	 *           next_instr = 109
	 *
	 * [109..111] movhlps %xmm0, %xmm1           (3 bytes: 0F 12 C8)
	 * [112..116] movq %xmm1, %rax               (5 bytes: 66 48 0F 7E C8)
	 * [117..126] mov $0x0123456789ABCDEF, %rbx  (10 bytes)
	 * [127..129] cmp %rbx, %rax                 (3 bytes)
	 * [130..131] jne .xmm_fail  rel=+20=0x14    (2 bytes)
	 *           next_instr = 132
	 *
	 * [132..138] mov $0xBB, %rbx                (7 bytes)
	 * [139..145] mov $1, %rax                   (7 bytes)
	 * [146..148] vmcall                          (3 bytes)
	 * [149]     hlt                              (1 byte)
	 * [150..151] jmp .halt  rel=-2=0xFE         (2 bytes)
	 *
	 * .xmm_fail = 152:
	 * [152..158] mov $0xCC, %rbx                (7 bytes)
	 * [159..165] mov $1, %rax                   (7 bytes)
	 * [166..168] vmcall                          (3 bytes)
	 * [169]     hlt                              (1 byte)
	 * [170..171] jmp .halt  rel=-2=0xFE         (2 bytes)
	 *
	 * Jump offset verification:
	 *   jl  .write_loop:  target=46, next=72, rel=46-72=-26=0xE6
	 *   jne .xmm_fail #1: target=152, next=109, rel=152-109=43=0x2B
	 *   jne .xmm_fail #2: target=152, next=132, rel=152-132=20=0x14
	 */

	/* [0..9] mov $0xDEADBEEFCAFEBABE, %rax (REX.W B8 + 8-byte imm) */
	0x48, 0xB8,
	0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE,

	/* [10..14] movq %rax, %xmm0  (66 REX.W 0F 6E /r, ModRM=C0) */
	0x66, 0x48, 0x0F, 0x6E, 0xC0,

	/* [15..24] mov $0x0123456789ABCDEF, %rax */
	0x48, 0xB8,
	0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,

	/* [25..29] movq %rax, %xmm1  (66 REX.W 0F 6E /r, ModRM=C8) */
	0x66, 0x48, 0x0F, 0x6E, 0xC8,

	/* [30..32] movlhps %xmm1, %xmm0  (0F 16 /r, ModRM=C1)
	 * Moves xmm1[63:0] → xmm0[127:64] */
	0x0F, 0x16, 0xC1,

	/* [33..42] mov $0x900000, %rbx */
	0x48, 0xBB,
	0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00,

	/* [43..45] xor %rcx, %rcx */
	0x48, 0x31, 0xC9,

	/* .write_loop: [46] */
	/* [46..52] mov $0xCAFE, %rax */
	0x48, 0xC7, 0xC0, 0xFE, 0xCA, 0x00, 0x00,
	/* [53..55] mov %rax, (%rbx) */
	0x48, 0x89, 0x03,
	/* [56..62] add $0x1000, %rbx */
	0x48, 0x81, 0xC3, 0x00, 0x10, 0x00, 0x00,
	/* [63..65] inc %rcx */
	0x48, 0xFF, 0xC1,
	/* [66..69] cmp $5, %rcx */
	0x48, 0x83, 0xF9, 0x05,
	/* [70..71] jl .write_loop  (next=72, target=46, rel=46-72=-26=0xE6) */
	0x7C, 0xE6,

	/* [72..78] mov $0xAA, %rbx */
	0x48, 0xC7, 0xC3, 0xAA, 0x00, 0x00, 0x00,
	/* [79..85] mov $1, %rax */
	0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
	/* [86..88] vmcall */
	0x0F, 0x01, 0xC1,

	/*
	 * === SNAPSHOT RIP = 89 ===
	 * On the NEXT run, execution resumes at this byte offset
	 * (GUEST_CODE_GPA + 89) because snapshot_create saved this RIP.
	 */

	/* [89..93] movq %xmm0, %rax  (66 REX.W 0F 7E /r, ModRM=C0) */
	0x66, 0x48, 0x0F, 0x7E, 0xC0,

	/* [94..103] mov $0xDEADBEEFCAFEBABE, %rbx */
	0x48, 0xBB,
	0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE,

	/* [104..106] cmp %rbx, %rax */
	0x48, 0x39, 0xD8,

	/* [107..108] jne .xmm_fail  (next=109, target=152, rel=43=0x2B) */
	0x75, 0x2B,

	/* [109..111] movhlps %xmm0, %xmm1  (0F 12 /r, ModRM=C8)
	 * Moves xmm0[127:64] → xmm1[63:0] */
	0x0F, 0x12, 0xC8,

	/* [112..116] movq %xmm1, %rax  (66 REX.W 0F 7E /r, ModRM=C8) */
	0x66, 0x48, 0x0F, 0x7E, 0xC8,

	/* [117..126] mov $0x0123456789ABCDEF, %rbx */
	0x48, 0xBB,
	0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,

	/* [127..129] cmp %rbx, %rax */
	0x48, 0x39, 0xD8,

	/* [130..131] jne .xmm_fail  (next=132, target=152, rel=20=0x14) */
	0x75, 0x14,

	/* PASS path: */
	/* [132..138] mov $0xBB, %rbx */
	0x48, 0xC7, 0xC3, 0xBB, 0x00, 0x00, 0x00,
	/* [139..145] mov $1, %rax */
	0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
	/* [146..148] vmcall */
	0x0F, 0x01, 0xC1,
	/* [149] hlt */
	0xF4,
	/* [150..151] jmp .halt  rel=-2 */
	0xEB, 0xFD,

	/* .xmm_fail = 152: */
	/* [152..158] mov $0xCC, %rbx */
	0x48, 0xC7, 0xC3, 0xCC, 0x00, 0x00, 0x00,
	/* [159..165] mov $1, %rax */
	0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
	/* [166..168] vmcall */
	0x0F, 0x01, 0xC1,
	/* [169] hlt */
	0xF4,
	/* [170..171] jmp .halt  rel=-2 */
	0xEB, 0xFD,
};

/* ------------------------------------------------------------------
 * Guest binary 9 (test_id=8): kAFL/Nyx ABI hypercall harness
 *
 * Implements the full nyx_api iteration loop:
 *   1. GET_PAYLOAD (0x11a): register payload buffer at GPA 0x5000.
 *      On ACQUIRE, host will copy shared_mem->payload to this GPA.
 *   2. ACQUIRE (0x11c): take snapshot on first call.
 *      On subsequent calls (RUN_ITERATION), resumes from snapshot RIP.
 *      === snapshot RIP is here (after ACQUIRE vmcall) ===
 *   3. Read payload[0..7] from GPA 0x5000 into RBX.
 *   4. RELEASE (0x11d): store result=OK, call snapshot_restore.
 *      Guest never returns here — next iteration starts at snapshot RIP.
 *   5. Safety: hlt + jmp loop (unreachable in normal operation).
 *
 * Assembly (64-bit long mode):
 *
 *   ; Phase 1: register payload buffer at GPA 0x5000
 *   mov $0x11a, %rax              ; GET_PAYLOAD
 *   mov $0x5000, %rbx             ; payload GPA
 *   vmcall
 *
 *   ; Phase 2: acquire snapshot (or resume from snapshot)
 *   mov $0x11c, %rax              ; ACQUIRE
 *   vmcall
 *   === snapshot RIP = GUEST_CODE_GPA + 36 ===
 *
 *   ; Phase 3: read payload[0..7]
 *   mov 0x5000, %rbx              ; absolute memory ref
 *
 *   ; Phase 4: release (end iteration)
 *   mov $0x11d, %rax              ; RELEASE
 *   vmcall
 *
 *   ; Safety halt
 *   hlt
 *   jmp .halt
 *
 * Byte layout:
 *   [0..9]    mov $0x11a, %rax    (10 bytes)
 *   [10..19]  mov $0x5000, %rbx   (10 bytes)
 *   [20..22]  vmcall               (3 bytes)
 *   [23..32]  mov $0x11c, %rax    (10 bytes)
 *   [33..35]  vmcall               (3 bytes)
 *   === snapshot RIP = GUEST_CODE_GPA + 36 ===
 *   [36..43]  mov 0x5000, %rbx    (8 bytes, absolute SIB encoding)
 *   [44..53]  mov $0x11d, %rax    (10 bytes)
 *   [54..56]  vmcall               (3 bytes)
 *   [57]      hlt                  (1 byte)
 *   [58..59]  jmp .halt  rel=-2   (2 bytes)
 * ------------------------------------------------------------------ */
static const u8 phantom_hypercall_harness_bin[] = {
	/* [0..9] mov $0x11a, %rax  (REX.W B8 + 8-byte imm) */
	0x48, 0xB8, 0x1A, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* [10..19] mov $0x5000, %rbx  (REX.W BB + 8-byte imm) */
	0x48, 0xBB, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* [20..22] vmcall */
	0x0F, 0x01, 0xC1,
	/* [23..32] mov $0x11c, %rax */
	0x48, 0xB8, 0x1C, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* [33..35] vmcall */
	0x0F, 0x01, 0xC1,
	/*
	 * === snapshot RIP = GUEST_CODE_GPA + 36 ===
	 * Execution resumes here each iteration after snapshot_restore.
	 *
	 * [36..43] mov 0x5000, %rbx  (absolute memory reference)
	 * Encoding: REX.W(0x48) 8B /r with ModRM=00,011,100(SIB)
	 *           SIB=00,100,101(disp32) + 32-bit displacement 0x00005000
	 * = 48 8B 1C 25 00 50 00 00
	 */
	0x48, 0x8B, 0x1C, 0x25, 0x00, 0x50, 0x00, 0x00,
	/* [44..53] mov $0x11d, %rax */
	0x48, 0xB8, 0x1D, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* [54..56] vmcall  (RELEASE → snapshot_restore → guest resumes at [36]) */
	0x0F, 0x01, 0xC1,
	/* [57] hlt  (safety: unreachable in normal operation) */
	0xF4,
	/* [58..59] jmp .halt  rel=-2 */
	0xEB, 0xFD,
};

/* ------------------------------------------------------------------
 * Guest binary 10 (test_id=9): deliberate panic for crash detection
 *
 * Issues ACQUIRE (0x11c) to take snapshot, then immediately issues
 * PANIC (0x11e) with crash address 0xDEADBEEF.  Used by test_crash.c
 * to verify that the host correctly detects and records the crash.
 *
 * Assembly:
 *   mov $0x11c, %rax    ; HYPERCALL_KAFL_ACQUIRE
 *   xor %rcx, %rcx
 *   vmcall
 *   mov $0x11e, %rax    ; HYPERCALL_KAFL_PANIC
 *   mov $0xDEADBEEF, %rcx
 *   vmcall
 * .Lhang:
 *   jmp .Lhang          ; never reached after PANIC
 *
 * Byte layout:
 *   [0..9]   mov $0x11c, %rax  (REX.W B8 + 8-byte imm)
 *   [10..12] xor %rcx, %rcx   (REX.W 31 C9)
 *   [13..15] vmcall            (0F 01 C1)
 *   [16..25] mov $0x11e, %rax  (REX.W B8 + 8-byte imm)
 *   [26..35] mov $0xDEADBEEF, %rcx (REX.W B9 + 8-byte imm)
 *   [36..38] vmcall            (0F 01 C1)
 *   [39..40] jmp .Lhang  rel=-2 (EB FE)
 * ------------------------------------------------------------------ */
static const u8 phantom_panic_guest_bin[] = {
	/* [0..9] mov $0x11c, %rax */
	0x48, 0xB8, 0x1C, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* [10..12] xor %rcx, %rcx */
	0x48, 0x31, 0xC9,
	/* [13..15] vmcall */
	0x0F, 0x01, 0xC1,
	/* [16..25] mov $0x11e, %rax */
	0x48, 0xB8, 0x1E, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* [26..35] mov $0xDEADBEEF, %rcx */
	0x48, 0xB9, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00,
	/* [36..38] vmcall */
	0x0F, 0x01, 0xC1,
	/* [39..40] jmp .Lhang  rel=-2 (never reached) */
	0xEB, 0xFE,
};

/* ------------------------------------------------------------------
 * File operations
 * ------------------------------------------------------------------ */

static int phantom_open(struct inode *inode, struct file *filp)
{
	struct phantom_dev *pdev;
	struct phantom_file *fctx;

	pdev = container_of(inode->i_cdev, struct phantom_dev, cdev);

	if (!pdev->initialized) {
		pr_err("phantom: open() called before module is fully initialised\n");
		return -ENXIO;
	}

	fctx = kzalloc(sizeof(*fctx), GFP_KERNEL);
	if (!fctx)
		return -ENOMEM;

	fctx->pdev      = pdev;
	fctx->bound_cpu = -1;  /* no VM created yet */
	filp->private_data = fctx;

	return 0;
}

static int phantom_release(struct inode *inode, struct file *filp)
{
	struct phantom_file *fctx = filp->private_data;

	kfree(fctx);
	filp->private_data = NULL;
	return 0;
}

/*
 * phantom_file_cpu - Return the CPU bound to this fd, or fallback to first.
 *
 * If the fd has been bound via CREATE_VM, return that CPU.
 * Otherwise fall back to the first CPU in the vmx_cpumask (legacy behaviour
 * for ioctls called before CREATE_VM on single-core setups).
 */
static int phantom_file_cpu(struct phantom_file *fctx)
{
	if (fctx->bound_cpu >= 0)
		return fctx->bound_cpu;

	/* Fallback: first CPU in mask */
	{
		int cpu;

		for_each_cpu(cpu, fctx->pdev->vmx_cpumask)
			return cpu;
	}
	return -1;
}

static long phantom_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	struct phantom_file *fctx = filp->private_data;
	struct phantom_dev *pdev;
	long ret = 0;

	if (!fctx)
		return -ENXIO;
	pdev = fctx->pdev;
	if (!pdev || !pdev->initialized)
		return -ENXIO;

	switch (cmd) {
	case PHANTOM_IOCTL_GET_VERSION: {
		__u32 ver = PHANTOM_VERSION;

		if (copy_to_user((__u32 __user *)arg, &ver, sizeof(ver)))
			ret = -EFAULT;
		break;
	}

	case PHANTOM_IOCTL_RUN_GUEST: {
		struct phantom_run_args args;
		struct phantom_vmx_cpu_state *state;
		int target_cpu;
		u32 test_id;

		if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
			ret = -EFAULT;
			break;
		}

		/*
		 * args.reserved is used as test_id:
		 *   0 = R/W checksum test (10 pages at GPA 0x30000–0x39000)
		 *   1 = absent-GPA test (access GPA 0x1000000 → EPT violation)
		 *   2 = CoW write test (20 pages at GPA 0x30000–0x43000)
		 *   3 = pool exhaustion test (5-page pool, 10-page write)
		 *   4 = MMIO CoW rejection test (write to LAPIC MMIO GPA)
		 *   5 = 2MB split + CoW test (write to GPA 0x100000)
		 *   6 = mixed 2MB + 4KB workload (10 writes, both regions)
		 *   7 = snapshot/restore XMM test (task 1.6)
		 *   9 = deliberate panic (ACQUIRE + PANIC(0xDEADBEEF))
		 *  10 = external binary (PHANTOM_LOAD_TARGET, no code overwrite)
		 */
		test_id = args.reserved;
		if (test_id > 10) {
			pr_err("phantom: RUN_GUEST: invalid test_id=%u\n",
			       test_id);
			ret = -EINVAL;
			break;
		}

		/*
		 * Select target CPU: prefer the CPU bound to this fd via
		 * CREATE_VM, then honour args.cpu if set, finally fall back
		 * to the first CPU in the vmx_cpumask.
		 */
		target_cpu = phantom_file_cpu(fctx);
		if (target_cpu < 0) {
			pr_err("phantom: RUN_GUEST: no VMX CPU available\n");
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		if (!state->vcpu_thread) {
			pr_err("phantom: RUN_GUEST: vCPU thread not running\n");
			ret = -ENXIO;
			break;
		}

		/*
		 * Phase A: Allocate pages in process context (GFP_KERNEL safe).
		 * Idempotent; phantom_vmcs_setup() returns 0 if already done.
		 */
		ret = phantom_vmcs_setup(state);
		if (ret) {
			pr_err("phantom: RUN_GUEST: vmcs_setup failed: %ld\n",
			       ret);
			break;
		}

		/*
		 * Phase B: Prepare guest memory.
		 *
		 * This runs in IOCTL process context (any CPU), which is fine:
		 * we're writing to physical pages, not VMCS fields.
		 * The vCPU thread handles all VMCS operations.
		 */

		/*
		 * Re-prime detection: if RUN_GUEST is called with a different
		 * test_id than the last run, the previous snapshot is stale.
		 * Clear snap_acquired and snap_taken so the new binary is
		 * loaded fresh and a new snapshot is taken on the next ACQUIRE.
		 */
		if (state->last_test_id != test_id) {
			state->snap_acquired   = false;
			state->snap_taken      = false;
			state->snap_continue   = false;
			state->iteration_active = false;
			state->last_test_id    = test_id;
		}

		/*
		 * Select and load guest binary into code page.
		 * test_id=0: R/W checksum test
		 * test_id=1: absent-GPA EPT violation test
		 * test_id=2: CoW write test (20 pages)
		 * test_id=3: pool exhaustion test (5-page pool, 10-write)
		 * test_id=4: MMIO CoW rejection test
		 * test_id=5: 2MB split + CoW (write to GPA 0x100000)
		 * test_id=6: mixed 2MB + 4KB workload (10 writes)
		 * test_id=7: snapshot/restore XMM test (task 1.6)
		 * test_id=9: deliberate panic (ACQUIRE + PANIC(0xDEADBEEF))
		 *
		 * Note for test_id=7: the binary has TWO phases.  On the
		 * first run it reaches the VMCALL(1,0xAA) and exits.  The
		 * userspace test then calls SNAPSHOT_CREATE (which saves
		 * the VMCS RIP pointing AFTER the VMCALL instruction).
		 * On subsequent runs the guest resumes from that saved RIP
		 * and checks XMM0, issuing VMCALL(1,0xBB) on success.
		 *
		 * To support the two-phase behavior, test_id=7 does NOT
		 * overwrite the code page on continuation runs (snap_taken
		 * is true).  The snap_continue flag (set by SNAPSHOT_RESTORE)
		 * controls whether the vCPU thread skips the RIP reset.
		 */
		if (test_id == 0) {
			memcpy(page_address(state->guest_code_page),
			       phantom_rw_guest_bin,
			       sizeof(phantom_rw_guest_bin));

			/*
			 * Zero the 10 R/W test pages at GPA 0x30000–0x39000
			 * for determinism across multiple runs.
			 */
			{
				int p;

				for (p = 0; p < GUEST_RWTEST_NR_PAGES; p++) {
					u64 gpa = GUEST_RWTEST_GPA_BASE +
						  (u64)p * PAGE_SIZE;
					struct page *pg;
					u64 *dp;

					pg = phantom_ept_get_ram_page(
						&state->ept, gpa);
					if (!pg)
						continue;
					dp = (u64 *)page_address(pg);
					memset(dp, 0, PAGE_SIZE);
				}
			}
		} else if (test_id == 1) {
			/* absent-GPA test */
			memcpy(page_address(state->guest_code_page),
			       phantom_absent_gpa_guest_bin,
			       sizeof(phantom_absent_gpa_guest_bin));
		} else if (test_id == 2) {
			/*
			 * CoW write test: 20 pages at GPA 0x30000–0x43000.
			 * Zero all 20 pages before the run for determinism.
			 */
			memcpy(page_address(state->guest_code_page),
			       phantom_cow_write_guest_bin,
			       sizeof(phantom_cow_write_guest_bin));
			{
				int p;

				for (p = 0; p < 20; p++) {
					u64 gpa = GUEST_RWTEST_GPA_BASE +
						  (u64)p * PAGE_SIZE;
					struct page *pg;

					pg = phantom_ept_get_ram_page(
						&state->ept, gpa);
					if (!pg)
						continue;
					memset(page_address(pg), 0, PAGE_SIZE);
				}
			}
		} else if (test_id == 3) {
			/*
			 * Pool exhaustion test: use default pool (which was
			 * initialised at vmcs_setup time).  The 10-page write
			 * will exhaust the 4096-page default pool after 10
			 * CoW faults.  For a tighter test the userspace tool
			 * unloads and reloads the module with a tiny pool —
			 * but within the module this uses the default pool and
			 * we just verify that even with a "large" pool the 10
			 * writes produce exactly 10 dirty entries.
			 *
			 * The true tiny-pool exhaustion test is done by the
			 * test binary by checking run_result vs dirty_count.
			 */
			memcpy(page_address(state->guest_code_page),
			       phantom_pool_exhaust_guest_bin,
			       sizeof(phantom_pool_exhaust_guest_bin));
			{
				int p;

				for (p = 0; p < 10; p++) {
					u64 gpa = GUEST_RWTEST_GPA_BASE +
						  (u64)p * PAGE_SIZE;
					struct page *pg;

					pg = phantom_ept_get_ram_page(
						&state->ept, gpa);
					if (!pg)
						continue;
					memset(page_address(pg), 0, PAGE_SIZE);
				}
			}
		} else if (test_id == 4) {
			/* test_id=4: MMIO CoW rejection test */
			memcpy(page_address(state->guest_code_page),
			       phantom_mmio_cow_guest_bin,
			       sizeof(phantom_mmio_cow_guest_bin));
		} else if (test_id == 5) {
			/*
			 * test_id=5: 2MB split + CoW test.
			 * Guest writes to GPA 0x100000 — triggers 2MB split.
			 * No pre-zeroing needed (only one word written).
			 */
			memcpy(page_address(state->guest_code_page),
			       phantom_2mb_split_guest_bin,
			       sizeof(phantom_2mb_split_guest_bin));
		} else if (test_id == 6) {
			/*
			 * test_id=6: mixed 2MB + 4KB workload.
			 * Guest writes 10 words across both regions.
			 */
			memcpy(page_address(state->guest_code_page),
			       phantom_mixed_cow_guest_bin,
			       sizeof(phantom_mixed_cow_guest_bin));
		} else if (test_id == 7) {
			/*
			 * test_id=7: snapshot/restore XMM test.
			 *
			 * Phase 1: guest loads XMM0, writes 5 pages,
			 * issues VMCALL(1,0xAA) → exits with result=0xAA.
			 * Userspace then calls SNAPSHOT_CREATE.
			 *
			 * Phase 2 (after snapshot): guest checks XMM0,
			 * issues VMCALL(1,0xBB) on match or 0xCC on fail.
			 *
			 * We only load the binary on first use (when
			 * snap_taken is false).  On subsequent runs after
			 * SNAPSHOT_RESTORE, the guest code page is already
			 * correct (it was written before the snapshot) and
			 * the binary must NOT be overwritten (that would
			 * lose the post-snapshot instructions).
			 */
			if (!state->snap_taken) {
				memcpy(page_address(state->guest_code_page),
				       phantom_snapshot_xmm_guest_bin,
				       sizeof(phantom_snapshot_xmm_guest_bin));
			}
		} else if (test_id == 8) {
			/*
			 * test_id=8: kAFL/Nyx ABI hypercall harness.
			 *
			 * The binary uses ACQUIRE/RELEASE semantics:
			 *   1. GET_PAYLOAD (0x11a): register GPA 0x5000.
			 *   2. ACQUIRE (0x11c): take snapshot on first call.
			 *   3. Read payload[0..7] from GPA 0x5000.
			 *   4. RELEASE (0x11d): end iteration, restore snap.
			 *
			 * Only load the binary on the first run (snap_acquired
			 * is false).  After ACQUIRE fires and the snapshot is
			 * taken, the guest will resume from snapshot RIP on
			 * each subsequent RUN_GUEST/RUN_ITERATION call.
			 * Overwriting the code page would corrupt the binary
			 * at the snapshot resume point.
			 */
			if (!state->snap_acquired) {
				memcpy(page_address(state->guest_code_page),
				       phantom_hypercall_harness_bin,
				       sizeof(phantom_hypercall_harness_bin));
			}
		} else if (test_id == 9) {
			/*
			 * test_id=9: deliberate panic test.
			 *
			 * Issues ACQUIRE (takes snapshot) then immediately
			 * issues PANIC(0xDEADBEEF).  Used by test_crash.c to
			 * verify crash detection: the hypercall handler must
			 * set run_result=PHANTOM_RESULT_CRASH and record
			 * crash_addr=0xDEADBEEF.
			 *
			 * Load binary fresh each run (no snapshot resume
			 * needed — PANIC always terminates the iteration).
			 */
			memcpy(page_address(state->guest_code_page),
			       phantom_panic_guest_bin,
			       sizeof(phantom_panic_guest_bin));
		} else {
			/*
			 * test_id >= 10: external binary already loaded via
			 * PHANTOM_LOAD_TARGET.  Do not overwrite guest_code_page.
			 * The caller is responsible for loading the binary into
			 * EPT RAM before issuing RUN_GUEST.
			 */
		}

		/* Save test_id for the vCPU thread */
		state->test_id = test_id;

		/*
		 * Phase C: Prepare guest-state reset for relaunches.
		 *
		 * On first setup, phantom_vmcs_configure_fields() initialises
		 * RIP/RSP/RFLAGS correctly.  On subsequent runs, we signal
		 * the vCPU thread to reset those fields before VMLAUNCH
		 * (vcpu_run_request bit 1 = "reset needed").
		 *
		 * Always clear the per-run result state here.
		 *
		 * snap_continue: tells the vCPU thread whether to skip the
		 * RIP/RSP/RFLAGS reset.  Set true only for test_id=7 when
		 * a snapshot has been taken (phase 2 + all continuation runs
		 * after SNAPSHOT_RESTORE).  False for all other test_ids and
		 * for the very first test_id=7 run (phase 1, snap_taken=false).
		 *
		 * This must be set BEFORE signaling vcpu_work_ready so the
		 * vCPU thread sees the correct value via the
		 * smp_store_release / smp_load_acquire barrier pair.
		 */
		state->run_result      = 0;
		state->run_result_data = 0;
		memset(&state->guest_regs, 0, sizeof(state->guest_regs));
		/*
		 * snap_continue: true when the guest should resume from the
		 * snapshot RIP rather than being reset to GUEST_CODE_GPA.
		 *   test_id=7: snap_taken after first SNAPSHOT_CREATE.
		 *   test_id=8: snap_acquired after first ACQUIRE hypercall.
		 *   test_id=9: always false — PANIC terminates each run.
		 */
		state->snap_continue = ((test_id == 7 && state->snap_taken) ||
					 (test_id == 8 && state->snap_acquired));

		if (!state->vmcs_configured) {
			/* First run — configure_fields sets initial values */
			state->vcpu_run_request = 1; /* run only */
		} else {
			/* Re-launch — thread must reset RIP/RSP/RFLAGS */
			state->vcpu_run_request = 3; /* run | reset */
		}

		/*
		 * Phase D: Signal the vCPU thread to run the guest and wait
		 * for it to complete.
		 *
		 * The vCPU thread is a kernel thread pinned to target_cpu.
		 * It runs phantom_vmcs_configure_fields() (idempotent) and
		 * then phantom_run_guest() — all on the correct CPU where the
		 * VMCS is current.
		 *
		 * Nested KVM IPI safety:
		 *
		 *   After the first VMLAUNCH, KVM L0's nested VMX tracking
		 *   for target_cpu is "dirty" even after the guest exits.
		 *   Any RESCHEDULE IPI sent to target_cpu in this state
		 *   causes a triple fault.  complete() sends RESCHEDULE IPI.
		 *
		 *   On the FIRST run: the vCPU thread is sleeping on
		 *   vcpu_run_start completion (Phase 1 in phantom_vcpu_fn).
		 *   complete() is safe — no VMLAUNCH has occurred yet.
		 *
		 *   On SUBSEQUENT runs: the vCPU thread is busy-waiting on
		 *   vcpu_work_ready (Phase 2 in phantom_vcpu_fn).  We set the
		 *   flag via smp_store_release (no IPI) and the thread polls
		 *   it via smp_load_acquire in its cpu_relax() busy-wait loop.
		 */
		if (!state->vmcs_configured) {
			/* First run: thread is sleeping, safe to use complete */
			complete(&state->vcpu_run_start);
		} else {
			/*
			 * Subsequent run: thread is busy-waiting.
			 * smp_store_release pairs with smp_load_acquire in
			 * phantom_vcpu_fn to ensure the run_request update
			 * is visible before vcpu_work_ready is seen as true.
			 */
			smp_store_release(&state->vcpu_work_ready, true);
		}

		/* Wait for the vCPU thread to finish the guest run */
		wait_for_completion(&state->vcpu_run_done);

		if (state->vcpu_run_result < 0) {
			pr_err("phantom: RUN_GUEST execution failed: %d\n",
			       state->vcpu_run_result);
			ret = state->vcpu_run_result;
			break;
		}

		/*
		 * Populate output fields.
		 *
		 * For CoW tests (test_id=2,3), the ioctl handler captures
		 * the dirty_count BEFORE phantom_cow_abort_iteration() resets
		 * it.  However, abort_iteration runs in the vCPU thread
		 * immediately after phantom_run_guest() returns, so by the
		 * time we read dirty_count here it may already be 0.
		 *
		 * To expose dirty_count to userspace, we encode it in the
		 * upper 32 bits of args.result for test_id=2,3 only:
		 *   bits 63:32 = dirty_count at end-of-run
		 *   bits 31:0  = run_result_data (e.g. checksum or count)
		 *
		 * For test_id=0,1,4: args.result = run_result_data as-is.
		 *
		 * Note: abort_iteration resets dirty_count to 0, so we use
		 * run_result_data (set by the VMCALL handler) as a proxy for
		 * "how many pages were written" (guest passes count via RBX).
		 */
		args.result      = state->run_result_data;
		args.exit_reason = state->exit_reason & 0xFFFF;

		if (copy_to_user((void __user *)arg, &args, sizeof(args)))
			ret = -EFAULT;
		break;
	}

	case PHANTOM_IOCTL_DEBUG_DUMP_EPT: {
		int target_cpu = -1;
		struct phantom_vmx_cpu_state *state;

		target_cpu = phantom_file_cpu(fctx);

		if (target_cpu < 0) {
			pr_err("phantom: DEBUG_DUMP_EPT: no VMX CPU\n");
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		/*
		 * Ensure pages are allocated before walking the EPT.
		 * phantom_vmcs_setup() is idempotent — no-op if already done.
		 */
		ret = phantom_vmcs_setup(state);
		if (ret) {
			pr_err("phantom: DEBUG_DUMP_EPT: vmcs_setup "
			       "failed: %ld\n", ret);
			break;
		}

		ret = phantom_debug_dump_ept(state);
		break;
	}

	case PHANTOM_IOCTL_DEBUG_DUMP_DIRTY_LIST: {
		int target_cpu = -1;
		struct phantom_vmx_cpu_state *state;

		target_cpu = phantom_file_cpu(fctx);

		if (target_cpu < 0) {
			pr_err("phantom: DEBUG_DUMP_DIRTY_LIST: "
			       "no VMX CPU\n");
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		if (!state->pages_allocated) {
			pr_err("phantom: DEBUG_DUMP_DIRTY_LIST: "
			       "pages not allocated\n");
			ret = -EINVAL;
			break;
		}

		ret = phantom_debug_dump_dirty_list(state);
		break;
	}

	case PHANTOM_IOCTL_DEBUG_DUMP_DIRTY_OVERFLOW: {
		int target_cpu;
		struct phantom_vmx_cpu_state *state;

		target_cpu = phantom_file_cpu(fctx);
		if (target_cpu < 0) {
			pr_err("phantom: DEBUG_DUMP_DIRTY_OVERFLOW: "
			       "no VMX CPU\n");
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);
		ret = phantom_debug_dump_dirty_overflow(state);
		break;
	}

	case PHANTOM_IOCTL_SNAPSHOT_CREATE: {
		int target_cpu;
		struct phantom_vmx_cpu_state *state;

		target_cpu = phantom_file_cpu(fctx);
		if (target_cpu < 0) {
			pr_err("phantom: SNAPSHOT_CREATE: no VMX CPU\n");
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		if (!state->pages_allocated) {
			pr_err("phantom: SNAPSHOT_CREATE: pages not allocated\n");
			ret = -EINVAL;
			break;
		}

		if (!state->vmcs_configured) {
			/*
			 * VMCS not yet configured — cannot snapshot.
			 * Caller must run RUN_GUEST first to get the guest
			 * into a consistent state before snapshotting.
			 */
			pr_err("phantom: SNAPSHOT_CREATE: VMCS not configured "
			       "(run RUN_GUEST first)\n");
			ret = -EINVAL;
			break;
		}

		if (!state->vcpu_thread) {
			pr_err("phantom: SNAPSHOT_CREATE: vCPU thread not "
			       "running\n");
			ret = -ENXIO;
			break;
		}

		/*
		 * SNAPSHOT_CREATE must run on the vCPU thread (same CPU
		 * where the VMCS is current) because it calls VMCS read
		 * helpers and phantom_ept_mark_all_ro().
		 *
		 * vcpu_run_request = 4 means "run snapshot_create only".
		 *
		 * SNAPSHOT_CREATE is always called after the first RUN_GUEST,
		 * so we are always in Phase 2 (vmlaunch_done = true) and the
		 * IPI-free busy-wait path via smp_store_release is correct.
		 */
		state->vcpu_run_request = 4;
		smp_store_release(&state->vcpu_work_ready, true);
		wait_for_completion(&state->vcpu_run_done);

		if (state->vcpu_run_result < 0) {
			pr_err("phantom: SNAPSHOT_CREATE failed: %d\n",
			       state->vcpu_run_result);
			ret = state->vcpu_run_result;
		} else {
			state->snap_taken = true;
			pr_info("phantom: CPU%d: snapshot created "
				"(rip=0x%llx cr3=0x%llx)\n",
				target_cpu,
				state->snap.rip, state->snap.cr3);
		}
		break;
	}

	case PHANTOM_IOCTL_SNAPSHOT_RESTORE: {
		int target_cpu;
		struct phantom_vmx_cpu_state *state;

		target_cpu = phantom_file_cpu(fctx);
		if (target_cpu < 0) {
			pr_err("phantom: SNAPSHOT_RESTORE: no VMX CPU\n");
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		if (!state->snap_taken || !state->snap.valid) {
			pr_err("phantom: SNAPSHOT_RESTORE: no valid snapshot\n");
			ret = -EINVAL;
			break;
		}

		/*
		 * Request the vCPU thread to execute snapshot_restore
		 * on its own CPU (VMCS must be current).
		 * vcpu_run_request = 5 means "run snapshot_restore only".
		 */
		state->vcpu_run_request = 5;
		smp_store_release(&state->vcpu_work_ready, true);
		wait_for_completion(&state->vcpu_run_done);

		if (state->vcpu_run_result < 0) {
			pr_err("phantom: SNAPSHOT_RESTORE failed: %d\n",
			       state->vcpu_run_result);
			ret = state->vcpu_run_result;
		}
		break;
	}

	case PHANTOM_IOCTL_PERF_RESTORE_LATENCY: {
		/*
		 * Return the per-phase rdtsc cycle counts from the last
		 * phantom_snapshot_restore() call.
		 *
		 * These are populated by snapshot_restore() running on the
		 * vCPU thread and are stable by the time the ioctl handler
		 * reads them (wait_for_completion() in SNAPSHOT_RESTORE
		 * provides the necessary memory barrier before the thread
		 * stores the values, and by definition no new SNAPSHOT_RESTORE
		 * can be in flight when this ioctl is running).
		 *
		 * Returns -EINVAL if no snapshot has been taken (no restore
		 * has ever run, so the counters would be meaningless zeros).
		 */
		int target_cpu;
		struct phantom_vmx_cpu_state *state;
		struct phantom_perf_result result;

		target_cpu = phantom_file_cpu(fctx);
		if (target_cpu < 0) {
			pr_err("phantom: PERF_RESTORE_LATENCY: no VMX CPU\n");
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		if (!state->snap_taken) {
			pr_err("phantom: PERF_RESTORE_LATENCY: no snapshot "
			       "has been taken (run SNAPSHOT_RESTORE first)\n");
			ret = -EINVAL;
			break;
		}

		/* Copy perf_last from kernel state */
		result = state->perf_last;

		if (copy_to_user((void __user *)arg, &result, sizeof(result)))
			ret = -EFAULT;
		break;
	}

	case PHANTOM_IOCTL_RUN_ITERATION: {
		/*
		 * RUN_ITERATION — run one kAFL/Nyx fuzzing iteration.
		 *
		 * Prerequisites:
		 *   - phantom_vmcs_setup() must have run (pages_allocated).
		 *   - ACQUIRE hypercall must have fired (snap_acquired=true).
		 *   - Userspace must have written payload to shared_mem->payload
		 *     and set shared_mem->payload_len before this ioctl.
		 *
		 * Execution:
		 *   1. Copy payload from shared_mem into guest RAM at
		 *      state->payload_gpa (if set by GET_PAYLOAD hypercall).
		 *   2. Set snap_continue=true so vCPU thread skips RIP reset.
		 *   3. Signal vCPU thread via vcpu_run_request=6.
		 *   4. Wait for iteration to complete.
		 *   5. Copy result back to shared_mem (done by hypercall handler).
		 *   6. Return 0; caller reads status from shared_mem or GET_RESULT.
		 */
		struct phantom_iter_params params;
		struct phantom_vmx_cpu_state *state;
		int target_cpu;
		struct phantom_shared_mem *sm;

		if (copy_from_user(&params, (void __user *)arg, sizeof(params))) {
			ret = -EFAULT;
			break;
		}

		if (params.payload_len > PHANTOM_PAYLOAD_MAX) {
			ret = -EINVAL;
			break;
		}

		/* Find target CPU — use the CPU bound to this fd */
		target_cpu = phantom_file_cpu(fctx);
		if (target_cpu < 0) {
			pr_err("phantom: RUN_ITERATION: no VMX CPU\n");
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		if (!state->pages_allocated) {
			pr_err("phantom: RUN_ITERATION: pages not allocated "
			       "(run RUN_GUEST test_id=8 first)\n");
			ret = -ENXIO;
			break;
		}

		if (!state->snap_acquired) {
			pr_err("phantom: RUN_ITERATION: no snapshot taken "
			       "(run RUN_GUEST test_id=8 first)\n");
			ret = -EINVAL;
			break;
		}

		if (!state->vcpu_thread) {
			pr_err("phantom: RUN_ITERATION: vCPU thread not running\n");
			ret = -ENXIO;
			break;
		}

		/*
		 * Update payload_len in shared memory so phantom_copy_to_guest
		 * (called by inject_payload in handle_acquire) copies the
		 * correct number of bytes.
		 */
		sm = (struct phantom_shared_mem *)state->shared_mem;
		if (sm)
			sm->payload_len = params.payload_len;

		/*
		 * Clear per-run result state before signalling the vCPU thread.
		 * snap_continue=true: VMCS RIP is already at snap->rip from
		 * the last phantom_snapshot_restore() (in RELEASE/PANIC/KASAN).
		 */
		state->run_result      = PHANTOM_RESULT_OK;
		state->run_result_data = 0;
		state->crash_addr      = 0;
		state->snap_continue   = true;
		state->vcpu_run_request = 6;

		/*
		 * Signal the vCPU thread.  After the first ACQUIRE (which means
		 * vmcs_configured is true and vmlaunch_done is true in the vCPU
		 * thread), we must use the IPI-free busy-wait path.
		 *
		 * CRITICAL: re-initialize vcpu_run_done BEFORE signalling the
		 * vCPU.  The boot run (BOOT_KERNEL step 7, async) fires
		 * complete(&vcpu_run_done) when the guest reaches HC_RELEASE.
		 * Without this init, wait_for_completion returns immediately on
		 * the stale count from the boot run, causing GET_ITER_STATE to
		 * race against the vCPU's in-progress snapshot_restore.
		 */
		init_completion(&state->vcpu_run_done);
		smp_store_release(&state->vcpu_work_ready, true);
		wait_for_completion(&state->vcpu_run_done);

		if (state->vcpu_run_result < 0) {
			pr_err("phantom: RUN_ITERATION failed: %d\n",
			       state->vcpu_run_result);
			ret = state->vcpu_run_result;
			break;
		}

		ret = 0;
		break;
	}

	case PHANTOM_IOCTL_GET_RESULT: {
		/*
		 * GET_RESULT — retrieve status and crash_addr from last iter.
		 *
		 * Returns a snapshot of state->run_result and crash_addr.
		 * Safe to call after RUN_ITERATION completes.
		 */
		struct phantom_iter_result result;
		struct phantom_vmx_cpu_state *state;
		int target_cpu;

		target_cpu = phantom_file_cpu(fctx);
		if (target_cpu < 0) {
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		memset(&result, 0, sizeof(result));
		result.status     = (u32)state->run_result;
		result.crash_addr = state->crash_addr;

		if (copy_to_user((void __user *)arg, &result, sizeof(result)))
			ret = -EFAULT;
		break;
	}

	case PHANTOM_IOCTL_PT_GET_EVENTFD: {
		/*
		 * PT_GET_EVENTFD — create an eventfd for PT iteration
		 * notification and store a reference in state->pt.eventfd.
		 *
		 * After each iteration, phantom_pt_iteration_reset() signals
		 * the eventfd (writes 1), unblocking userspace epoll/read.
		 *
		 * Kernel-internal pattern for creating an eventfd from kernel
		 * module code (Linux 5.x / 6.x):
		 *   1. eventfd_ctx_fdget(fd) — but we need an fd first.
		 *   2. Use eventfd_file_create() + get_unused_fd_flags() to
		 *      create the fd in the current process's file table.
		 *
		 * eventfd_file_create() is not exported; the standard
		 * kernel-space approach is to use do_eventfd() (available in
		 * recent kernels) or to use the ksys_eventfd2() wrapper.
		 *
		 * On Linux 6.8+, the correct approach is:
		 *   struct file *f = eventfd_file_create(0, EFD_CLOEXEC);
		 *   efd = get_unused_fd_flags(O_CLOEXEC);
		 *   fd_install(efd, f);
		 *   ctx = eventfd_ctx_fileget(f);
		 *
		 * Since eventfd_file_create may not be available as a symbol,
		 * we use the exported eventfd_ctx_fdget() after creating the
		 * eventfd via sys_eventfd2 indirectly.
		 *
		 * Simplest correct approach: anon_inode_getfd + eventfd_ctx.
		 * We accept an existing fd from userspace (passed via arg),
		 * get the ctx, and store it.  Userspace creates the eventfd
		 * and passes the fd number to this ioctl.
		 *
		 * This is the standard KVM approach for irqfd registration.
		 */
		struct phantom_vmx_cpu_state *state;
		struct eventfd_ctx *ctx;
		int target_cpu;
		int user_fd;

		/*
		 * arg is the eventfd file descriptor created by userspace
		 * via eventfd(0, EFD_CLOEXEC).  We get the ctx from it.
		 */
		user_fd = (int)arg;

		target_cpu = phantom_file_cpu(fctx);
		if (target_cpu < 0) {
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		if (!state->pt.pt_enabled) {
			pr_err("phantom: PT_GET_EVENTFD: Intel PT not "
			       "available on CPU%d\n", target_cpu);
			ret = -EINVAL;
			break;
		}

		/*
		 * Get the eventfd_ctx from the userspace-provided fd.
		 * eventfd_ctx_fdget() increments the context refcount and
		 * verifies the fd refers to an eventfd file.
		 * We hold this reference until pt_teardown or the next
		 * PT_GET_EVENTFD call.
		 */
		ctx = eventfd_ctx_fdget(user_fd);
		if (IS_ERR(ctx)) {
			pr_err("phantom: PT_GET_EVENTFD: fd %d is not "
			       "an eventfd\n", user_fd);
			ret = PTR_ERR(ctx);
			break;
		}

		/* Release any previous eventfd reference */
		if (state->pt.eventfd) {
			eventfd_ctx_put(state->pt.eventfd);
			state->pt.eventfd = NULL;
		}

		state->pt.eventfd = ctx;

		pr_info("phantom: CPU%d: PT eventfd registered (user_fd=%d)\n",
			target_cpu, user_fd);

		ret = 0;
		break;
	}

	/* ----------------------------------------------------------
	 * Task 2.3: Production ioctl API
	 * ---------------------------------------------------------- */

	case PHANTOM_CREATE_VM: {
		/*
		 * PHANTOM_CREATE_VM — initialise a VM instance.
		 *
		 * Phantom is currently single-instance (one VM per module
		 * load).  Validate pinned_cpu, call vmcs_setup(), return
		 * instance_id=0.
		 */
		struct phantom_create_args args;
		struct phantom_vmx_cpu_state *state;
		int target_cpu;

		if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
			ret = -EFAULT;
			break;
		}

		/* Find the requested CPU in the VMX cpumask */
		if (args.pinned_cpu == 0) {
			/* pinned_cpu=0 means "any" — use first available */
			target_cpu = cpumask_first(pdev->vmx_cpumask);
		} else if (cpumask_test_cpu((int)args.pinned_cpu,
					    pdev->vmx_cpumask)) {
			target_cpu = (int)args.pinned_cpu;
		} else {
			/* pinned_cpu not in VMX cpumask — fall back to first */
			target_cpu = cpumask_first(pdev->vmx_cpumask);
		}

		if (target_cpu < 0) {
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		if (!state->vcpu_thread) {
			pr_err("phantom: CREATE_VM: vCPU thread not running\n");
			ret = -ENXIO;
			break;
		}

		ret = phantom_vmcs_setup(state);
		if (ret) {
			pr_err("phantom: CREATE_VM: vmcs_setup failed: %ld\n",
			       ret);
			break;
		}

		/* Bind this fd to the selected CPU for all subsequent ioctls */
		fctx->bound_cpu = target_cpu;

		args.instance_id = 0;
		if (copy_to_user((void __user *)arg, &args, sizeof(args)))
			ret = -EFAULT;
		break;
	}

	case PHANTOM_LOAD_TARGET: {
		/*
		 * PHANTOM_LOAD_TARGET — copy a binary from userspace into
		 * guest EPT RAM at the specified GPA.
		 *
		 * args.gpa          — target guest physical address
		 * args.userspace_ptr — source buffer in userspace
		 * args.size          — byte count (may span multiple pages)
		 *
		 * The binary is written page by page using
		 * phantom_ept_get_ram_page() so it works for arbitrarily
		 * large binaries (up to 16MB EPT RAM).
		 *
		 * Legacy behaviour (gpa == 0): write into shared_mem->payload
		 * (max PHANTOM_PAYLOAD_MAX bytes) for compatibility with the
		 * task 2.3 payload-only interface.
		 */
		struct phantom_load_args args;
		struct phantom_vmx_cpu_state *state;
		int target_cpu;

		if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
			ret = -EFAULT;
			break;
		}

		target_cpu = phantom_file_cpu(fctx);
		if (target_cpu < 0) {
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		if (args.gpa == 0) {
			/* Legacy: write into shared_mem payload buffer */
			struct phantom_shared_mem *sm;

			if (args.size > PHANTOM_PAYLOAD_MAX) {
				ret = -EINVAL;
				break;
			}
			if (!state->shared_mem) {
				ret = -ENXIO;
				break;
			}
			sm = (struct phantom_shared_mem *)state->shared_mem;
			if (copy_from_user(sm->payload,
					   (void __user *)(uintptr_t)
					   args.userspace_ptr,
					   (size_t)args.size)) {
				ret = -EFAULT;
				break;
			}
			sm->payload_len = (u32)args.size;
		} else {
			/*
			 * EPT RAM load: scatter the binary page by page.
			 * Supports binaries larger than PHANTOM_PAYLOAD_MAX.
			 */
			u64 gpa = args.gpa;
			u64 remaining = args.size;
			u8 __user *uptr = (u8 __user *)(uintptr_t)
						args.userspace_ptr;

			if (gpa + remaining > PHANTOM_EPT_RAM_END) {
				ret = -EINVAL;
				break;
			}

			while (remaining > 0) {
				struct page *pg;
				u8 *kva;
				u64 page_off = gpa & (PAGE_SIZE - 1);
				u64 chunk = PAGE_SIZE - page_off;
				u64 copy_len;

				if (chunk > remaining)
					chunk = remaining;
				copy_len = chunk;

				pg = phantom_ept_get_ram_page(&state->ept,
							      gpa);
				if (!pg) {
					ret = -ERANGE;
					break;
				}

				kva = (u8 *)page_address(pg) + page_off;
				if (copy_from_user(kva, uptr,
						   (size_t)copy_len)) {
					ret = -EFAULT;
					break;
				}

				gpa       += copy_len;
				uptr      += copy_len;
				remaining -= copy_len;
			}
		}
		break;
	}

	case PHANTOM_SET_SNAPSHOT: {
		/*
		 * PHANTOM_SET_SNAPSHOT — alias for PHANTOM_IOCTL_SNAPSHOT_CREATE.
		 *
		 * Captures current guest state as the snapshot point and
		 * marks all RAM EPT pages read-only for CoW protection.
		 * Must be called after at least one VMLAUNCH (RUN_GUEST
		 * with test_id=8 or kAFL ACQUIRE hypercall).
		 */
		int target_cpu = -1;
		struct phantom_vmx_cpu_state *state;

		target_cpu = phantom_file_cpu(fctx);

		if (target_cpu < 0) {
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		if (!state->pages_allocated || !state->vmcs_configured) {
			pr_err("phantom: SET_SNAPSHOT: not ready "
			       "(pages=%d vmcs=%d)\n",
			       state->pages_allocated,
			       state->vmcs_configured);
			ret = -EINVAL;
			break;
		}

		if (!state->vcpu_thread) {
			ret = -ENXIO;
			break;
		}

		state->vcpu_run_request = 4;
		smp_store_release(&state->vcpu_work_ready, true);
		wait_for_completion(&state->vcpu_run_done);

		if (state->vcpu_run_result < 0) {
			ret = state->vcpu_run_result;
		} else {
			state->snap_taken = true;
			pr_info("phantom: CPU%d: SET_SNAPSHOT done "
				"(rip=0x%llx)\n",
				target_cpu, state->snap.rip);
		}
		break;
	}

	case PHANTOM_RUN_ITERATION: {
		/*
		 * PHANTOM_RUN_ITERATION (new API) — run one fuzzing iteration.
		 *
		 * Accepts a struct phantom_run_args2 with an explicit
		 * payload pointer and size.  Copies payload into shared_mem,
		 * then runs one iteration via vcpu_run_request=6.
		 */
		struct phantom_run_args2 args2;
		struct phantom_vmx_cpu_state *state;
		struct phantom_shared_mem *sm;
		int target_cpu;

		if (copy_from_user(&args2, (void __user *)arg, sizeof(args2))) {
			ret = -EFAULT;
			break;
		}

		if (args2.payload_size > PHANTOM_PAYLOAD_MAX) {
			pr_err("phantom: RUN_ITERATION: payload_size=%u > MAX=%u\n",
			       args2.payload_size, PHANTOM_PAYLOAD_MAX);
			ret = -EINVAL;
			break;
		}

		target_cpu = phantom_file_cpu(fctx);
		if (target_cpu < 0) {
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		if (!state->pages_allocated) {
			ret = -ENXIO;
			break;
		}

		if (!state->snap_acquired) {
			pr_err("phantom: RUN_ITERATION: snap_acquired=false "
			       "cpu=%d pages=%d\n",
			       target_cpu, state->pages_allocated);
			ret = -EINVAL;
			break;
		}

		if (!state->vcpu_thread) {
			ret = -ENXIO;
			break;
		}

		sm = (struct phantom_shared_mem *)state->shared_mem;

		/* Copy payload from userspace into shared memory */
		if (args2.payload_size && args2.payload_ptr) {
			if (copy_from_user(sm->payload,
				(void __user *)(uintptr_t)args2.payload_ptr,
				(size_t)args2.payload_size)) {
				ret = -EFAULT;
				break;
			}
		}

		sm->payload_len = args2.payload_size;

		state->run_result      = PHANTOM_RESULT_OK;
		state->run_result_data = 0;
		state->crash_addr      = 0;
		state->snap_continue   = true;
		state->vcpu_run_request = 6;

		smp_store_release(&state->vcpu_work_ready, true);
		wait_for_completion(&state->vcpu_run_done);

		if (state->vcpu_run_result < 0) {
			ret = state->vcpu_run_result;
			break;
		}

		/* Fill out result fields */
		args2.result      = (u32)state->run_result;
		args2.exit_reason = state->exit_reason & 0xFFFF;
		args2.checksum    = state->run_result_data;

		if (copy_to_user((void __user *)arg, &args2, sizeof(args2)))
			ret = -EFAULT;
		break;
	}

	case PHANTOM_GET_STATUS: {
		/*
		 * PHANTOM_GET_STATUS — return current instance status.
		 */
		struct phantom_status st;
		struct phantom_vmx_cpu_state *state;
		int target_cpu;

		target_cpu = phantom_file_cpu(fctx);

		if (target_cpu < 0) {
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		memset(&st, 0, sizeof(st));
		st.result      = (u32)state->run_result;
		st.exit_reason = state->exit_reason & 0xFFFF;
		st.crash_addr  = state->crash_addr;
		st.checksum    = state->run_result_data;
		st.iterations  = 0; /* not tracked yet */

		if (copy_to_user((void __user *)arg, &st, sizeof(st)))
			ret = -EFAULT;
		break;
	}

	case PHANTOM_DESTROY_VM:
		/*
		 * PHANTOM_DESTROY_VM — no-op for now.
		 *
		 * Cleanup happens when the /dev/phantom fd is closed or
		 * the module is unloaded.  Return 0 to indicate success.
		 */
		ret = 0;
		break;

	case PHANTOM_IOCTL_BOOT_KERNEL: {
		/*
		 * PHANTOM_IOCTL_BOOT_KERNEL — load a Linux bzImage and
		 * configure a Class B guest.
		 *
		 * Process-context steps (done here):
		 *   1. Copy bzImage from userspace.
		 *   2. Allocate 256MB Class B EPT (GFP_KERNEL allowed).
		 *   3. Load kernel image + populate boot_params.
		 *   4. Set up MSR bitmap for Class B exits.
		 *   5. Initialise MSR shadow state.
		 *
		 * vCPU-thread step (via vcpu_run_request=7):
		 *   6. Write VMCS guest-state for 64-bit Linux boot.
		 *
		 * Step 6 must run on the vCPU thread because VMWRITE
		 * requires the target VMCS to be current (VMPTRLD'd)
		 * on the executing CPU.
		 */
		struct phantom_boot_kernel_args bk_args;
		struct phantom_vmx_cpu_state *state;
		int target_cpu;
		bool was_launched;
		void *buf;

		if (copy_from_user(&bk_args, (void __user *)arg,
				   sizeof(bk_args))) {
			ret = -EFAULT;
			break;
		}

		if (bk_args.bzimage_size == 0 ||
		    bk_args.bzimage_size > PHANTOM_MAX_BZIMAGE_SIZE) {
			ret = -EINVAL;
			break;
		}

		/* Resolve target CPU */
		if (bk_args.cpu == 0) {
			target_cpu = cpumask_first(pdev->vmx_cpumask);
		} else if (cpumask_test_cpu((int)bk_args.cpu,
					    pdev->vmx_cpumask)) {
			target_cpu = (int)bk_args.cpu;
		} else {
			target_cpu = cpumask_first(pdev->vmx_cpumask);
		}

		if (target_cpu < 0) {
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		if (!state->vcpu_thread) {
			ret = -ENXIO;
			break;
		}

		buf = vmalloc(bk_args.bzimage_size);
		if (!buf) {
			ret = -ENOMEM;
			break;
		}

		if (copy_from_user(buf,
				   (void __user *)(uintptr_t)bk_args.bzimage_uaddr,
				   (size_t)bk_args.bzimage_size)) {
			vfree(buf);
			ret = -EFAULT;
			break;
		}

		/* Free any existing Class B EPT */
		if (state->class_b)
			phantom_ept_free_class_b(state);

		state->class_b     = true;
		state->guest_mem_mb = bk_args.guest_mem_mb ? bk_args.guest_mem_mb : 256;

		/*
		 * Check state->vcpu_phase2 (set by vCPU thread on ANY VM entry
		 * attempt — even a failed one).  This is more reliable than
		 * state->launched which we are about to reset to false.
		 * If vcpu_phase2 is true the thread is in Phase 2 busy-wait;
		 * use the IPI-free wakeup.  Otherwise Phase 1 (safe to sleep).
		 */
		was_launched = READ_ONCE(state->vcpu_phase2);
		state->launched       = false;
		state->vmcs_configured = false;

		/*
		 * Step 1b: Allocate Class A infrastructure (MSR bitmap, CoW
		 * pool, XSAVE area, IO bitmaps) via phantom_vmcs_setup().
		 * This is idempotent if already called; for a fresh fd it
		 * allocates the resources that phantom_vmcs_configure_fields()
		 * expects (MSR bitmap, CoW pool, etc.).
		 *
		 * The Class A 16MB EPT allocated here is overridden by
		 * phantom_ept_alloc_class_b() below which writes the 256MB
		 * Class B EPTP into state->ept.eptp.
		 */
		ret = phantom_vmcs_setup(state);
		if (ret) {
			vfree(buf);
			state->class_b = false;
			break;
		}

		/* Step 2: Allocate 256MB EPT (overwrites state->ept.eptp) */
		ret = phantom_ept_alloc_class_b(state);
		if (ret) {
			vfree(buf);
			state->class_b = false;
			break;
		}

		/* Step 3: Load kernel image + build boot structures */
		ret = phantom_load_kernel_image(state, buf,
						(size_t)bk_args.bzimage_size);
		vfree(buf);
		if (ret) {
			phantom_ept_free_class_b(state);
			state->class_b = false;
			break;
		}

		/* Step 4: Configure MSR bitmap for Class B exits */
		if (state->msr_bitmap)
			phantom_msr_bitmap_setup_class_b(
				page_address(state->msr_bitmap));

		/* Step 5: Initialise MSR shadow state */
		phantom_msr_state_init(state);

		/* Step 6: Write VMCS guest-state (must run on vCPU thread) */
		init_completion(&state->vcpu_run_done);
		state->vcpu_run_request = 7;
		/*
		 * Use was_launched (saved before the reset above) to determine
		 * which wakeup path to use.  The vCPU thread's local
		 * vmlaunch_done flag mirrors was_launched: if was_launched is
		 * true the thread is in Phase 2 busy-wait; if false it is in
		 * Phase 1 sleeping on vcpu_run_start.
		 */
		if (was_launched)
			smp_store_release(&state->vcpu_work_ready, true);
		else
			complete(&state->vcpu_run_start);
		wait_for_completion(&state->vcpu_run_done);
		ret = state->vcpu_run_result;
		if (ret)
			break;

		/* Bind fd to this CPU for subsequent ioctls */
		fctx->bound_cpu = target_cpu;

		/*
		 * Step 7: Launch the guest kernel.
		 *
		 * After step 6 completes, the thread loops back.  If
		 * was_launched was true (Phase 2 before reset), the thread
		 * stays in Phase 2 busy-wait — use IPI-free wakeup.
		 * If was_launched was false (first boot, Phase 1), the
		 * thread is sleeping — use complete().
		 *
		 * The ioctl returns immediately; boot is asynchronous.
		 */
		init_completion(&state->vcpu_run_done);
		state->vcpu_run_request = 1;   /* run guest, no reset */
		if (was_launched)
			smp_store_release(&state->vcpu_work_ready, true);
		else
			complete(&state->vcpu_run_start);
		/* Return immediately — boot is asynchronous */
		ret = 0;
		break;
	}

	case PHANTOM_IOCTL_GET_ITER_STATE: {
		/*
		 * GET_ITER_STATE — read per-iteration state for determinism
		 * testing.
		 *
		 * Returns guest GPRs, VMCS-sourced registers (RIP, RFLAGS,
		 * CR3 cached at HC_RELEASE time), the dirty GPA list, TSS
		 * verification results, and the run result.
		 *
		 * This ioctl must be called after RUN_ITERATION completes.
		 * All fields are populated by the HC_RELEASE/PANIC/KASAN
		 * handlers in VMX-root context.
		 */
		struct phantom_iter_state *istate;
		struct phantom_vmx_cpu_state *state;
		int target_cpu;
		u32 dc;

		target_cpu = phantom_file_cpu(fctx);
		if (target_cpu < 0) {
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		/*
		 * Allocate on heap — struct is >32KB (4096 u64 dirty_gpas)
		 * and must not be placed on the kernel stack.
		 */
		istate = kzalloc(sizeof(*istate), GFP_KERNEL);
		if (!istate) {
			ret = -ENOMEM;
			break;
		}

		/* GPRs saved by the VM exit handler (not VMCS-sourced) */
		istate->rax = state->guest_regs.rax;
		istate->rbx = state->guest_regs.rbx;
		istate->rcx = state->guest_regs.rcx;
		istate->rdx = state->guest_regs.rdx;
		istate->rsi = state->guest_regs.rsi;
		istate->rdi = state->guest_regs.rdi;
		istate->rsp = state->last_guest_rsp;
		istate->rbp = state->guest_regs.rbp;
		istate->r8  = state->guest_regs.r8;
		istate->r9  = state->guest_regs.r9;
		istate->r10 = state->guest_regs.r10;
		istate->r11 = state->guest_regs.r11;
		istate->r12 = state->guest_regs.r12;
		istate->r13 = state->guest_regs.r13;
		istate->r14 = state->guest_regs.r14;
		istate->r15 = state->guest_regs.r15;

		/*
		 * RIP/RFLAGS/CR3 cached at HC_RELEASE time from VMCS
		 * (cannot be read here — not in VMX-root context).
		 */
		istate->rip    = state->last_guest_rip;
		istate->rflags = state->last_guest_rflags;
		istate->cr3    = state->last_guest_cr3;

		/*
		 * Dirty page list — use last_dirty_count (populated before
		 * phantom_cow_abort_iteration() resets dirty_count to 0).
		 */
		dc = state->last_dirty_count;
		if (dc > PHANTOM_MAX_DIRTY_PAGES)
			dc = PHANTOM_MAX_DIRTY_PAGES;
		istate->dirty_count = dc;

		if (dc && state->dirty_list) {
			u32 i;

			for (i = 0; i < dc; i++)
				istate->dirty_gpas[i] = state->dirty_list[i].gpa;
		}

		/* TSS verification */
		istate->tss_verified      = state->tss_dirty_verified ? 1 : 0;
		istate->tss_rsp0_snapshot = state->tss_rsp0_snapshot;
		istate->tss_rsp0_restored = state->tss_rsp0_restored;

		/* Run result */
		istate->run_result = (u32)state->run_result;

		if (copy_to_user((void __user *)arg, istate, sizeof(*istate)))
			ret = -EFAULT;

		kfree(istate);
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

/* ------------------------------------------------------------------
 * mmap support — map shared_mem, coverage bitmap, and PT ToPA buffers.
 *
 * Five regions are supported, selected by the mmap offset:
 *
 *   PHANTOM_MMAP_PAYLOAD / PHANTOM_MMAP_SHARED_MEM (0x00000):
 *     struct phantom_shared_mem (payload[64KB] + status + crash_addr).
 *     Mapped RW — userspace writes payload[] before RUN_ITERATION.
 *
 *   PHANTOM_MMAP_BITMAP (0x10000):
 *     AFL++ coverage bitmap (Phase 3; currently maps shared_mem RO
 *     as a placeholder until bitmap has its own allocation).
 *     Mapped RO — VM_WRITE cleared.
 *
 *   PHANTOM_MMAP_TOPA_BUF_A (0x20000):
 *     PT output buffer slot 0.  Mapped RO via vm_insert_page().
 *     Legacy offset 0x10000 also accepted for backwards compatibility.
 *
 *   PHANTOM_MMAP_TOPA_BUF_B (0x30000):
 *     PT output buffer slot 1.  Mapped RO via vm_insert_page().
 *     Legacy offset 0x20000 also accepted for backwards compatibility.
 *
 *   PHANTOM_MMAP_STATUS (0x40000):
 *     Read-only status page (first page of shared_mem, RO view).
 *     Mapped RO — VM_WRITE cleared.
 *
 * Any other offset returns -EINVAL.
 * ------------------------------------------------------------------ */

static int phantom_mmap_topa(struct vm_area_struct *vma,
			     struct phantom_pt_state *pt, int slot)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long topa_size = (unsigned long)pt->topa_page_count[slot] *
				  PAGE_SIZE;
	unsigned long addr = vma->vm_start;
	int i;
	int err;

	if (!pt->pt_enabled || !pt->topa_page_count[slot])
		return -EINVAL;

	if (size > topa_size)
		return -EINVAL;

	/*
	 * Map each PT output page individually using vm_insert_page().
	 * The pages are not necessarily physically contiguous, so we
	 * cannot use remap_pfn_range() with a single base PFN.
	 *
	 * vm_insert_page() requires VM_MIXEDMAP (set before the loop).
	 * Pages must have page_count >= 1 (they do — freshly allocated).
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP |
		     VM_MIXEDMAP);
	vm_flags_clear(vma, VM_WRITE);
#else
	vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP | VM_MIXEDMAP;
	vma->vm_flags &= ~VM_WRITE;
#endif

	for (i = 0; i < pt->topa_page_count[slot] &&
	     addr < vma->vm_end; i++, addr += PAGE_SIZE) {
		err = vm_insert_page(vma, addr, pt->topa_pages[slot][i]);
		if (err) {
			pr_err("phantom: mmap ToPA slot%d page%d failed: %d\n",
			       slot, i, err);
			return err;
		}
	}

	return 0;
}

/*
 * phantom_mmap_shared_ro - Map the shared_mem region read-only.
 *
 * Used for PHANTOM_MMAP_BITMAP and PHANTOM_MMAP_STATUS — both expose
 * a read-only view of the shared memory pages.  VM_WRITE is cleared
 * before calling remap_pfn_range so userspace gets a read-only mapping.
 */
static int phantom_mmap_shared_ro(struct vm_area_struct *vma,
				  struct phantom_vmx_cpu_state *state,
				  unsigned long max_size)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;

	if (!state->shared_mem_pages)
		return -EINVAL;

	if (size > max_size)
		return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);
	vm_flags_clear(vma, VM_WRITE);
#else
	vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_flags &= ~VM_WRITE;
#endif

	pfn = page_to_pfn(state->shared_mem_pages);
	return remap_pfn_range(vma, vma->vm_start, pfn, size,
			       vma->vm_page_prot);
}

static int phantom_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct phantom_file *fctx = filp->private_data;
	struct phantom_dev *pdev;
	struct phantom_vmx_cpu_state *state;
	int target_cpu;
	unsigned long offset;
	unsigned long size;
	unsigned long pfn;

	if (!fctx)
		return -ENXIO;
	pdev = fctx->pdev;
	if (!pdev || !pdev->initialized)
		return -ENXIO;

	target_cpu = phantom_file_cpu(fctx);
	if (target_cpu < 0)
		return -ENODEV;

	state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

	if (!state->pages_allocated)
		return -EINVAL;

	/*
	 * Use the mmap page offset to select which region to map.
	 * vma->vm_pgoff is in pages; convert to bytes for comparison.
	 */
	offset = vma->vm_pgoff << PAGE_SHIFT;
	size   = vma->vm_end - vma->vm_start;

	if (offset == PHANTOM_MMAP_PAYLOAD) {
		/*
		 * PHANTOM_MMAP_PAYLOAD (0x00000) — payload buffer, RW.
		 * Alias: PHANTOM_MMAP_SHARED_MEM.
		 *
		 * Maps struct phantom_shared_mem in full.
		 * Userspace writes payload[] before each RUN_ITERATION.
		 * VM_WRITE is kept (default).
		 */
		if (!state->shared_mem_pages)
			return -EINVAL;

		if (size > (PAGE_SIZE << state->shared_mem_order))
			return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);
#else
		vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP;
#endif

		pfn = page_to_pfn(state->shared_mem_pages);
		return remap_pfn_range(vma, vma->vm_start, pfn, size,
				       vma->vm_page_prot);

	} else if (offset == PHANTOM_MMAP_BITMAP) {
		/*
		 * PHANTOM_MMAP_BITMAP (0x10000) — coverage bitmap, RO.
		 *
		 * Phase 3 will allocate a dedicated 64KB bitmap buffer.
		 * For now, map the shared_mem region read-only as a stub
		 * so that userspace can map this offset without error.
		 * Size is limited to PHANTOM_PAYLOAD_MAX (64KB).
		 *
		 * Legacy: old TOPA_BUF_A offset (0x10000) is handled here.
		 * If PT is enabled and the caller maps 0x10000 expecting
		 * the PT buffer (task 2.2 behaviour), try topa slot 0.
		 * Determine by checking whether PT is active.
		 */
		if (state->pt.pt_enabled && state->pt.topa_page_count[0]) {
			/*
			 * Legacy path: task 2.2 test binaries map 0x10000
			 * to get PT buffer A.  Honour that for backwards
			 * compatibility.
			 */
			return phantom_mmap_topa(vma, &state->pt, 0);
		}
		return phantom_mmap_shared_ro(vma, state, PHANTOM_PAYLOAD_MAX);

	} else if (offset == PHANTOM_MMAP_TOPA_BUF_A) {
		/*
		 * PHANTOM_MMAP_TOPA_BUF_A (0x20000) — PT buffer A, RO.
		 * Also handles legacy offset PHANTOM_MMAP_TOPA_BUF_B_LEGACY
		 * (0x20000 was old TOPA_BUF_B in task 2.2).
		 */
		return phantom_mmap_topa(vma, &state->pt, 0);

	} else if (offset == PHANTOM_MMAP_TOPA_BUF_B) {
		/*
		 * PHANTOM_MMAP_TOPA_BUF_B (0x30000) — PT buffer B, RO.
		 */
		return phantom_mmap_topa(vma, &state->pt, 1);

	} else if (offset == PHANTOM_MMAP_STATUS) {
		/*
		 * PHANTOM_MMAP_STATUS (0x40000) — status struct, RO.
		 *
		 * Maps one page of shared_mem read-only.  Userspace can
		 * poll the status word without calling GET_RESULT ioctl.
		 */
		return phantom_mmap_shared_ro(vma, state, PAGE_SIZE);

	} else {
		pr_err("phantom: mmap: invalid offset 0x%lx "
		       "(valid: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
		       offset,
		       PHANTOM_MMAP_PAYLOAD, PHANTOM_MMAP_BITMAP,
		       PHANTOM_MMAP_TOPA_BUF_A, PHANTOM_MMAP_TOPA_BUF_B,
		       PHANTOM_MMAP_STATUS);
		return -EINVAL;
	}
}

static const struct file_operations phantom_fops = {
	.owner          = THIS_MODULE,
	.open           = phantom_open,
	.release        = phantom_release,
	.unlocked_ioctl = phantom_ioctl,
	.mmap           = phantom_mmap,
};

/* ------------------------------------------------------------------
 * Chardev registration / unregistration
 * ------------------------------------------------------------------ */

/**
 * phantom_chardev_register - Register the /dev/phantom chardev.
 * @pdev: Device context; cdev, class, and devno are populated.
 *
 * Returns 0 on success, negative errno on failure.
 */
int phantom_chardev_register(struct phantom_dev *pdev)
{
	int ret;

	ret = alloc_chrdev_region(&pdev->devno, 0, 1, PHANTOM_DEVICE_NAME);
	if (ret) {
		pr_err("phantom: failed to allocate chardev region: %d\n", ret);
		return ret;
	}

	cdev_init(&pdev->cdev, &phantom_fops);
	pdev->cdev.owner = THIS_MODULE;

	ret = cdev_add(&pdev->cdev, pdev->devno, 1);
	if (ret) {
		pr_err("phantom: cdev_add failed: %d\n", ret);
		goto fail_cdev;
	}

	pdev->class = phantom_class_create(PHANTOM_CLASS_NAME);
	if (IS_ERR(pdev->class)) {
		ret = PTR_ERR(pdev->class);
		pr_err("phantom: class_create failed: %d\n", ret);
		pdev->class = NULL;
		goto fail_class;
	}

	{
		struct device *dev;

		dev = device_create(pdev->class, NULL, pdev->devno,
				    NULL, PHANTOM_DEVICE_NAME);
		if (IS_ERR(dev)) {
			ret = PTR_ERR(dev);
			pr_err("phantom: device_create failed: %d\n", ret);
			goto fail_device;
		}
	}

	pr_info("phantom: chardev registered as /dev/%s (major=%d)\n",
		PHANTOM_DEVICE_NAME, MAJOR(pdev->devno));
	return 0;

fail_device:
	class_destroy(pdev->class);
	pdev->class = NULL;
fail_class:
	cdev_del(&pdev->cdev);
fail_cdev:
	unregister_chrdev_region(pdev->devno, 1);
	return ret;
}

/**
 * phantom_chardev_unregister - Remove the /dev/phantom chardev.
 * @pdev: Device context.
 */
void phantom_chardev_unregister(struct phantom_dev *pdev)
{
	if (pdev->class) {
		device_destroy(pdev->class, pdev->devno);
		class_destroy(pdev->class);
		pdev->class = NULL;
	}

	cdev_del(&pdev->cdev);
	unregister_chrdev_region(pdev->devno, 1);

	pr_info("phantom: chardev unregistered\n");
}
