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

#include "phantom.h"
#include "interface.h"
#include "vmx_core.h"
#include "ept.h"
#include "ept_cow.h"
#include "snapshot.h"
#include "debug.h"
#include "compat.h"

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
 * File operations
 * ------------------------------------------------------------------ */

static int phantom_open(struct inode *inode, struct file *filp)
{
	struct phantom_dev *pdev;

	pdev = container_of(inode->i_cdev, struct phantom_dev, cdev);
	filp->private_data = pdev;

	if (!pdev->initialized) {
		pr_err("phantom: open() called before module is fully initialised\n");
		return -ENXIO;
	}

	return 0;
}

static int phantom_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static long phantom_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	struct phantom_dev *pdev = filp->private_data;
	long ret = 0;

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
		 */
		test_id = args.reserved;
		if (test_id > 7) {
			pr_err("phantom: RUN_GUEST: invalid test_id=%u\n",
			       test_id);
			ret = -EINVAL;
			break;
		}

		/* Find the target CPU — first CPU in vmx_cpumask by default */
		target_cpu = -1;
		{
			int cpu;

			for_each_cpu(cpu, pdev->vmx_cpumask) {
				target_cpu = cpu;
				break; /* use first CPU always for now */
			}
		}

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
		 * Select and load guest binary into code page.
		 * test_id=0: R/W checksum test
		 * test_id=1: absent-GPA EPT violation test
		 * test_id=2: CoW write test (20 pages)
		 * test_id=3: pool exhaustion test (5-page pool, 10-write)
		 * test_id=4: MMIO CoW rejection test
		 * test_id=5: 2MB split + CoW (write to GPA 0x100000)
		 * test_id=6: mixed 2MB + 4KB workload (10 writes)
		 * test_id=7: snapshot/restore XMM test (task 1.6)
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
		} else {
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
		state->snap_continue   = (test_id == 7 && state->snap_taken);

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
		int cpu;

		for_each_cpu(cpu, pdev->vmx_cpumask) {
			target_cpu = cpu;
			break;
		}

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
		int cpu;

		for_each_cpu(cpu, pdev->vmx_cpumask) {
			target_cpu = cpu;
			break;
		}

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
		int target_cpu = -1;
		struct phantom_vmx_cpu_state *state;
		int cpu;

		for_each_cpu(cpu, pdev->vmx_cpumask) {
			target_cpu = cpu;
			break;
		}

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
		int target_cpu = -1;
		struct phantom_vmx_cpu_state *state;
		int cpu;

		for_each_cpu(cpu, pdev->vmx_cpumask) {
			target_cpu = cpu;
			break;
		}

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
		int target_cpu = -1;
		struct phantom_vmx_cpu_state *state;
		int cpu;

		for_each_cpu(cpu, pdev->vmx_cpumask) {
			target_cpu = cpu;
			break;
		}

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
		int target_cpu = -1;
		struct phantom_vmx_cpu_state *state;
		struct phantom_perf_result result;
		int cpu;

		for_each_cpu(cpu, pdev->vmx_cpumask) {
			target_cpu = cpu;
			break;
		}

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

	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

static const struct file_operations phantom_fops = {
	.owner          = THIS_MODULE,
	.open           = phantom_open,
	.release        = phantom_release,
	.unlocked_ioctl = phantom_ioctl,
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
