/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vmx_trampoline.S — VMLAUNCH/VMRESUME assembly trampoline for phantom.ko
 *
 * C prototype:
 *   int phantom_vmlaunch_trampoline(struct phantom_vmx_cpu_state *state);
 *
 * System V AMD64 ABI: RDI = state pointer on entry.
 * Returns: 0 on VM exit (success), -EIO (-5) on VM-entry failure.
 *
 * Stack frame layout (from bottom of frame, growing downward):
 *   [rsp+0]  = return value slot (0 = success, -5 = failure)
 *   [rsp+8]  = saved state pointer (RDI at entry)
 *   [rsp+16] = saved R15
 *   [rsp+24] = saved R14
 *   [rsp+32] = saved R13
 *   [rsp+40] = saved R12
 *   [rsp+48] = saved RBP
 *   [rsp+56] = saved RBX
 *   [rsp+64] = return address (from caller)
 *
 * On VM exit, the CPU jumps to phantom_vm_exit_return with RSP restored
 * to the value we set in VMCS HOST_RSP (the address of [rsp+0] above).
 *
 * Offsets into struct phantom_vmx_cpu_state:
 *   All offsets match the struct layout in vmx_core.h.
 *   If the struct changes, these offsets MUST be updated.
 *
 * VMCS field encodings (from vmx_core.h):
 *   VMCS_HOST_RSP = 0x6C14
 *   VMCS_HOST_RIP = 0x6C16
 *   VMCS_RO_VM_INSTR_ERROR = 0x4400
 *   VMCS_GUEST_RIP = 0x681E
 */

#include <linux/linkage.h>
#include <asm/asm.h>

/* VMCS field encodings */
#define VMCS_HOST_RSP		0x6C14
#define VMCS_HOST_RIP		0x6C16
#define VMCS_RO_VM_INSTR_ERROR	0x4400

/*
 * Offsets into struct phantom_vmx_cpu_state.
 * Must match the C struct layout exactly.
 *
 * struct layout (in order):
 *   vmxon_region   (8B) @ 0
 *   vmcs_region    (8B) @ 8
 *   vmx_active     (1B) @ 16
 *   saved_cr4      (8B) @ 24   (aligned to 8)
 *   cpu            (4B) @ 32
 *   init_err       (4B) @ 36
 *   msr_bitmap     (8B) @ 40   (ptr, aligned)
 *   ept_pml4       (8B) @ 48
 *   ept_pdpt       (8B) @ 56
 *   ept_pd         (8B) @ 64
 *   ept_pt         (8B) @ 72
 *   guest_code_page(8B) @ 80
 *   guest_stack_page(8B)@ 88
 *   guest_data_page(8B) @ 96
 *   guest_pml4_page(8B) @ 104
 *   guest_pdpt_page(8B) @ 112
 *   guest_pd_page  (8B) @ 120
 *   guest_regs:          @ 128
 *     rax  (8B) @ 128
 *     rbx  (8B) @ 136
 *     rcx  (8B) @ 144
 *     rdx  (8B) @ 152
 *     rsi  (8B) @ 160
 *     rdi  (8B) @ 168
 *     rbp  (8B) @ 176
 *     r8   (8B) @ 184
 *     r9   (8B) @ 192
 *     r10  (8B) @ 200
 *     r11  (8B) @ 208
 *     r12  (8B) @ 216
 *     r13  (8B) @ 224
 *     r14  (8B) @ 232
 *     r15  (8B) @ 240
 *   exit_reason    (4B) @ 248
 *   exit_qual      (8B) @ 256  (aligned to 8)
 *   vm_instr_error (4B) @ 264
 *   run_result     (4B) @ 268
 *   run_result_data(8B) @ 272
 *   launched       (1B) @ 280
 *   vmcs_configured(1B) @ 281
 *   host_rsp       (8B) @ 288  (aligned to 8)
 *
 * NOTE: These offsets are computed by the C compiler based on alignment
 * rules. The values above are APPROXIMATE. The actual offsets must be
 * verified. In vmx_core.c we use offsetof() which is correct; here we
 * use hardcoded values which must match.
 *
 * To make this robust, we use a C file to export the offsets as
 * constants and use them here. For now we use the C version of the
 * trampoline (in vmx_core.c) and mark this file as a reference.
 *
 * The actual production trampoline is implemented as inline asm in
 * vmx_core.c using offsetof() for all struct member accesses.
 */

/*
 * phantom_vm_exit_return - VM exit landing pad.
 *
 * HOST_RIP is set to this address before VMLAUNCH/VMRESUME.
 * When a VM exit occurs, the CPU:
 *   1. Restores RSP from HOST_RSP (our saved host stack)
 *   2. Jumps here
 *
 * At this point:
 *   RSP = host RSP (points to our stack frame)
 *   All other GPRs = guest values (except those cleared by VM exit)
 *   [rsp+0]  = return value slot
 *   [rsp+8]  = state pointer
 *
 * We cannot implement the full trampoline here without knowing the
 * exact struct offsets at assembly time. The inline asm in vmx_core.c
 * uses offsetof() at compile time to embed the correct offsets.
 *
 * This file is kept as documentation. The actual trampoline function
 * phantom_vmlaunch_trampoline() is in vmx_core.c as inline asm.
 */
