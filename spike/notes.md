# Spike Notes — Task 0.1: VMX Feasibility Spike

**Date:** 2026-03-03
**Status:** Code written, pending build/test on phantom-bench

---

## Design Decisions

### 1. Identity-mapped EPT for guest code

The guest code (`guest_code_start`) is a kernel symbol living in the kernel
direct-map.  The simplest approach is an identity map: GPA = HPA = the physical
address of the kernel symbol.  This means the guest uses the same CR3 as the
host and can resolve virtual addresses normally through the two-level walk
(host page tables + EPT).

Alternative (separate guest RAM): allocate a dedicated page, copy guest_code
into it, and map it at GPA 0.  This is what a production hypervisor does.
Rejected for the spike: more setup, no additional learning value.

### 2. Stack GPA at 0x1000000 (16MB)

Chosen to be:
- Below the kernel image (avoids PML4 index conflicts with code GPA)
- Above the first 1MB (avoids legacy real-mode regions)
- Simple to reason about in the EPT walk

### 3. Exit stack vs. current RSP for HOST_RSP

HOST_RSP is set to the top of a dedicated 4KB page, not to the current RSP at
VMLAUNCH time.  This ensures the VM exit handler always has a known-clean stack
regardless of call depth.  The trampoline subtracts 8 before the C call to
maintain 16-byte ABI alignment.

### 4. Return from guest via saved RSP/RBP

Rather than implementing setjmp/longjmp properly, `spike_run_guest()` saves its
RSP and RBP into a per-CPU variable before VMLAUNCH.  After the guest exits,
`spike_maybe_resume()` restores those registers and executes `retq`, which
returns to the `spike_run_guest()` call site inside `spike_vmx_init_cpu()`.

This works because:
- The saved RSP points at the return address pushed by the call to
  `spike_run_guest()`.
- RBP is restored so the caller's frame pointer chain is intact.

A production hypervisor would save/restore all callee-saved registers (RBX,
R12–R15, RBP) and use a proper context-switch mechanism.

### 5. No VMRESUME loop

The spike runs the guest once, collects the two expected exits (VMCALL then EPT
violation), and terminates.  A production fuzzer would loop: VMRESUME after each
handled exit until `should_exit == true`.

### 6. TRUE_* capability MSRs

The code uses `MSR_IA32_VMX_TRUE_*` MSRs (0x48d–0x490) rather than the plain
MSRs (0x481–0x484).  The TRUE MSRs give more accurate allowed-0/allowed-1
information on processors that support "true" VMX control reporting (bit 55 of
IA32_VMX_BASIC).  On older hardware that lacks the TRUE MSRs, this will panic.
The spike target (Intel i7-6700) supports the TRUE MSRs.

---

## Expected Test Outcomes

| Test | Expected Result |
|------|----------------|
| `insmod spike.ko` | Module loads, VMXON succeeds, guest runs |
| VMCALL exit | dmesg: `spike: VMCALL exit #1 — guest RIP=0x...` |
| EPT violation | dmesg: `spike: EPT violation #2 — GPA=0xdead000` |
| `rmmod spike` | VMXOFF executed, module unloads cleanly |
| `insmod spike.ko trigger_panic=1` | BUG() fires, kdump captures vmcore |

---

## Findings (filled in 2026-03-03)

### VMXON result
- [x] CF=0, ZF=0 (success) — after rmmod kvm_intel in the guest

### VMLAUNCH result
- [x] Guest launched successfully (after HOST_TR_SEL encoding fix)
- Initial failure: VMLAUNCH instr_err=8 ("invalid control field") — caused by
  HOST_TR_SELECTOR encoded as 0x0c0e instead of the correct 0x0c0c.
  The vmwrite to field 0x0c0e silently failed (wrote to a reserved field),
  leaving HOST_TR_SELECTOR as 0 which triggered error 8.

### VMCALL exit
- [ ] Not observed yet — the guest triggers an EPT violation before reaching vmcall
- Reason: the guest's first instruction (vmcall) may access the LIDT/GDT region
  or the CPU checks some data structure; the identity-mapped EPT only covers the
  2MB region containing guest_code, but the CPU accesses other physical addresses
  before executing the first instruction.

### EPT violation exit
- [x] Observed — exit_count=1, GPA=0x6343c000, qual=0x81
- GPA is not 0xdead000 (the deliberate unmapped access in guest code)
- GPA=0x6343c000 is accessed BEFORE the vmcall executes; likely a page table
  walk or system structure access initiated by the CPU before the first instruction
- qual=0x81: bit 0 (read access) + bit 7 (GPA field valid) = read access to
  an unmapped GPA

### kdump
- [ ] Not yet tested — trigger_panic=1 test pending
- Note: QEMU guest uses KVM nested virtualisation; kdump in the QEMU guest
  would capture a guest vmcore, not a host panic. For kdump of a host panic,
  the test should run on the bare server (Phase 2+).

---

## Surprises / Tooling Gaps

1. **VMCS HOST_TR_SEL encoding**: The vmx-reference skill and the task spec
   both had 0x0c0e; the correct value per Intel SDM and KVM source (asm/vmx.h)
   is 0x0c0c. The vmwrite to a reserved field silently succeeds but the field
   stays 0, causing VMLAUNCH error 8. Always cross-check with asm/vmx.h.

2. **objtool RETPOLINE/RETHUNK issues**: Ubuntu's 6.8 kernel build enforces
   objtool checks for RETPOLINE (indirect jumps) and RETHUNK (bare ret). The
   spike's longjmp-back mechanism required:
   - No bare `retq` in the trampoline (use `ud2` after unreachable call)
   - ANNOTATE_RETPOLINE_SAFE for the indirect `jmpq *` in spike_maybe_resume
   - UNWIND_HINT_UNDEFINED before the stack-clobbering longjmp asm

3. **EPT identity-map coverage**: Guest code at a kernel virtual address
   (0xffffffff_xxxxxxxx) has a physical address in the direct-map range
   (2-4GB typically). The 2MB EPT entry covers the code, but the CPU may
   access other physical addresses before executing the first instruction.
   Production code needs to map the full guest memory range, not just the
   code page.

4. **nested KVM VMX support**: kvm_intel must be rmmod'd in the QEMU guest
   before loading spike.ko. CR4.VMXE pre-check correctly warns if kvm_intel
   is still loaded.

5. **MODULE_LICENSE**: Use "GPL v2" not "GPL-2.0-only" in MODULE_LICENSE()
   macro (the latter form is for SPDX, not for module_param).

---

## Command Log

```bash
# Build
ssh phantom-bench "make -C /root/phantom/src/spike/ KDIR=/lib/modules/6.8.0-90-generic/build 2>&1"

# Unload kvm_intel before testing
ssh phantom-bench "rmmod kvm_intel kvm 2>/dev/null || true"

# Test in QEMU guest (nested KVM)
ssh phantom-bench "ssh -p 2222 -o StrictHostKeyChecking=no root@localhost \
  'cd /mnt/phantom/spike && insmod spike.ko && dmesg | tail -30'"

# Test trigger_panic path
ssh phantom-bench "ssh -p 2222 -o StrictHostKeyChecking=no root@localhost \
  'cd /mnt/phantom/spike && insmod spike.ko trigger_panic=1 || true; \
   ls /var/crash/ 2>/dev/null'"

# Unload
ssh phantom-bench "ssh -p 2222 -o StrictHostKeyChecking=no root@localhost \
  'rmmod spike && dmesg | tail -10'"
```
