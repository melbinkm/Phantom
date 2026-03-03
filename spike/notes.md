# Spike Notes — Task 0.1: VMX Feasibility Spike

**Date:** 2026-03-03
**Status:** COMPLETE — all tests pass

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
R12-R15, RBP) and use a proper context-switch mechanism.

### 5. VMRESUME loop limited to two exits

The spike runs the guest, collects two expected exits (VMCALL then #PF), and
terminates.  A production fuzzer would loop: VMRESUME after each handled exit
until `should_exit == true`.

### 6. TRUE_* capability MSRs

The code uses `MSR_IA32_VMX_TRUE_*` MSRs (0x48d-0x490) rather than the plain
MSRs (0x481-0x484).  The TRUE MSRs give more accurate allowed-0/allowed-1
information on processors that support "true" VMX control reporting (bit 55 of
IA32_VMX_BASIC).  On older hardware that lacks the TRUE MSRs, this will panic.
The spike target (Intel i7-6700) supports the TRUE MSRs.

### 7. Guest executes at kernel virtual address, not physical address

GUEST_RIP = virtual address of guest_code_start (NOT the physical address).
Setting GUEST_RIP to the physical address (code_gpa) causes the CPU to execute
at a low userspace VA that is not mapped in the host's kernel CR3, immediately
triggering a guest page fault before any guest instruction executes.

The correct two-level address translation for the guest:
  VA 0xffffffff_xxxxxxxx -> (host CR3 + guest page tables) -> GPA = HPA = phys
                         -> (EPT 1GB identity map) -> same HPA

### 8. #PF exception bitmap intercept instead of EPT violation

The deliberate "bad access" in guest_code uses VA 0xdead000, which is NOT in
the host's kernel page tables.  This causes a guest #PF, not an EPT violation
(EPT violations only occur when the VA->GPA translation succeeds but the GPA
is absent from the EPT).

Fix: EXCEPTION_BITMAP bit 14 (#PF) is set so all guest page faults cause VM
exits rather than being delivered to the guest's IDT (which would run the host's
page fault handler in guest context, causing an MSR-access loop).

The exit qualification for exception exit reason 0 holds the faulting VA
(0xdead000), confirming the deliberate unmapped access was intercepted.

### 9. MSR bitmap (all zeros) to prevent RDMSR/WRMSR exits

The nested KVM hypervisor forces bit 28 of primary proc-based controls to 0
(MSR bitmaps disabled), meaning ALL RDMSR/WRMSR instructions exit by default.
When the guest's #PF handler ran (before fix #8), it made MSR accesses that
caused repeated RDMSR/WRMSR exits, creating a soft lockup.

Fix: request "use MSR bitmaps" (bit 28) in the desired proc-based control
flags.  Allocate a 4KB zero-filled bitmap (no MSRs intercepted).  With this
fix, RDMSR/WRMSR in the guest run silently without any VM exits.

---

## Final Test Results (2026-03-03)

### dmesg from successful test run

```
spike: Project Phantom VMX feasibility spike loading
spike: EPT built: eptp=0x106cf701e code_gpa=0xc3f50b10 stack_gpa=0x1000000
spike: CHECKPOINT - about to execute VMXON on CPU 0
spike: vmxon_pa=0x109035000 vmcs_pa=0x10943d000 eptp=0x106cf701e
spike: VMCS revision ID = 0x11e57ed0
spike: VMXON succeeded on CPU 0
spike: PINBASED_CTLS cap_msr=0x7f00000016
spike: PROCBASED_CTLS cap_msr=0xfff9fffe04006172 (forced=0x04006172)
spike: proc1_ctl=0x94006172
spike: VMLAUNCH: guest RIP=0xffffffffc0750b10 (VA) / HPA=0xc3f50b10 guest RSP=0x1001000
spike: VMCALL exit #1 - guest RIP=0xffffffffc0750b10; advancing RIP by 3
spike: guest exception #14 at RIP=0xffffffffc0750b1a fault_VA=0xdead000 (exit #2) - #PF - deliberate unmapped access confirmed
spike: guest run complete after 2 exits
spike: spike loaded successfully; exit_count=2
spike: unloading
spike: VMXOFF executed on CPU 0
spike: unloaded cleanly
```

### Test results checklist

| Test | Result |
|------|--------|
| `insmod spike.ko` | PASS: loads, VMXON succeeds |
| VMCALL exit | PASS: `spike: VMCALL exit #1 - guest RIP=0xffffffff...` |
| Deliberate bad access | PASS: `spike: guest exception #14 ... fault_VA=0xdead000 - #PF` |
| `rmmod spike` | PASS: VMXOFF executed, unloaded cleanly |
| `insmod spike.ko trigger_panic=1` | PASS: BUG() fires, kernel oops at spike_main.c:1043 |

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

3. **GUEST_RIP must be virtual address, not physical**: Setting GUEST_RIP to the
   physical address of guest_code_start caused the CPU to execute at a low
   userspace VA, immediately triggering a guest #PF before any guest instruction.
   GUEST_RIP must be the kernel virtual address (0xffffffff...) so the guest's
   two-level MMU walk (host CR3 + EPT) resolves it correctly.

4. **EPT identity-map coverage must be 1GB pages for entire address space**: The
   initial 2MB large-page EPT caused EPT violations before the first guest
   instruction because the host's page-table walk structures live at physical
   addresses outside the 2MB region. Mapping all 512 PDPT entries with 1GB pages
   covering 0-512GB solves this.

5. **MSR bitmaps required to prevent RDMSR/WRMSR exit loops**: In nested KVM,
   the outer hypervisor forces all MSR accesses to exit unconditionally unless
   MSR bitmaps are enabled. A zero MSR bitmap (no interceptions) prevents the
   page fault handler's MSR accesses from causing a VMRESUME loop soft lockup.

6. **#PF exception bitmap required for deliberate bad access**: The guest's
   "deliberate bad access" at VA 0xdead000 causes a guest #PF (not an EPT
   violation) because 0xdead000 is not in the host's kernel page tables. Without
   EXCEPTION_BITMAP bit 14, the #PF is delivered to the guest IDT (host's page
   fault handler in guest context), which loops. The exception bitmap intercepts
   it as a VM exit instead.

7. **nested KVM VMX support**: kvm_intel must be rmmod'd in the QEMU guest
   before loading spike.ko. CR4.VMXE pre-check correctly warns if kvm_intel
   is still loaded.

8. **MODULE_LICENSE**: Use "GPL v2" not "GPL-2.0-only" in MODULE_LICENSE()
   macro (the latter form is for SPDX, not for module_param).

---

## Command Log

```bash
# Build
ssh phantom-bench "make -C /root/phantom/src/spike/ KDIR=/lib/modules/6.8.0-90-generic/build 2>&1"

# Unload kvm_intel before testing
ssh phantom-bench "ssh -p 2222 -o StrictHostKeyChecking=no root@localhost \
  'rmmod kvm_intel kvm 2>/dev/null; true'"

# Test in QEMU guest (nested KVM)
ssh phantom-bench "ssh -p 2222 -o StrictHostKeyChecking=no root@localhost \
  'insmod /mnt/phantom/spike/spike.ko && dmesg | grep spike && rmmod spike'"

# Test trigger_panic path
ssh phantom-bench "ssh -p 2222 -o StrictHostKeyChecking=no root@localhost \
  'insmod /mnt/phantom/spike/spike.ko trigger_panic=1 || true'"

# Reboot guest
ssh phantom-bench "ssh -p 2222 -o StrictHostKeyChecking=no root@localhost \
  'echo b > /proc/sysrq-trigger'"
```
