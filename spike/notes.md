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

## Findings (to be filled in after testing)

### VMXON result
- [ ] CF=0, ZF=0 (success)
- [ ] CF=1 (failure — kvm_intel still loaded?)
- [ ] ZF=1 (instruction error — check VMCS field 0x4400)

### VMLAUNCH result
- [ ] Guest launched successfully
- [ ] VMLAUNCH failed (instr_err = ?)

### VMCALL exit
- [ ] Observed with correct exit reason (18)
- [ ] RIP advanced by 3 bytes correctly

### EPT violation exit
- [ ] Observed with GPA=0xdead000
- [ ] Exit qualification bits logged correctly

### kdump
- [ ] kdump captured vmcore after trigger_panic=1
- [ ] Serial console showed panic output
- [ ] crash(1) could load vmcore with module symbols

---

## Surprises / Tooling Gaps

(to be filled in during testing)

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
