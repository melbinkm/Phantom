# Appendix B: §5.6 Debugging and Observability Tooling

> Part of [Project Phantom Development Plan](../../project-phantom-dev-plan-v2.md)
>
> This appendix is cross-referenced by multiple tasks. See also [Appendix A: Error Handling](appendix-a-error-handling.md).

`debug.c` is a first-class component of Phantom, not an afterthought. It must be set up and working from **Week 1**.

## 1. VMCS Dump-on-Exit-Failure

Automatically triggered on any unexpected VM exit reason (not in the handled set) or on VMLAUNCH/VMRESUME failure (CF=1 or ZF=1). Output format:

```
PHANTOM VMCS DUMP [instance=N, cpu=M, exit_reason=X, iteration=Y]
  GUEST_RIP=0x... GUEST_RSP=0x... GUEST_RFLAGS=0x...
  GUEST_CR0=0x... GUEST_CR3=0x... GUEST_CR4=0x...
  EXIT_QUALIFICATION=0x... VM_INSTRUCTION_ERROR=N
  GUEST_CS: sel=0x... base=0x... limit=0x... ar=0x...
  ... [all fields]
```

Output via `trace_printk` (not `printk`) to avoid lock contention. Structured format parseable by a companion userspace tool (`tools/vmcs-dump/`).

## 2. EPT Walker/Dumper

Debug ioctl `PHANTOM_DEBUG_DUMP_EPT`:
- Walks the full 4-level EPT for the specified instance
- Prints each mapped region: GPA range, HPA, permissions, memory type
- Highlights: CoW'd pages (private HPA != original HPA), split 2MB pages, MMIO regions, absent regions
- Output to debugfs file `/sys/kernel/debug/phantom/instance_N/ept_map`

## 3. Dirty List Inspector

Debug ioctl `PHANTOM_DEBUG_DUMP_DIRTY_LIST`:
- Returns current dirty list contents: GPA, original HPA, private HPA, iteration number for each entry
- Available mid-iteration (for debugging runaway dirty sets) and post-iteration
- Output to debugfs file `/sys/kernel/debug/phantom/instance_N/dirty_list`

## 4. Trace Logging Ring Buffer

Hot-path event logging via `trace_printk` (not `printk` — `printk` is too slow for the hot path and would corrupt timing measurements):
- VM entry / VM exit + exit reason
- EPT violation GPA and resolved action (CoW, MMIO emulate, abort)
- CoW allocation (GPA, private HPA)
- Snapshot create / restore timestamps
- ToPA overflow events

Accessible via `trace-cmd` or directly from `/sys/kernel/debug/tracing/trace`. Minimal overhead when not being read (ring buffer).

## 5. VMCS Field Validator

Before every VMLAUNCH and VMRESUME (in debug builds): check all VMCS fields against Intel SDM Vol. 3C §26.3 requirements:
- Segment register access rights consistency (S/E/W bit combinations)
- CR0/CR4 fixed bits (against `IA32_VMX_CR0_FIXED0/1` and `IA32_VMX_CR4_FIXED0/1`)
- Control field consistency (exec controls vs exit controls vs entry controls)
- Reserved fields zero

Compiled out in production (`#ifdef PHANTOM_DEBUG`). In development: compile with `-DPHANTOM_DEBUG` at all times.

## 6. Crash Observability Procedure

**Crash observability is a hard requirement** — debugging host panics without post-mortem data is
infeasible. The approach differs between Phase 0–1 (QEMU guest) and Phase 2+ (bare-metal server).

### Phase 0–1: QEMU Guest Crash Recovery

When phantom.ko in the nested KVM guest panics:

1. The QEMU guest process dies; the host server (phantom-bench) is **unaffected**.
2. Guest serial output (panic backtrace) is captured to the serial log:
   ```bash
   ssh phantom-bench "tail -100 /root/phantom/logs/guest.log"
   ```
3. Examine the panic backtrace and call trace from the serial log.
4. Restart the guest and reload for another attempt:
   ```bash
   ssh phantom-bench "bash /root/phantom/src/scripts/launch-guest.sh"
   ```
5. No kdump, no reboot needed — recovery is seconds, not minutes.

### Phase 2+: Bare-Metal Host Crash Recovery

When phantom.ko on phantom-bench triggers a host panic:

1. kdump captures crash dump to `/var/crash/` (requires `crashkernel=256M` in boot cmdline;
   configured by `scripts/server-setup.sh`, requires one reboot to activate).
2. Server reboots automatically. Reconnect after ~2 minutes:
   ```bash
   ssh phantom-bench "echo ok; uname -r"
   ```
3. Verify kdump captured a dump:
   ```bash
   ssh phantom-bench "ls -lt /var/crash/ | head"
   ```
4. Examine Phantom state:
   ```bash
   ssh phantom-bench
   crash /usr/lib/debug/vmlinux /var/crash/<latest-dir>/vmcore
   # In crash shell:
   crash> mod -s phantom /root/phantom/src/kernel/phantom.ko
   crash> bt <phantom_vmx_exit_handler>
   crash> struct phantom_instance <addr>
   ```
5. Companion script `tools/crash-scripts/phantom-state.py` automates extraction of
   Phantom-specific state (instance status, dirty list, VMCS last-snapshot values).

### Netconsole (UDP Serial Substitute for Remote Servers)

Physical serial console is not available on the Hetzner dedicated server. Netconsole sends
kernel log messages over UDP to the dev machine during and after a panic — this is the substitute.

**One-time setup on phantom-bench:**
```bash
# Find the server's NIC
IFACE=$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -1)

# Load netconsole (replace DEV_MACHINE_IP with your WSL2 IP)
modprobe netconsole "netconsole=@/${IFACE},6666@DEV_MACHINE_IP/"

# Verify: kernel messages appear on dev machine
echo "netconsole test" > /dev/kmsg
```

**Dev machine (WSL2) — listen for messages:**
```bash
nc -u -l -p 6666
```

**To find WSL2 IP from the server:** `cat /etc/resolv.conf | grep nameserver` on WSL2, or
check `ip addr` on the WSL2 default interface.

**To make netconsole persistent** across reboots, edit `/etc/modprobe.d/netconsole.conf`
(created by `scripts/server-setup.sh` with a template — fill in `DEV_MACHINE_IP`).

### Summary: Crash Observability by Phase

| Phase | Crash Target | Recovery Method | Time to Recovery |
|-------|-------------|-----------------|-----------------|
| 0–1 | QEMU guest | Serial log at `/root/phantom/logs/guest.log` | ~5 seconds |
| 2+ | phantom-bench host | kdump at `/var/crash/` + netconsole | ~2 minutes (reboot) |

## debug.c Skeleton (Week 1 Setup)

```c
/* debug.c — first-class component, set up from week 1 */

/* Rule: hot-path events ALWAYS use trace_printk, never printk */

void phantom_dump_vmcs(struct phantom_instance *inst, u32 exit_reason)
{
    trace_printk("PHANTOM VMCS DUMP [instance=%d, cpu=%d, exit_reason=%u, iteration=%llu]\n",
                 inst->id, smp_processor_id(), exit_reason, inst->iteration);
    trace_printk("  GUEST_RIP=0x%llx GUEST_RSP=0x%llx GUEST_RFLAGS=0x%llx\n",
                 vmcs_read(GUEST_RIP), vmcs_read(GUEST_RSP),
                 vmcs_read(GUEST_RFLAGS));
    trace_printk("  GUEST_CR0=0x%llx GUEST_CR3=0x%llx GUEST_CR4=0x%llx\n",
                 vmcs_read(GUEST_CR0), vmcs_read(GUEST_CR3),
                 vmcs_read(GUEST_CR4));
    trace_printk("  EXIT_QUAL=0x%llx VM_INSTR_ERROR=%u\n",
                 vmcs_read(EXIT_QUALIFICATION),
                 vmcs_read32(VM_INSTRUCTION_ERROR));
    /* ... all segment registers, MSRs, interrupt state ... */
}

/* Hot-path macros — compiled to no-ops in production */
#ifdef PHANTOM_DEBUG
#define PHANTOM_TRACE_VM_ENTRY(inst) \
    trace_printk("VMX_ENTRY inst=%d iter=%llu\n", (inst)->id, (inst)->iteration)
#define PHANTOM_TRACE_VM_EXIT(inst, reason) \
    trace_printk("VMX_EXIT inst=%d reason=%u\n", (inst)->id, reason)
#define PHANTOM_TRACE_COW(gpa, priv_hpa) \
    trace_printk("COW gpa=0x%llx priv_hpa=0x%llx\n", gpa, priv_hpa)
#else
#define PHANTOM_TRACE_VM_ENTRY(inst)        do {} while(0)
#define PHANTOM_TRACE_VM_EXIT(inst, reason) do {} while(0)
#define PHANTOM_TRACE_COW(gpa, priv_hpa)   do {} while(0)
#endif
```

## Cross-Task References

- **Task 1.1** (Bootstrap): debug.c skeleton, `trace_printk` for hot-path events from Week 1
- **Task 1.2** (VMCS): VMCS dump-on-exit-failure, VMCS field validator
- **Task 1.3** (EPT): EPT walker/dumper, `PHANTOM_DEBUG_DUMP_EPT` ioctl
- **Task 1.4** (CoW): Dirty list inspector, `PHANTOM_DEBUG_DUMP_DIRTY_LIST` ioctl
- **Task 0.1** (Spike): kdump procedure — serial console, crash utility procedure
