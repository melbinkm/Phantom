# Task 4.1: Extended Bug Campaigns

> **Phase:** Extended Campaigns + Publication + Release | **Week(s):** 33–35 | **Depends on:** [Task 3.4](../phase-3-kernel-fuzzing/task-3.4-performance-benchmarking.md)

## Objective

Run sustained bug-finding campaigns on high-value kernel targets (netfilter, eBPF, Bluetooth) and secondary targets, document all crashes with root-cause analysis, and submit responsible disclosure reports.

## What to Build

- Primary targets (chosen for CVE potential and research impact): Linux netfilter/nf_tables (leveraging existing expertise and harness knowledge), eBPF verifier (high-value target, active area of kernel security research), Linux Bluetooth stack (L2CAP, SMP — historically bug-rich)
- Secondary targets (demonstrating breadth): filesystem image parsing (ext4 superblock handling), crypto subsystem (AF_ALG interface), device driver interfaces (USB, input subsystem)
- Per bug: minimise reproducer using AFL++ `tmin` or kAFL minimiser; complete root cause analysis; write patch where appropriate; report to security@kernel.org or relevant maintainer; track CVE assignment

## Implementation Guidance

### Class B Target List (§3)

From §3 — example targets for Class B kernel fuzzing:
- **nf_tables (netfilter):** Leverages existing expertise; high-value for CVEs. Start with `nf_tables_newrule` and related path.
- **eBPF verifier:** Active security research area; complex state machine. Harness: feed crafted eBPF programs to `bpf_check()`.
- **Bluetooth L2CAP/SMP:** Historically bug-rich subsystem. Harness: feed crafted L2CAP packets to `l2cap_recv_acldata()`.
- **ext4 superblock:** Feed malformed ext4 images to `ext4_fill_super()`.
- **AF_ALG:** Crypto interface; feed operation sequences to `af_alg_accept()`.

### Harness Templates (§10 Repo Structure)

From the repository structure at §10:

```
guest/
├── nyx_api.h                  # Standard kAFL harness header
├── harness_template_a.c       # Class A template
├── harness_template_b.c       # Class B template (kernel module)
├── examples/
│   ├── parser_xml.c           # libxml2 parser harness (Class A)
│   ├── parser_png.c           # libpng harness (Class A)
│   └── kernel_nftables.c      # nf_tables kernel harness (Class B)
```

Class B harness template structure:

```c
/* harness_template_b.c — kernel module harness */
#include "nyx_api.h"

static int harness_init(void)
{
    /* 1. Acquire snapshot point */
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

    return 0;
}

static void harness_exit(void)
{
    /* 2. Release: triggers PT stop + snapshot restore */
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
}

static void fuzz_one(u8 *payload, size_t size)
{
    /* 3. Call target function */
    target_subsystem_entry(payload, size);
}

/* Custom init thread: registered as kernel_thread */
static int harness_thread_fn(void *data)
{
    u8 *payload_buf;

    /* Register payload buffer with Phantom */
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (u64)&payload_buf);

    harness_init();  /* ACQUIRE — snapshot taken here */

    while (1) {
        fuzz_one(payload_buf, PAYLOAD_SIZE);
        harness_exit();  /* RELEASE — restore happens here */
        /* Execution continues from ACQUIRE point on next iteration */
    }
}
```

### Bug Campaign Process

For each crash found:

1. **Minimise:** `afl-tmin -i crash_input -o min_crash -- ./harness @@`
2. **Root cause:** Analyze crash address, call stack, KASAN report (if enabled)
3. **Patch:** Write fix if straightforward; otherwise document root cause
4. **Report:** Submit to security@kernel.org with:
   - Affected subsystem and kernel version range
   - Minimised reproducer
   - Root cause analysis
   - Suggested fix (if available)
5. **Track:** Monitor CVE assignment and patch acceptance

### Real Crash Criterion (§9)

From §9 quantified criteria:
> "Real crash found" = Crash in unmodified real-world target binary/kernel, **not** pre-seeded with a known crash input.

Verification: confirm crash input triggers in a clean kernel build outside Phantom:
```bash
# Reproduce outside Phantom
insmod target_module.ko
./inject_crash_input min_crash
# Must see KASAN report / kernel oops in dmesg
```

## Key Data Structures

```c
/* Bug report tracking */
struct phantom_bug_report {
    char     target[64];          /* e.g., "nf_tables", "ebpf_verifier"  */
    char     kernel_version[32];  /* Affected version range               */
    u64      crash_addr;          /* From PHANTOM_RESULT_CRASH            */
    char     root_cause[512];     /* Analysis summary                     */
    bool     patch_written;
    bool     reported_to_security_kernel;
    char     cve_id[32];          /* e.g., "CVE-2027-XXXXX"              */
    bool     patch_merged;
};
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `guest/examples/kernel_nftables.c` | nf_tables harness |
| `guest/harness_template_b.c` | Template for new Class B harnesses |
| `benchmarks/reproduce.sh` | Extended campaign scripts |

## Reference Sections

- §3: Class B targets — nf_tables, eBPF verifier, ext4, Bluetooth, AF_ALG
- §10: Harness templates — `harness_template_b.c`, `examples/kernel_nftables.c`
- §9: Real crash criterion — must trigger in unmodified kernel outside Phantom

## Tests to Run

- Bug campaigns run continuously for 3 weeks across all primary and secondary targets (pass = campaigns execute without host instability or resource exhaustion)
- Each crash has a minimised reproducer confirmed to trigger in isolation (pass = reproducer verified on clean kernel build outside Phantom)
- Root cause analysis completed for each bug (pass = root cause documented with affected code path)
- Bugs reported to security@kernel.org with responsible disclosure timeline (pass = submission confirmed and acknowledgement received)

## Deliverables

At least 5 bugs found in real kernel targets, ideally with CVEs assigned.
