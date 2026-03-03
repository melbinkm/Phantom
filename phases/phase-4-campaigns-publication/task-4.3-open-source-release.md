# Task 4.3: Open-Source Release + Artifact Evaluation

> **Phase:** Extended Campaigns + Publication + Release | **Week(s):** 39–40 | **Depends on:** [Task 4.2](task-4.2-paper-writing.md)

## Objective

Publish a clean, documented, CI-verified public repository and achieve Artifact Evaluated — Functional (AEF) and Artifact Evaluated — Reusable (AERR) badges.

## What to Build

- Code cleanup: consistent code style (kernel coding style for `phantom.ko`, standard C for userspace), remove debug hacks/TODOs/dead code, add comments to non-obvious code paths (EPT CoW, VMCS handling, XSAVE path, NMI handler)
- Documentation: `README.md` (project overview, architecture diagram, quick-start), `docs/setup-guide.md` (hardware requirements, kernel config, build instructions), `docs/writing-harnesses.md` (how to write a Class A and Class B harness), `docs/benchmarks.md` (how to reproduce published benchmarks), `docs/architecture.md` (detailed design document, expanded from paper)
- Packaging: Makefile/Kbuild for kernel module, pip/setup.py for userspace tools, Dockerised build environment for reproducibility, minimal guest kernel defconfig included
- CI expansion: sparse + smatch have run on every commit since Phase 1a; this task migrates them to the public self-hosted GitHub Actions runner, adds the full test suite (module load/unload, basic fuzz loop, determinism check, exec/sec threshold), and enables the dedicated bare-metal performance runner — `CONFIG_KASAN`/`KMEMLEAK`/`LOCKDEP`/`DEBUG_ATOMIC_SLEEP` remain mandatory in CI builds
- Artifact evaluation preparation: `benchmarks/reproduce.sh` (end-to-end reproduction script with expected result ranges), pre-built VM image with all tools installed, expected result ranges stated in reproduction script (e.g., "exec/sec should be 40k–120k for this target on this hardware class"), target AEF (Artifact Evaluated — Functional) and AERR (Artifact Evaluated — Reusable) badges
- Release: GitHub repository (GPL-2.0 for kernel module, MIT for userspace tools), blog post announcing the project, example harnesses for 3+ targets
- Security: fuzz `/dev/phantom` ioctls with syzkaller to find host-side vulnerabilities before public release

## Implementation Guidance

### Full Repository Structure (§10)

```
phantom/
├── README.md
├── LICENSE-GPL2          # kernel module
├── LICENSE-MIT           # userspace
├── Makefile
│
├── docs/
│   ├── architecture.md   # Detailed design document
│   ├── setup-guide.md    # Build + install instructions
│   ├── writing-harnesses.md  # Class A + B harness guide
│   ├── benchmarks.md     # Reproduce benchmarks
│   ├── determinism.md    # Guide to achieving deterministic fuzzing
│   ├── troubleshooting.md
│   └── gpl-symbols.md    # GPL-only symbol dependencies
│
├── kernel/               # phantom.ko — GPL-2.0
│   ├── Kbuild
│   ├── compat.h          # Kernel version compatibility
│   ├── phantom_main.c    # Module init/cleanup, chardev
│   ├── vmx_core.c / .h   # VMXON, VMCS, VM entry/exit
│   ├── ept.c / .h        # EPT page table + GPA classification
│   ├── ept_cow.c / .h    # CoW handler, page pool, dirty list
│   ├── snapshot.c / .h   # VMCS save/restore, XSAVE/XRSTOR
│   ├── hypercall.c / .h  # nyx_api VMCALL handler
│   ├── pt_config.c / .h  # Intel PT MSR + ToPA setup
│   ├── watchdog.c / .h   # VMX preemption timer
│   ├── nmi.c / .h        # NMI-exiting handler
│   ├── interface.c / .h  # /dev/phantom ioctl + mmap
│   ├── multicore.c / .h  # Per-CPU instance management
│   ├── memory.c / .h     # Global memory accounting
│   └── debug.c / .h      # VMCS dump, EPT walker, observability
│
├── userspace/            # MIT licensed
│   ├── phantom-pt-decode/
│   ├── phantom-ctl/
│   ├── afl-phantom/
│   └── kafl-bridge/
│
├── guest/                # Harness code (MIT)
│   ├── nyx_api.h
│   ├── harness_template_a.c
│   ├── harness_template_b.c
│   ├── examples/
│   └── guest_kernel/
│       ├── defconfig
│       └── init_harness.c
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── performance/
│
├── benchmarks/
│   ├── scripts/
│   ├── reproduce.sh
│   ├── results/
│   └── comparison/
│
└── docker/
    ├── Dockerfile.build
    └── Dockerfile.test
```

### CI Environment (§9)

The final CI pipeline (migrated to public GitHub Actions):

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  static-analysis:
    runs-on: self-hosted  # nested-KVM runner
    steps:
      - run: make sparse  # Zero warnings required
      - run: make smatch  # Zero warnings required

  kernel-tests:
    runs-on: self-hosted
    env:
      KCONFIG_KASAN: y
      KCONFIG_KMEMLEAK: y
      KCONFIG_LOCKDEP: y
      KCONFIG_DEBUG_ATOMIC_SLEEP: y
    steps:
      - run: make && insmod phantom.ko && rmmod phantom.ko  # 100x
      - run: make test-basic-fuzz  # 60s fuzz, find seeded crash
      - run: make test-determinism  # 1000 runs
      - run: make test-ept-isolation

  performance:
    runs-on: bare-metal  # Dedicated bare-metal runner
    steps:
      - run: make bench-execsec  # Assert >= threshold
```

### Licensing (§8)

| Component | License | Rationale |
|-----------|---------|-----------|
| `phantom.ko` kernel module | GPL-2.0-only | Deep kernel interaction requires GPL-only symbols |
| Userspace tools | MIT | Independent programs communicating via ioctl/mmap |
| `libipt` dependency | BSD-3-Clause | Compatible with both GPL-2.0 and MIT |
| `nyx_api.h` | MIT | Compatible |
| Bareflank extracted primitives | MIT | Compatible |

### Kernel Compatibility (§6.9)

CI matrix as of March 2026: kernels **6.8, 6.12** (LTS), **6.14** (latest stable), and HEAD.

```c
/* kernel/compat.h — all version-specific workarounds centralised here */
#include <linux/version.h>

/* Document each case with the kernel commit that changed the API */
#if KERNEL_VERSION(6, 8, 0) <= LINUX_VERSION_CODE
/* ... */
#endif
```

### Syzkaller Self-Fuzz (§6.5)

Before public release, fuzz `/dev/phantom` ioctls with syzkaller:
- Target: all `PHANTOM_*` ioctls with malformed arguments (wrong sizes, NULL pointers, out-of-range values, mismatched instance IDs)
- Run soak: monitor for host crashes
- Add ioctl input validation tests to standard test suite

From §6.5:
> "Fuzz `/dev/phantom` ioctls with syzkaller to find host-side vulnerabilities before public release"

## Key Data Structures

```
Artifact evaluation targets:
  AEF  — Artifact Evaluated — Functional
  AERR — Artifact Evaluated — Reusable

Repository release checklist:
  [ ] GPL-2.0 LICENSE-GPL2 file present
  [ ] MIT LICENSE-MIT file present
  [ ] All 5 docs/ files complete
  [ ] CI green (sparse, smatch, test suite)
  [ ] benchmarks/reproduce.sh verified on clean machine
  [ ] At least 1 beta tester confirmed reproduction
  [ ] Blog post published
  [ ] 3+ example harnesses in guest/examples/
  [ ] Syzkaller soak: zero host crashes
```

## Source Files to Modify

| File | Purpose |
|------|---------|
| `kernel/` (all files) | Code cleanup: style, comments, remove TODOs |
| `docs/` | All 5 documentation files |
| `.github/workflows/ci.yml` | Migrated CI pipeline |
| `benchmarks/reproduce.sh` | Complete end-to-end script |

## Reference Sections

- §10: Full repo structure — exact directory layout and file descriptions
- §6.5: Syzkaller self-fuzz — ioctl soak before release, validation tests
- §8: Licensing — GPL-2.0 for kernel module, MIT for userspace, bundled deps
- §6.9: Kernel compat — CI matrix (6.8, 6.12, 6.14, HEAD), `compat.h` pattern
- §9: CI environment — self-hosted runner, mandatory debug configs, bare-metal performance

## Tests to Run

- CI green: all tests pass, sparse + smatch report zero warnings (pass = CI pipeline succeeds on a clean commit)
- `benchmarks/reproduce.sh` works on a clean machine (pass = script completes, results fall within stated expected ranges)
- At least 1 external user reproduces published results (pass = beta tester confirms reproduction independently)
- Documentation complete: all 5 docs files exist and cover their stated topics (pass = docs reviewed by external reader)
- Syzkaller finds no host crashes when fuzzing `/dev/phantom` ioctls (pass = zero host panics after a soak run)

## Deliverables

Public GitHub repository with documentation, CI, and artifacts; blog post published; AEF + AERR artifact evaluation targeted.

## Exit Criteria

**Phase 4 exit criteria:** at least 5 bugs in real-world kernel targets (ideally with CVEs assigned); paper submitted to top-tier venue (USENIX Security 2027 or IEEE S&P 2027); public GitHub repository with documentation; CI pipeline passing (includes sparse + smatch static analysis); artifact evaluation badges targeted (AEF + AERR); at least one external user has reproduced results (beta tester).
