# Phantom Class B Guest Kernel

Minimal Linux kernel for fuzzing kernel subsystems with Phantom.

## Quick Start

On phantom-bench:
```bash
cd /root/phantom/src/guest/guest_kernel
make setup     # download Linux 6.1.90, apply config + harness
make bzImage   # build (~5-10 minutes)
make install   # copy to /root/phantom/bzImage-guest
```

## Configuration

- No SMP, no modules, no networking
- KASAN enabled for kernel bug detection
- All randomisation disabled for determinism
- Custom `init_harness.c` built into kernel — enters Phantom fuzz loop

## Memory Layout (GPA)

| GPA | Contents |
|-----|----------|
| 0x6000 | Guest GDT |
| 0x7000 | Linux boot_params |
| 0x8000 | Kernel command line |
| 0x70000-0x872FF | Guest page tables (PML4+PDPT+PD+128×PT) |
| 0x600000 | Payload region (u32 len + payload bytes) |
| 0x1000000 | Kernel load address (bzImage protected mode) |
