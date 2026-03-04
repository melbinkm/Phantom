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
#include "compat.h"

/* ------------------------------------------------------------------
 * Guest binary — trivial_guest machine code embedded as byte array.
 *
 * This is the hand-assembled equivalent of guest/trivial_guest.S:
 *
 *   xor  %rax, %rax         ; RAX = 0 (GET_HOST_DATA hypercall)
 *   vmcall                  ; host sets RBX = data buffer GPA
 *   xor  %rcx, %rcx         ; counter = 0
 *   xor  %rdx, %rdx         ; accumulator = 0
 * .loop:
 *   mov  (%rbx,%rcx,8),%rax ; load data[rcx]
 *   xor  %rax, %rdx         ; acc ^= data[rcx]
 *   inc  %rcx               ; rcx++
 *   cmp  $512, %rcx         ; if rcx < 512, continue
 *   jl   .loop
 *   mov  %rdx, %rbx         ; RBX = checksum
 *   mov  $1, %rax            ; RAX = 1 (SUBMIT_RESULT hypercall)
 *   vmcall                  ; host records RBX
 * .halt:
 *   hlt
 *   jmp  .halt
 * ------------------------------------------------------------------ */
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
		u64 *dp;
		int i;

		if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
			ret = -EFAULT;
			break;
		}

		if (args.reserved != 0) {
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

		/* Load guest binary into code page (always refresh) */
		memcpy(page_address(state->guest_code_page),
		       phantom_trivial_guest_bin,
		       sizeof(phantom_trivial_guest_bin));

		/* Fill data page with known test pattern:
		 *   data[i] = (i+1) * 0x1234567890ABCDEFull
		 */
		dp = (u64 *)page_address(state->guest_data_page);
		for (i = 0; i < 512; i++)
			dp[i] = (u64)(i + 1) * 0x1234567890ABCDEFull;

		/*
		 * Phase C: Prepare guest-state reset for relaunches.
		 *
		 * On first setup, phantom_vmcs_configure_fields() initialises
		 * RIP/RSP/RFLAGS correctly.  On subsequent runs, we signal
		 * the vCPU thread to reset those fields before VMLAUNCH
		 * (vcpu_run_request bit 1 = "reset needed").
		 *
		 * Always clear the per-run result state here.
		 */
		state->run_result      = 0;
		state->run_result_data = 0;
		memset(&state->guest_regs, 0, sizeof(state->guest_regs));

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

		/* Populate output fields */
		args.result      = state->run_result_data;
		args.exit_reason = state->exit_reason & 0xFFFF;

		if (copy_to_user((void __user *)arg, &args, sizeof(args)))
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
