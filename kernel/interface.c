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
 *   1. Loads the trivial guest binary (trivial_guest.bin) into the
 *      guest code page via copy_from_user / embedded binary
 *   2. Populates the guest data page with a known test pattern
 *   3. Calls phantom_vmcs_setup() on the target CPU
 *   4. Calls phantom_run_guest() via smp_call_function_single()
 *   5. Copies result back to userspace
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

#include "phantom.h"
#include "interface.h"
#include "vmx_core.h"
#include "compat.h"

/* ------------------------------------------------------------------
 * Guest binary — trivial_guest.bin embedded as a byte array.
 *
 * This is the compiled flat binary produced by guest/Makefile.
 * The kernel loads it into the guest code page at GPA 0x10000.
 *
 * For the kernel module build, we include a pre-built binary.
 * If the binary is not present, we fall back to an inline HLT loop.
 * ------------------------------------------------------------------ */

/*
 * Minimal inline guest: GET_HOST_DATA → read 512 u64s → XOR fold →
 * SUBMIT_RESULT → HLT loop.
 *
 * Opcode sequence (assembled for GPA 0x10000, but position-independent
 * since all branches are relative):
 *
 *   xor  %rax, %rax        ; hc_nr = 0 (GET_HOST_DATA)
 *   vmcall                 ; host sets RBX = data_gpa
 *   xor  %rcx, %rcx        ; counter = 0
 *   xor  %rdx, %rdx        ; checksum = 0
 * .loop:
 *   mov  (%rbx,%rcx,8), %rax
 *   xor  %rax, %rdx
 *   inc  %rcx
 *   cmp  $512, %rcx
 *   jl   .loop
 *   mov  %rdx, %rbx        ; checksum → RBX
 *   mov  $1, %rax           ; hc_nr = 1 (SUBMIT_RESULT)
 *   vmcall
 * .halt:
 *   hlt
 *   jmp  .halt
 */
static const u8 phantom_trivial_guest_bin[] = {
	/* xor %rax, %rax */        0x48, 0x31, 0xC0,
	/* vmcall */                 0x0F, 0x01, 0xC1,
	/* xor %rcx, %rcx */        0x48, 0x31, 0xC9,
	/* xor %rdx, %rdx */        0x48, 0x31, 0xD2,
	/* .loop: */
	/* mov (%rbx,%rcx,8),%rax */0x48, 0x8B, 0x04, 0xCB,
	/* xor %rax, %rdx */        0x48, 0x31, 0xC2,
	/* inc %rcx */               0x48, 0xFF, 0xC1,
	/* cmp $512, %rcx */        0x48, 0x81, 0xF9, 0x00, 0x02, 0x00, 0x00,
	/* jl .loop (-16 bytes) */  0x7C, 0xF0,
	/* mov %rdx, %rbx */        0x48, 0x89, 0xD3,
	/* mov $1, %rax */          0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
	/* vmcall */                 0x0F, 0x01, 0xC1,
	/* .halt: hlt */            0xF4,
	/* jmp .halt (-2 bytes) */  0xEB, 0xFD,
};

/* ------------------------------------------------------------------
 * Work struct for smp_call_function_single guest execution
 * ------------------------------------------------------------------ */

struct phantom_run_work {
	struct phantom_vmx_cpu_state *state;
	int result;
};

static void phantom_run_guest_on_cpu(void *data)
{
	struct phantom_run_work *work = data;
	struct phantom_vmx_cpu_state *state = work->state;
	int ret;

	ret = phantom_vmcs_setup(state);
	if (ret) {
		work->result = ret;
		return;
	}

	work->result = phantom_run_guest(state);
}

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
		struct phantom_run_work work;
		u64 *data_page;
		int target_cpu;
		int i;

		if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
			ret = -EFAULT;
			break;
		}

		if (args.reserved != 0) {
			ret = -EINVAL;
			break;
		}

		/* Find the target CPU — use cpu=0 by default */
		target_cpu = -1;
		{
			int cpu;

			for_each_cpu(cpu, pdev->vmx_cpumask) {
				if (args.cpu == 0 || (int)args.cpu == cpu) {
					target_cpu = cpu;
					break;
				}
			}
		}

		if (target_cpu < 0) {
			pr_err("phantom: RUN_GUEST: no valid target CPU\n");
			ret = -ENODEV;
			break;
		}

		state = per_cpu_ptr(&phantom_vmx_state, target_cpu);

		/*
		 * Load the trivial guest binary into the guest code page.
		 * The page was already allocated by phantom_vmcs_setup if
		 * vmcs_configured is set, but we need to set it up first.
		 *
		 * phantom_vmcs_setup handles allocation; we need the code
		 * page populated before calling phantom_run_guest.
		 * Strategy: call setup, then load binary.
		 *
		 * Since setup allocates pages but vmcs_configured may already
		 * be true (idempotent), we need to handle both paths.
		 */
		if (!state->vmcs_configured) {
			/* Setup will be called inside phantom_run_guest_on_cpu */
			/* But we need the page allocated first to copy binary */
			int node = cpu_to_node(target_cpu);

			state->guest_code_page = alloc_pages_node(
				node, GFP_KERNEL | __GFP_ZERO, 0);
			if (!state->guest_code_page) {
				ret = -ENOMEM;
				break;
			}

			/* Copy trivial guest binary to code page */
			memcpy(page_address(state->guest_code_page),
			       phantom_trivial_guest_bin,
			       sizeof(phantom_trivial_guest_bin));

			/* Allocate data page for test pattern */
			state->guest_data_page = alloc_pages_node(
				node, GFP_KERNEL | __GFP_ZERO, 0);
			if (!state->guest_data_page) {
				__free_page(state->guest_code_page);
				state->guest_code_page = NULL;
				ret = -ENOMEM;
				break;
			}

			/* Fill data page with test pattern */
			data_page = (u64 *)page_address(state->guest_data_page);
			for (i = 0; i < 512; i++)
				data_page[i] = (u64)(i + 1) * 0x1234567890ABCDEFull;
		} else {
			/*
			 * VMCS already configured — reload guest code and
			 * data pages (reset state for a fresh run).
			 */
			memcpy(page_address(state->guest_code_page),
			       phantom_trivial_guest_bin,
			       sizeof(phantom_trivial_guest_bin));

			data_page = (u64 *)page_address(state->guest_data_page);
			for (i = 0; i < 512; i++)
				data_page[i] = (u64)(i + 1) * 0x1234567890ABCDEFull;

			/* Reset RIP/RSP for fresh execution */
			state->launched = false;
		}

		/* Run guest on target CPU */
		work.state  = state;
		work.result = 0;

		smp_call_function_single(target_cpu,
					 phantom_run_guest_on_cpu,
					 &work, 1);

		if (work.result < 0) {
			ret = work.result;
			break;
		}

		/*
		 * Reset guest RIP and RSP in VMCS for next run.
		 * This requires being on the target CPU.
		 */

		/* Populate output args */
		args.result      = state->run_result_data;
		args.exit_reason = state->exit_reason;

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
