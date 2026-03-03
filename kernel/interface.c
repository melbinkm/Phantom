// SPDX-License-Identifier: GPL-2.0-only
/*
 * interface.c — /dev/phantom chardev: open, release, ioctl
 *
 * Responsibilities (task 1.1):
 *   - Allocate dynamic device number
 *   - Register character device with the kernel
 *   - Create device class and device node (triggers udev/mdev)
 *   - Dispatch PHANTOM_IOCTL_GET_VERSION
 *
 * Future phases will add:
 *   - CREATE_INSTANCE / DESTROY_INSTANCE
 *   - RUN_ITERATION (blocking ioctl that enters guest and returns result)
 *   - mmap for payload buffer, coverage bitmap, PT trace buffer
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/errno.h>

#include "phantom.h"
#include "interface.h"
#include "compat.h"

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
	/* No per-fd state in task 1.1 */
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
 * Steps:
 *   1. Allocate a dynamic major/minor pair
 *   2. Init and add the cdev
 *   3. Create the device class
 *   4. Create the device node (triggers udev / mdev)
 *
 * On any failure the function cleans up resources already allocated
 * before returning the error.
 */
int phantom_chardev_register(struct phantom_dev *pdev)
{
	int ret;

	/* Step 1: allocate device number */
	ret = alloc_chrdev_region(&pdev->devno, 0, 1, PHANTOM_DEVICE_NAME);
	if (ret) {
		pr_err("phantom: failed to allocate chardev region: %d\n", ret);
		return ret;
	}

	/* Step 2: initialise and add cdev */
	cdev_init(&pdev->cdev, &phantom_fops);
	pdev->cdev.owner = THIS_MODULE;

	ret = cdev_add(&pdev->cdev, pdev->devno, 1);
	if (ret) {
		pr_err("phantom: cdev_add failed: %d\n", ret);
		goto fail_cdev;
	}

	/* Step 3: create device class */
	pdev->class = phantom_class_create(PHANTOM_CLASS_NAME);
	if (IS_ERR(pdev->class)) {
		ret = PTR_ERR(pdev->class);
		pr_err("phantom: class_create failed: %d\n", ret);
		pdev->class = NULL;
		goto fail_class;
	}

	/* Step 4: create device node */
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
 *
 * Safe to call even if phantom_chardev_register() only partially
 * succeeded — each step is guarded by a NULL check.
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
