// SPDX-License-Identifier: GPL-2.0-only
/*
 * interface.h — /dev/phantom chardev declarations
 *
 * Exposes the chardev file operations and the ioctl registration
 * entry points.  The ioctl command numbers are defined here so that
 * both kernel (interface.c) and userspace test binaries can include
 * a single authoritative header.
 */
#ifndef PHANTOM_INTERFACE_H
#define PHANTOM_INTERFACE_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* ------------------------------------------------------------------
 * Version encoding: 0xMMmmpp  (Major . minor . patch)
 * Task 1.1 baseline: version 1.1.0 = 0x00010100
 * ------------------------------------------------------------------ */
#define PHANTOM_VERSION		0x00010100U

/* ------------------------------------------------------------------
 * ioctl command numbers
 *
 * Magic byte 'P' (0x50).  Only GET_VERSION is implemented in task 1.1;
 * further commands are reserved for later phases.
 * ------------------------------------------------------------------ */
#define PHANTOM_IOCTL_MAGIC		'P'

/* _IOR: read-only from userspace perspective (kernel writes the result) */
#define PHANTOM_IOCTL_GET_VERSION	_IOR(PHANTOM_IOCTL_MAGIC, 0, __u32)

/*
 * Reserved for future phases — not implemented yet:
 *
 * PHANTOM_IOCTL_CREATE_INSTANCE	_IOW(PHANTOM_IOCTL_MAGIC, 1, ...)
 * PHANTOM_IOCTL_DESTROY_INSTANCE	_IOW(PHANTOM_IOCTL_MAGIC, 2, __u32)
 * PHANTOM_IOCTL_RUN_ITERATION		_IOWR(PHANTOM_IOCTL_MAGIC, 3, ...)
 * PHANTOM_IOCTL_GET_STATUS		_IOR(PHANTOM_IOCTL_MAGIC, 4, ...)
 */

/* ------------------------------------------------------------------
 * Forward declaration — struct phantom_dev is defined in phantom.h
 * ------------------------------------------------------------------ */
struct phantom_dev;

/**
 * phantom_chardev_register - Allocate device number and register cdev.
 * @pdev: Device context; cdev, class, and devno are populated on success.
 *
 * Creates /dev/phantom via udev/mdev notification.
 * Returns 0 on success, negative errno on failure.
 */
int phantom_chardev_register(struct phantom_dev *pdev);

/**
 * phantom_chardev_unregister - Remove cdev and release device number.
 * @pdev: Device context.
 *
 * Safe to call if phantom_chardev_register() partially succeeded.
 */
void phantom_chardev_unregister(struct phantom_dev *pdev);

#endif /* PHANTOM_INTERFACE_H */
