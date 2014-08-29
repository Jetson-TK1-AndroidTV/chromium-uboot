/*
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

#ifndef CHROMEOS_NVSTORAGE_H_
#define CHROMEOS_NVSTORAGE_H_

#include <vboot_api.h>

struct vboot_info;

/*
 * When the disk-based NV context driver is used, the VbNvContext is stored
 * in block 0, which is also the MBR on x86 platforms but generally unused on
 * ARM platforms.  Given this, it is not a perfect place for storing stuff,
 * but since there are no fixed blocks that we may use reliably, block 0 is
 * our only option left.
 *
 * For MMC booting machines it may be appropriate to put this in the boot
 * region. Note that it changes fairly regularly with software updates and
 * other system events.
 *
 * TODO(sjg@chromium.org): Actually this value is in the device tree, so it
 * should be not be hard-coded like this.
 */
#define CHROMEOS_VBNVCONTEXT_LBA	0

struct nvstorage_method {
	const char *name;
	VbError_t (*read)(uint8_t *buf);
	VbError_t (*write)(const uint8_t *buf);
	/**
	 * read_fdt() - Read method information from device tree
	 *
	 * @blob: Device tree to read from
	 * @offset: Node offset in device tree to read from
	 * @vboot: Place to put the data that is read
	 * @return 0 if OK, -FDT_ERR_... on error
	 */
	int (*read_fdt)(struct vboot_info *vboot, const void *blob,
			int offset);
	/**
	 * write_fdt() - Write method information to device tree
	 *
	 * @blob: Device tree to write to
	 * @offset: Node offset in device tree to write to
	 * @vboot: Place containing data to be written
	 * @return 0 if OK, -FDT_ERR_... on error
	 */
	int (*write_fdt)(const struct vboot_info *vboot, void *blob,
			 int offset);
	/**
	 * dump() - Dump out nvstorage information
	 *
	 * @vboot: Place containing data to be written
	 */
	void (*dump)(const struct vboot_info *vboot);
};

/**
 * Select the configured non-volatile storage driver
 *
 * @return 0 if OK, -ve on error
 */
int nvstorage_init(void);

/**
 * Get current non-volatile storage method
 *
 * @return	Current method structure for non-volatile storage, or NULL
 *		if there is no method.
 */
struct nvstorage_method *nvstorage_get_method(void);

/**
 * Set the current non-volatile storage method
 *
 * @param method	Pointer to storage method
 */
void nvstorage_set_method(struct nvstorage_method *method);

/**
 * Find a non-volatile storage method by name
 *
 * @param name	Name to to method to search for
 * @return pointer to storage method, or NULL if not found
 */
struct nvstorage_method *nvstorage_find_name(const char *name);

/**
 * Set new non-volatile storage type
 *
 * @param name	New storage type, a string
 * @return	0 on success, non-0 on error.
 */
int nvstorage_set_name(const char *name);

/*
 * Declare a non-volatile storage method, capable of accessing vboot context.
 * This is a 16-byte region used to remember things like recovery request and
 * reason.
 */
#define CROS_NVSTORAGE_METHOD(_name) \
	ll_entry_declare(struct nvstorage_method, _name, nvstorage_method)

#endif /* CHROMEOS_NVSTORAGE_H_ */
