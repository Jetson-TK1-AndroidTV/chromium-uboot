/*
 * Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

/* Interface for access various storage device */

#ifndef CHROMEOS_FIRMWARE_STORAGE_H_
#define CHROMEOS_FIRMWARE_STORAGE_H_

#include <cros/cros_fdtdec.h>

/**
 * These read or write [count] bytes starting from [offset] of storage into or
 * from the [buf].
 *
 * @param file is the device you access
 * @param offset is where on the device you access
 * @param count is the amount of data in byte you access
 * @param buf is the data that these functions read from or write to
 * @return 0 if it succeeds, non-zero if it fails
 */
typedef struct firmware_storage_t {
	int (*read)(struct firmware_storage_t *file,
			uint32_t offset, uint32_t count, void *buf);
	int (*write)(struct firmware_storage_t *file,
			uint32_t offset, uint32_t count, void *buf);
	int (*close)(struct firmware_storage_t *file);

	/**
	 * Determine if software write protect is enabled
	 *
	 * @param file	device to access
	 * @return	1 if sw wp is enabled, 0 if disabled.
	 */
	int (*sw_wp_enabled)(struct firmware_storage_t *file);

	void *context; /* device driver's private data */
} firmware_storage_t;

/**
 * Opens the firmware storage device
 *
 * Opens the built in firmware storage driver
 *
 * @param file - the open firmware storage device
 * @return 0 if successful, non-zero on error
 */
int firmware_storage_open(firmware_storage_t *file);

int firmware_storage_open_twostop(firmware_storage_t *file,
		struct twostop_fmap *fmap);

#endif /* CHROMEOS_FIRMWARE_STORAGE_H_ */
