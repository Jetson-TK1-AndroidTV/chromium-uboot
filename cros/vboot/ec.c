/*
 * Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

#include <common.h>
#include <asm/global_data.h>
#include <cros/common.h>
#include <cros/firmware_storage.h>
#include <cros/vboot_flag.h>
#include <malloc.h>
#include <cros_ec.h>
#include <vboot_api.h>

DECLARE_GLOBAL_DATA_PTR;

/* We support corrupting a byte of the EC image */
static int corrupt_offset = -1;	/* offset into image to corrupt */
static uint8_t corrupt_byte;		/* new byte value at that offset */


void cros_ec_set_corrupt_image(int offset, int byte)
{
	corrupt_offset = offset;
	corrupt_byte = byte;
}

int VbExTrustEC(int devidx)
{
	struct vboot_flag_details gpio_ec_in_rw;
	int okay;

	if (devidx != 0)
		return 0;

	/* If we don't have a valid GPIO to read, we can't trust it. */
	if (vboot_flag_fetch(VBOOT_FLAG_EC_IN_RW, &gpio_ec_in_rw)) {
		VBDEBUG("can't find GPIO to read, returning 0\n");
		return 0;
	}

	/* We only trust it if it's NOT in its RW firmware. */
	okay = !gpio_ec_in_rw.value;

	VBDEBUG("port=%d value=%d, returning %d\n",
		gpio_ec_in_rw.port, gpio_ec_in_rw.value, okay);

	return okay;
}

VbError_t VbExEcRunningRW(int devidx, int *in_rw)
{
	struct cros_ec_dev *mdev = board_get_cros_ec_dev();
	enum ec_current_image image;

	if (devidx != 0)
		return VBERROR_UNKNOWN;

	if (!mdev) {
		VBDEBUG("%s: no cros_ec device\n", __func__);
		return VBERROR_UNKNOWN;
	}

	if (cros_ec_read_current_image(mdev, &image) < 0)
		return VBERROR_UNKNOWN;

	switch (image) {
	case EC_IMAGE_RO:
		*in_rw = 0;
		break;
	case EC_IMAGE_RW:
		*in_rw = 1;
		break;
	default:
		return VBERROR_UNKNOWN;
	}

	return VBERROR_SUCCESS;
}

VbError_t VbExEcJumpToRW(int devidx)
{
	struct cros_ec_dev *mdev = board_get_cros_ec_dev();

	if (devidx != 0)
		return VBERROR_UNKNOWN;

	if (!mdev) {
		VBDEBUG("%s: no cros_ec device\n", __func__);
		return VBERROR_UNKNOWN;
	}

	if (cros_ec_reboot(mdev, EC_REBOOT_JUMP_RW, 0) < 0)
		return VBERROR_UNKNOWN;

	return VBERROR_SUCCESS;
}

VbError_t VbExEcDisableJump(int devidx)
{
	struct cros_ec_dev *mdev = board_get_cros_ec_dev();

	if (devidx != 0)
		return VBERROR_UNKNOWN;

	if (!mdev) {
		VBDEBUG("%s: no cros_ec device\n", __func__);
		return VBERROR_UNKNOWN;
	}

	if (cros_ec_reboot(mdev, EC_REBOOT_DISABLE_JUMP, 0) < 0)
		return VBERROR_UNKNOWN;

	return VBERROR_SUCCESS;
}

VbError_t VbExEcHashImage(int devidx, enum VbSelectFirmware_t select,
			  const uint8_t **hash, int *hash_size)
{
	struct cros_ec_dev *mdev = board_get_cros_ec_dev();
	static struct ec_response_vboot_hash resp __aligned(8);

	if (devidx != 0 || select == VB_SELECT_FIRMWARE_READONLY)
		return VBERROR_UNKNOWN;

	if (!mdev) {
		VBDEBUG("%s: no cros_ec device\n", __func__);
		return VBERROR_UNKNOWN;
	}

	if (cros_ec_read_hash(mdev, &resp) < 0)
		return VBERROR_UNKNOWN;

	if (resp.status != EC_VBOOT_HASH_STATUS_DONE)
		return VBERROR_UNKNOWN;
	if (resp.hash_type != EC_VBOOT_HASH_TYPE_SHA256)
		return VBERROR_UNKNOWN;

	*hash = resp.hash_digest;
	*hash_size = resp.digest_size;

	return VBERROR_SUCCESS;
}

static VbError_t ec_protect_rw(int protect)
{
	struct cros_ec_dev *mdev = board_get_cros_ec_dev();
	struct ec_response_flash_protect resp;
	uint32_t mask = EC_FLASH_PROTECT_ALL_NOW | EC_FLASH_PROTECT_ALL_AT_BOOT;

	if (!mdev) {
		VBDEBUG("%s: no cros_ec device\n", __func__);
		return VBERROR_UNKNOWN;
	}

	/* Update protection */
	if (cros_ec_flash_protect(mdev, mask, protect ? mask : 0, &resp) < 0)
		return VBERROR_UNKNOWN;

	if (!protect) {
		/* If protection is still enabled, need reboot */
		if (resp.flags & EC_FLASH_PROTECT_ALL_NOW)
			return VBERROR_EC_REBOOT_TO_RO_REQUIRED;

		return VBERROR_SUCCESS;
	}

	/*
	 * If write protect and ro-at-boot aren't both asserted, don't expect
	 * protection enabled.
	 */
	if ((~resp.flags) & (EC_FLASH_PROTECT_GPIO_ASSERTED |
			     EC_FLASH_PROTECT_RO_AT_BOOT))
		return VBERROR_SUCCESS;

	/* If flash is protected now, success */
	if (resp.flags & EC_FLASH_PROTECT_ALL_NOW)
		return VBERROR_SUCCESS;

	/* If RW will be protected at boot but not now, need a reboot */
	if (resp.flags & EC_FLASH_PROTECT_ALL_AT_BOOT)
		return VBERROR_EC_REBOOT_TO_RO_REQUIRED;

	/* Otherwise, it's an error */
	return VBERROR_UNKNOWN;
}

VbError_t VbExEcUpdateImage(int devidx, enum VbSelectFirmware_t select,
			    const uint8_t *image, int image_size)
{
	struct cros_ec_dev *mdev = board_get_cros_ec_dev();
	int rv;

	if (devidx != 0 || select == VB_SELECT_FIRMWARE_READONLY)
		return VBERROR_UNKNOWN;

	if (!mdev) {
		VBDEBUG("%s: no cros_ec device\n", __func__);
		return VBERROR_UNKNOWN;
	}

	rv = ec_protect_rw(0);
	if (rv == VBERROR_EC_REBOOT_TO_RO_REQUIRED)
		return rv;
	else if (rv != VBERROR_SUCCESS)
		return rv;

	rv = cros_ec_flash_update_rw(mdev, image, image_size);
	return rv == 0 ? VBERROR_SUCCESS : VBERROR_UNKNOWN;
}

VbError_t VbExEcProtect(int devidx, enum VbSelectFirmware_t select)
{
	if (devidx != 0 || select == VB_SELECT_FIRMWARE_READONLY)
		return VBERROR_UNKNOWN;

	return ec_protect_rw(1);
}

VbError_t VbExEcEnteringMode(int devidx, enum VbEcBootMode_t mode)
{
	struct cros_ec_dev *mdev = board_get_cros_ec_dev();

	if (devidx != 0)
		return VBERROR_UNKNOWN;

	if (!mdev) {
		VBDEBUG("%s: no cros_ec device\n", __func__);
		return VBERROR_UNKNOWN;
	}
	return cros_ec_entering_mode(mdev, mode);
}

VbError_t VbExEcGetExpectedImage(int devidx, enum VbSelectFirmware_t select,
				 const uint8_t **image, int *image_size)
{
	struct fmap_firmware_entry *fw_entry;
	struct twostop_fmap fmap;
	uint32_t offset;
	firmware_storage_t file;
	uint8_t *buf;
	int size;

	*image = NULL;
	*image_size = 0;

	if (devidx != 0 || select == VB_SELECT_FIRMWARE_READONLY)
		return VBERROR_UNKNOWN;

	cros_fdtdec_flashmap(gd->fdt_blob, &fmap);
	switch (select) {
	case VB_SELECT_FIRMWARE_A:
		fw_entry = &fmap.readwrite_a;
		break;
	case VB_SELECT_FIRMWARE_B:
		fw_entry = &fmap.readwrite_b;
		break;
	default:
		VBDEBUG("Unrecognized EC firmware requested.\n");
		return VBERROR_UNKNOWN;
	}

	if (firmware_storage_open(&file)) {
		VBDEBUG("Failed to open firmware storage.\n");
		return VBERROR_UNKNOWN;
	}

	offset = fw_entry->ec_rw.offset;
	size = fw_entry->ec_rw.used;
	VBDEBUG("EC-RW image offset %#x used %#x.\n", offset, size);

	/* Sanity-check; we don't expect EC images > 1MB */
	if (size <= 0 || size > 0x100000) {
		VBDEBUG("EC image has bogus size.\n");
		return VBERROR_UNKNOWN;
	}

	/*
	 * Note: this leaks memory each call, since we don't track the pointer
	 * and the caller isn't expecting to free it.
	 */
	buf = malloc(size);
	if (!buf) {
		VBDEBUG("Failed to allocate space for the EC RW image.\n");
		return VBERROR_UNKNOWN;
	}

	if (file.read(&file, offset, size, buf)) {
		free(buf);
		VBDEBUG("Failed to read the EC from flash.\n");
		return VBERROR_UNKNOWN;
	}

	file.close(&file);

	/* Corrupt a byte if requested */
	if (corrupt_offset >= 0 && corrupt_offset < size)
		buf[corrupt_offset] = corrupt_byte;

	*image = buf;
	*image_size = size;
	return VBERROR_SUCCESS;
}

VbError_t VbExEcGetExpectedImageHash(int devidx, enum VbSelectFirmware_t select,
				     const uint8_t **hash, int *hash_size)
{
	struct twostop_fmap fmap;
	struct fmap_entry *ec;

	*hash = NULL;

	if (devidx != 0 || select == VB_SELECT_FIRMWARE_READONLY)
		return VBERROR_UNKNOWN;

	/* TODO: Decode the flashmap once and reuse throughout. */
	cros_fdtdec_flashmap(gd->fdt_blob, &fmap);
	switch (select) {
	case VB_SELECT_FIRMWARE_A:
		ec = &fmap.readwrite_a.ec_rw;
		break;
	case VB_SELECT_FIRMWARE_B:
		ec = &fmap.readwrite_b.ec_rw;
		break;
	default:
		return VBERROR_UNKNOWN;
	}
	if (!ec->hash) {
		VBDEBUG("Failed to read EC hash.\n");
		return VBERROR_UNKNOWN;
	}
	*hash = ec->hash;
	*hash_size = ec->hash_size;

	return VBERROR_SUCCESS;
}
