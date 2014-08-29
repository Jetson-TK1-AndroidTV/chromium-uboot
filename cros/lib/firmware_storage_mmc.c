/*
 * Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

/* Implementation of firmware storage access interface for MMC */

#include <common.h>
#include <errno.h>
#include <fdtdec.h>
#include <libfdt.h>
#include <malloc.h>
#include <mmc.h>
#include <cros/common.h>
#include <cros/cros_fdtdec.h>
#include <cros/firmware_storage.h>

DECLARE_GLOBAL_DATA_PTR;

struct vboot_mmc {
	struct mmc *mmc;
	int device;
	u32 ro_section_size;	/* Offsets bigger are on partition 2 */
};

/*
 * Determine which boot partition the access falls within.
 *
 * Return partition number, or -EINVAL if discontinuous
 */
static int check_partition(struct vboot_mmc *vboot_mmc, uint32_t offset,
			   uint32_t count)
{
	int partition = 1;

	/*
	 * Check continuity
	 * If it starts in partition 1, and ends in partition 2, things
	 * will not go well.
	 */
	if (offset < vboot_mmc->ro_section_size &&
	    offset + count >= vboot_mmc->ro_section_size) {
		VBDEBUG("Boot partition access not contiguous\n");
		return -EINVAL;
	}

	/* Offsets not in the RO section must be in partition 2 */
	if (offset >= vboot_mmc->ro_section_size)
		partition = 2;

	return partition;
}

static int read_mmc(firmware_storage_t *file, uint32_t offset, uint32_t count,
		    void *buf)
{
	struct vboot_mmc *vboot_mmc = file->context;
	int partition, err;
	u8 *tmp_buf;
	int n, ret = -1;
	int start_block, start_block_offset, end_block, total_blocks;

	VBDEBUG("offset=%#x, count=%#x\n", offset, count);
	partition = check_partition(vboot_mmc, offset, count);
	if (partition < 0)
		return -1;

	if (partition == 2) {
		VBDEBUG("Reading from partition 2\n");
		offset -= vboot_mmc->ro_section_size;
	}

	start_block = offset / MMC_MAX_BLOCK_LEN;
	start_block_offset = offset % MMC_MAX_BLOCK_LEN;
	end_block = (offset + count) / MMC_MAX_BLOCK_LEN;

	/* Read start to end, inclusive */
	total_blocks = end_block - start_block + 1;

	VBDEBUG("Reading %d blocks\n", total_blocks);

	tmp_buf = malloc(MMC_MAX_BLOCK_LEN*total_blocks);
	if (!tmp_buf) {
		VBDEBUG("Failed to allocate buffer\n");
		goto out;
	}

	/* Open partition */
	err = mmc_part_access(vboot_mmc->mmc, partition);
	if (err) {
		VBDEBUG("Failed to open boot partition %d\n", partition);
		goto out_free;
	}

	/* Read data */
	n = vboot_mmc->mmc->block_dev.block_read(vboot_mmc->device,
						 start_block, total_blocks,
						 tmp_buf);
	if (n != total_blocks) {
		VBDEBUG("Failed to read blocks\n");
		goto out_close;
	}

	/* Copy to output buffer */
	memcpy(buf, tmp_buf + start_block_offset, count);

	ret = 0;

out_close:
	/* Close partition */
	err = mmc_part_access(vboot_mmc->mmc, 0);
	if (err) {
		VBDEBUG("Failed to close boot partition\n");
		ret = -1;
	}

out_free:
	free(tmp_buf);
out:
	return ret;
}

/*
 * Does not support unaligned writes.
 * Offset and count must be offset aligned.
 */
static int write_mmc(firmware_storage_t *file, uint32_t offset, uint32_t count,
		void *buf)
{
	struct vboot_mmc *vboot_mmc = file->context;
	uint32_t num, start_block, total_blocks;
	int partition, err, ret = 0;

	/* Writes not aligned to block size are unsupported. */
	if (offset % MMC_MAX_BLOCK_LEN) {
		VBDEBUG("Offset of %d bytes not aligned to 512 byte boundary\n",
			offset);
		return -1;
	}

	if (count % MMC_MAX_BLOCK_LEN) {
		VBDEBUG("Count of %d bytes not aligned to 512 byte boundary\n",
			count);
		return -1;
	}

	/* Determine partition */
	partition = check_partition(vboot_mmc, offset, count);
	if (partition < 0)
		return -1;

	if (partition == 2) {
		VBDEBUG("Writing to partition 2\n");
		offset -= vboot_mmc->ro_section_size;
	}

	start_block = offset / MMC_MAX_BLOCK_LEN;
	total_blocks = count / MMC_MAX_BLOCK_LEN;

	/* Open partition */
	err = mmc_part_access(vboot_mmc->mmc, partition);
	if (err) {
		VBDEBUG("Failed to open boot partition %d\n", partition);
		return -1;
	}

	/* Write data */
	num = vboot_mmc->mmc->block_dev.block_write(vboot_mmc->device,
						    start_block, total_blocks,
						    buf);
	if (num != total_blocks) {
		VBDEBUG("Failed to write blocks\n");
		ret = -1;
		goto out;
	}

out:
	/* Close partition */
	err = mmc_part_access(vboot_mmc->mmc, 0);
	if (err) {
		VBDEBUG("Failed to close boot partition\n");
		return -1;
	}

	return ret;
}

static int close_mmc(firmware_storage_t *file)
{
	free(file->context);
	return 0;
}

static int sw_wp_enabled_mmc(firmware_storage_t *file)
{
	struct vboot_mmc *vboot_mmc = file->context;

	return mmc_get_boot_wp(vboot_mmc->mmc);
}

int firmware_storage_open(firmware_storage_t *file)
{
	const void *blob = gd->fdt_blob;
	struct mmc *mmc;
	int node, parent, err;
	struct fmap_entry entry;
	struct vboot_mmc *vboot_mmc;

	node = cros_fdtdec_config_node(blob);
	if (node < 0)
		return -1;

	node = fdtdec_lookup_phandle(blob, node, "firmware-storage");
	if (node < 0) {
		VBDEBUG("fail to look up phandle: %d\n", node);
		return -1;
	}

	parent = fdt_parent_offset(blob, node);
	if (parent < 0) {
		VBDEBUG("fail to look up MMC parent: %d\n", parent);
		return -1;
	}

	mmc = mmc_get_device_by_node(blob, parent);
	if (!mmc) {
		VBDEBUG("fail to find MMC for node %d\n", parent);
		return -1;
	}

	err = mmc_init(mmc);
	if (err) {
		VBDEBUG("fail to initialize MMC: error %d\n", err);
		return -1;
	}

	/* Lookup partition size */
	node = fdt_path_offset(blob, "/flash/wp-ro");
	if (node < 0) {
		VBDEBUG("fail to lookup ro section\n");
		return -1;
	}

	err = fdtdec_read_fmap_entry(blob, node, "wp-ro", &entry);
	if (err) {
		VBDEBUG("fail to determine ro section size\n");
		return -1;
	}

	vboot_mmc = malloc(sizeof(*vboot_mmc));
	if (!vboot_mmc) {
		VBDEBUG("fail to allocate context structure\n");
		return -1;
	}

	vboot_mmc->mmc = mmc;
	vboot_mmc->device = mmc->block_dev.dev;
	vboot_mmc->ro_section_size = entry.length;

	file->context = vboot_mmc;
	file->read = read_mmc;
	file->write = write_mmc;
	file->close = close_mmc;
	file->sw_wp_enabled = sw_wp_enabled_mmc;

	return 0;
}
