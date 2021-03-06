/*
 * Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

#include <common.h>
#include <cros/common.h>
#include <cros/nvstorage.h>
#include <cros/vboot.h>

/* Import the header files from vboot_reference. */
#include <vboot_api.h>

/*
 * We had a discussion about the non-volatile storage device for keeping
 * the cookies. Due to the lack of SPI flash driver in kernel, kernel cannot
 * access cookies in SPI flash. So the final descision is to store the
 * cookies in eMMC device where we are certain that kernel can access.
 */

/*
 * Gets the first internal disk and caches the result in a static variable.
 * Returns 0 for success, non-zero for failure.
 */
static int get_internal_disk(VbDiskInfo **disk_ptr)
{
	static VbDiskInfo internal_disk;

	if (internal_disk.handle == NULL) {
		VbDiskInfo *disk_info;
		uint32_t disk_count;

		if (VbExDiskGetInfo(&disk_info, &disk_count,
				VB_DISK_FLAG_FIXED) || disk_count == 0) {
			VBDEBUG("No internal disk found!\n");
			return 1;
		}
		internal_disk = disk_info[0];
		VbExDiskFreeInfo(disk_info, internal_disk.handle);
	}

	*disk_ptr = &internal_disk;
	return 0;
}

/*
 * Allocates 1-block-sized memory to block_buf_ptr and fills it as the first
 * block of the disk.
 * Returns 0 for success, non-zero for failure.
 */
static int get_nvcxt_block_of_disk(const VbDiskInfo *disk,
		uint8_t **block_buf_ptr)
{
	uint8_t *block_buf = NULL;

	block_buf = VbExMalloc(disk->bytes_per_lba);

	if (VbExDiskRead(disk->handle,
				CHROMEOS_VBNVCONTEXT_LBA, 1, block_buf)) {
		VBDEBUG("Failed to read internal disk!\n");
		VbExFree(block_buf);
		return 1;
	}

	*block_buf_ptr = block_buf;
	return 0;
}

static VbError_t nvstorage_read_disk(uint8_t *buf)
{
	VbDiskInfo *internal_disk;
	uint8_t *block_buf;

	if (get_internal_disk(&internal_disk))
		return 1;

	if (get_nvcxt_block_of_disk(internal_disk, &block_buf))
		return 1;

	memcpy(buf, block_buf, VBNV_BLOCK_SIZE);

	VbExFree(block_buf);
	return VBERROR_SUCCESS;
}

static VbError_t nvstorage_write_disk(const uint8_t *buf)
{
	VbDiskInfo *internal_disk;
	uint8_t *block_buf;

	if (get_internal_disk(&internal_disk))
		return 1;

	if (get_nvcxt_block_of_disk(internal_disk, &block_buf))
		return 1;

	memcpy(block_buf, buf, VBNV_BLOCK_SIZE);

	if (VbExDiskWrite(internal_disk->handle,
				CHROMEOS_VBNVCONTEXT_LBA, 1, block_buf)) {
		VBDEBUG("Failed to write internal disk!\n");
		VbExFree(block_buf);
		return 1;
	}

	VbExFree(block_buf);

#ifdef CONFIG_EXYNOS5
	/*
	 * XXX(chrome-os-partner:10415): On Exynos, reliable write operations
	 * need write busy time; so add a delay here.  In the long run, we
	 * should avoid using eMMC as VbNvContext storage media.
	 */
	mdelay(1);
#endif

	return VBERROR_SUCCESS;
}

static int nvstorage_read_fdt_disk(struct vboot_info *vboot, const void *blob,
				   int node)
{
	vboot->nvcontext_lba = fdtdec_get_int(blob, node,
					"nonvolatile-context-lba", -1);
	vboot->nvcontext_offset = fdtdec_get_int(blob, node,
					"nonvolatile-context-offset", -1);
	vboot->nvcontext_size = fdtdec_get_int(blob, node,
					"nonvolatile-context-size", 0);

	return 0;
}

static int nvstorage_write_fdt_disk(const struct vboot_info *vboot, void *blob,
				    int node)
{
	int ret;

	ret = fdt_setprop_cell(blob, node, "nonvolatile-context-lba",
			       vboot->nvcontext_lba);
	if (!ret) {
		ret = fdt_setprop_cell(blob, node,
				       "nonvolatile-context-offset",
				       vboot->nvcontext_offset);
	}
	if (!ret) {
		ret = fdt_setprop_cell(blob, node, "nonvolatile-context-size",
				       vboot->nvcontext_size);
	}

	return 0;
}

static void nvstorage_dump_disk(const struct vboot_info *vboot)
{
	VBDEBUG(" %-30s: lba=%08lx, offset=%08x, size=%08x\n",	__func__,
		(ulong)vboot->nvcontext_lba, vboot->nvcontext_offset,
		vboot->nvcontext_size);
}

CROS_NVSTORAGE_METHOD(disk) = {
	.name = "disk",
	.read = nvstorage_read_disk,
	.write = nvstorage_write_disk,
	.read_fdt = nvstorage_read_fdt_disk,
	.write_fdt = nvstorage_write_fdt_disk,
	.dump = nvstorage_dump_disk,
};
