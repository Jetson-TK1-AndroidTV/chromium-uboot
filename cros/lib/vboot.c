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
#include <mapmem.h>
#include <asm/errno.h>
#include <asm/io.h>
#include <cros_ec.h>
#include <cros/power_management.h>
#include <cros/vboot.h>
#include <cros/gbb.h>
#ifdef CONFIG_X86
#include <asm/arch/sysinfo.h>
#endif

static struct vboot_info s_vboot;

struct vboot_info *vboot_get(void)
{
	return s_vboot.valid ? &s_vboot : NULL;
}

struct vboot_info *vboot_get_nocheck(void)
{
	return &s_vboot;
}

int vboot_load_config(const void *blob, struct vboot_info *vboot)
{
	int node;

	node = cros_fdtdec_config_node(blob);
	if (node < 0)
		return -1;

	if (fdtdec_get_bool(blob, node, "early-firmware-selection")) {
		vboot->use_efs = true;
		puts("Early firmware selection enabled");
	}

	if (fdtdec_get_bool(blob, node, "early-firmware-verification")) {
		vboot->early_firmware_verification = true;
		puts(" (with early verify)");
	}
	puts("\n");

	if (vboot->use_efs && vboot_persist_init(blob, vboot))
		return -1;

	return 0;
}

/* Request the EC reboot to RO when the AP shuts down. */
int vboot_request_ec_reboot_to_ro(void)
{
#ifdef CONFIG_CROS_EC
	struct cros_ec_dev *mdev = board_get_cros_ec_dev();

	if (!mdev) {
		VBDEBUG("%s: no cro_ec device: cannot request EC reboot to RO\n",
			__func__);
		return -1;
	}

	return cros_ec_reboot(mdev, EC_REBOOT_COLD,
			      EC_REBOOT_FLAG_ON_AP_SHUTDOWN);
#else
	return 0;
#endif
}

int vboot_set_error(struct vboot_info *vboot, const char *stage,
		    enum VbErrorPredefined_t err)
{
	VBDEBUG("Stage '%s' produced vboot error %#x\n", stage, err);
	vboot->vb_error = err;

	return -1;
}

void vboot_init_cparams(struct vboot_info *vboot, VbCommonParams *cparams)
{
#ifdef VBOOT_GBB_DATA
	cparams->gbb_data = vboot->gbb;
	cparams->gbb_size = vboot->fmap.readonly.gbb.length;
#endif
#ifdef CONFIG_SYS_COREBOOT
	cparams->shared_data_blob =
		&((chromeos_acpi_t *)lib_sysinfo.vdat_addr)->vdat;
	cparams->shared_data_size =
		sizeof(((chromeos_acpi_t *)lib_sysinfo.vdat_addr)->vdat);
#else
	cparams->shared_data_blob = vboot->vb_shared_data;
	cparams->shared_data_size = VB_SHARED_DATA_REC_SIZE;
#endif
	vboot->cparams.caller_context = vboot;
	VBDEBUG("cparams:\n");
#ifdef VBOOT_GBB_DATA
	VBDEBUG("- %-20s: %08x\n", "gbb_data",
		map_to_sysmem(cparams->gbb_data));
	VBDEBUG("- %-20s: %08x\n", "gbb_size", cparams->gbb_size);
#endif
	VBDEBUG("- %-20s: %08x\n", "shared_data_blob",
		(unsigned)map_to_sysmem(cparams->shared_data_blob));
	VBDEBUG("- %-20s: %08x\n", "shared_data_size",
		cparams->shared_data_size);
}

#ifdef CONFIG_VBOOT_REGION_READ
VbError_t VbExRegionRead(VbCommonParams *cparams,
			 enum vb_firmware_region region, uint32_t offset,
			 uint32_t size, void *buf)
{
	struct vboot_info *vboot = cparams->caller_context;
	firmware_storage_t *file = &vboot->file;

	if (region != VB_REGION_GBB) {
		VBDEBUG("Only GBB region is supported, region=%d\n", region);
		return VBERROR_REGION_READ_INVALID;
	}

// 	VBDEBUG("VbExRegionRead, offset=%x, size=%x\n",
// 		vboot->fmap.readonly.gbb.offset + offset, size);
	if (file->read(file, vboot->fmap.readonly.gbb.offset + offset, size,
		       buf)) {
		VBDEBUG("failed to read from gbb offset %x sze %x\n",
			offset, size);
		return VBERROR_REGION_READ_FAILED;
	}

	return 0;
}
#endif /* CONFIG_VBOOT_REGION_READ */

void vboot_persist_clear(struct vboot_info *vboot)
{
	if (vboot->persist) {
		memset(vboot->persist, '\0', sizeof(vboot->persist));
		VBDEBUG("persist: Clearing persist region - all is well\n");
	}
}

int vboot_persist_init(const void *blob, struct vboot_info *vboot)
{
	fdt_addr_t base;
	fdt_size_t size;

	/*
	 * This region is only needed with EFS when we don't verify RW U-Boot
	 * before jumping to RW SPL.
	 */
	if (!vboot->use_efs || vboot->early_firmware_verification)
		return 0;

	if (cros_fdtdec_decode_region(blob, "vboot-persist", ",efs",
				      &base, &size)) {
		VBDEBUG("Cannot find vboot persist region\n");
		return -ENOENT;
	}

	vboot->persist = map_sysmem(base, size);

	/* Init if there is nothing there yet */
	if (vboot->persist->magic != VBOOT_PERSIST_MAGIC) {
		memset(vboot->persist, '\0', sizeof(*vboot->persist));
		vboot->persist->magic = VBOOT_PERSIST_MAGIC;
		VBDEBUG("persist: Starting new persist region at %p\n",
			vboot->persist);
	}

	return 0;
}

void vboot_persist_dump(const char *name, struct vboot_info *vboot)
{
	struct vboot_persist *persist = vboot->persist;

	printf("Vboot persist at %s: ", name);
	if (persist) {
		printf("magic = %#x, flags = %#x\n", persist->magic,
		       persist->flags);
	} else {
		puts("none\n");
	}
}
