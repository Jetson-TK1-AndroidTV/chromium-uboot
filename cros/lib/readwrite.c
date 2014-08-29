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
#include <bootstage.h>
#include <malloc.h>
#include <tss_constants.h>
#include <asm/io.h>
#include <cros/boot_kernel.h>
#include <cros/cros_init.h>
#include <cros/nvstorage.h>
#include <cros/vboot.h>

DECLARE_GLOBAL_DATA_PTR;

int vboot_rw_init(struct vboot_info *vboot)
{
	const void *blob = gd->fdt_blob;
	fdt_addr_t base;
	const void *cdata_fdt;
	fdt_size_t size;

	memset(vboot, '\0', sizeof(*vboot));
	vboot->valid = true;

#ifdef CONFIG_BOOTSTAGE_STASH
	bootstage_unstash((void *)CONFIG_BOOTSTAGE_STASH,
			  CONFIG_BOOTSTAGE_STASH_SIZE);
#endif
	bootstage_mark_name(BOOTSTAGE_ID_ALLOC, "vboot_readwrite");
	VBDEBUG("Starting read-write firmware\n");

	if (cros_init()) {
		VBDEBUG("fail to init cros library\n");
		return -1;
	}

	if (vboot_load_config(blob, vboot)) {
		VBDEBUG("failed to read /chromeos-config\n");
		return -1;
	}

	/* Since we made it to U-Boot RW we can clear the persist info */
	vboot_persist_clear(vboot);

	if (cros_fdtdec_flashmap(blob, &vboot->fmap)) {
		VBDEBUG("failed to decode fmap\n");
		return -1;
	}

	if (cros_fdtdec_decode_region(blob, "cros-system-data",
				      vboot->use_efs ? ",efs" : NULL,
				      &base, &size)) {
		VBDEBUG("Cannot find cdata FDT\n");
		return -1;
	}
	VBDEBUG("Reading cdata from FDT at %08lx\n", (ulong)base);
	cdata_fdt = map_sysmem(base, size);
	if (vboot_read_from_fdt(vboot, cdata_fdt)) {
		VBDEBUG("Cannot read cdata FDT\n");
		return -1;
	}
	VBDEBUG("RO firmware requests '%s'\n", vboot->firmware_type);

	if (!vboot->nvcontext_method) {
		VBDEBUG("No selected nvcontext method\n");
		vboot_dump(vboot);
		return -1;
	}

	/* TODO(sjg@chromium.org): We should not need this - remove? */
	if (firmware_storage_open(&vboot->file)) {
		VBDEBUG("failed to open firmware storage\n");
		return -1;
	}

	/*
	 * VbSelectAndLoadKernel() assumes the TPM interface has already been
	 * initialized by VbSelectFirmware(). Since we haven't called
	 * VbSelectFirmware() in the readwrite firmware, we need to explicitly
	 * initialize the TPM interface. Note that this only re-initializes the
	 * interface, not the TPM itself.
	 */
	if (VbExTpmInit() != TPM_SUCCESS) {
		VBDEBUG("failed to init tpm interface\n");
		return -1;
	}

	return 0;
}

int vboot_rw_select_kernel(struct vboot_info *vboot)
{
	VbSelectAndLoadKernelParams *kparams = &vboot->kparams;
	VbError_t err;
	fdt_addr_t base;
	fdt_size_t size;

	vboot_init_cparams(vboot, &vboot->cparams);
	if (cros_fdtdec_decode_region(gd->fdt_blob, "kernel", NULL,
				      &base, &size)) {
		VBDEBUG("No kernel load address specified\n");
		return -1;
	}
	kparams->kernel_buffer = map_sysmem(base, size);
	kparams->kernel_buffer_size = size;

	VBDEBUG("kparams:\n");
	VBDEBUG("- kernel_buffer:      : %08x\n",
		(unsigned)map_to_sysmem(kparams->kernel_buffer));
	VBDEBUG("- kernel_buffer_size: : %08x\n",
		kparams->kernel_buffer_size);

	err = VbSelectAndLoadKernel(&vboot->cparams, kparams);
	if (err) {
		VBDEBUG("VbSelectAndLoadKernel: %d\n", err);
		vboot_set_error(vboot, "VbSelectAndLoadKernel", err);
		if (err == VBERROR_EC_REBOOT_TO_RO_REQUIRED)
			vboot_request_ec_reboot_to_ro();
		return -1;
	}

	VBDEBUG("kparams:\n");
	VBDEBUG("- kernel_buffer:      : %08x\n",
		(unsigned)map_to_sysmem(kparams->kernel_buffer));
	VBDEBUG("- kernel_buffer_size: : %08x\n", kparams->kernel_buffer_size);
	VBDEBUG("- disk_handle:        : %p\n", kparams->disk_handle);
	VBDEBUG("- partition_number:   : %08x\n", kparams->partition_number);
	VBDEBUG("- bootloader_address: : %08llx\n",
		(unsigned long long)kparams->bootloader_address);
	VBDEBUG("- bootloader_size:    : %08x\n", kparams->bootloader_size);
	VBDEBUG("- partition_guid:     :");
#ifdef VBOOT_DEBUG
	int i;
	for (i = 0; i < 16; i++)
		VbExDebug(" %02x", kparams->partition_guid[i]);
	VbExDebug("\n");
#endif /* VBOOT_DEBUG */

	/*
	 * EC might jump between RO and RW during software sync. We need to
	 * update active EC copy
	 */
	int in_rw = 0;
	int rv;

	/* If software sync is disabled, just leave this as original value. */
	vboot->active_ec_firmware = ACTIVE_EC_FIRMWARE_UNCHANGE;
	if (cros_fdtdec_config_has_prop(gd->fdt_blob, "ec-software-sync")) {
		rv = VbExEcRunningRW(0, &in_rw);
		if (rv == VBERROR_SUCCESS) {
			vboot->active_ec_firmware = in_rw ?
					ACTIVE_EC_FIRMWARE_RW :
					ACTIVE_EC_FIRMWARE_RO;
		}
	}

	vboot_dump(vboot);

	return 0;
}

int vboot_rw_boot(struct vboot_info *vboot)
{
	boot_kernel(vboot, &vboot->kparams, NULL);

	/* Should not get here */
	return -1;
}
