/*
 * Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

#ifndef __VBOOT_H
#define __VBOOT_H

#include <common.h>
#include <crossystem_data.h>
#include <firmware_storage.h>
#include <gbb_header.h>
#include <vboot_api.h>
#include <vboot_flag.h>
#include <cros/common.h>

/* Magic number in the vboot persist header */
#define VBOOT_PERSIST_MAGIC	0xfeed1a3b

/* These values indicate which firmwares have been tried */
enum vboot_persist_flags_t {
	VBOOT_PERSISTF_TRIED_A	= 1 << VB_SELECT_FIRMWARE_A,
	VBOOT_PERSISTF_TRIED_B	= 1 << VB_SELECT_FIRMWARE_B,
};

/**
 * Header for the information that persists in SRAM.
 *
 * This is set up on boot by the RO U-Boot, with the flags set to 0.
 * When an RW SPL fails to verify U-Boot, it sets a flag indicating this and
 * reboots. At that point RO U-Boot can see which firmware has been tried, in
 * VbExHashFirmwareBody(), and fail it before irrevocably jumping to its SPL
 * and then needing to reboot again (and again...).
 *
 * The information is cleared in RW U-Boot, since by then we know we have
 * succeeded in loading our RW firmware. So it only persists across reboot in
 * the case where we are failing. This will happen if the firmware updater
 * updates SPL but does not get around to updating the associated U-Boot.
 */
struct vboot_persist {
	uint32_t magic;		/* VBOOT_PERSIST_MAGIC */
	uint32_t flags;		/* enum vboot_persist_flags_t */
};

/* Signature for the stashed RW SPL */
#define VBOOT_SPL_SIGNATURE	0xf005ba11

/* Header for a stashed RW SPL */
struct vboot_spl_hdr {
	uint32_t signature;	/* VBOOT_SPL_SIGNATURE */
	uint32_t size;		/* Size excluding header */
	uint32_t crc32;		/* crc32 of contents */
	uint32_t spare;		/* Spare word */
};

/**
 * Information about each firmware type. We expect to have read-only (used for
 * RO-normal if enabled), read-write A, read-write B and recovery. Recovery
 * is the same as RO-normal unless EFS is enabled, in which case RO-normal
 * is a small, low-feature version incapable of running recovery, and we
 * have a separate recovery image.
 *
 * @vblock: Pointer to the vblock if loaded - this is NULL except for RW-A and
 *	RW-B
 * @size: Size of firmware in bytes (this is the compressed size if the
 *	firmware is compressed)
 * @cache: Firmware data, if loaded
 * @uncomp_size: Uncompressed size of firmware. Same as @size if it is not
 *	compressed
 * @fw_entry: Pointer to the firmware entry in the fmap - there are three
 *	possible ones: RO, RW-A and RW-B. Note that RO includes recovery if
 *	this is a separate U-Boot from the RO U-Boot.
 * @entry: Pointer to the firmware entry that we plan to load and run.
 *	Normally this is U-Boot, but with EFS it is SPL, since it is the SPL
 *	that is signed by the signer, verified by vboot and jumped to by
 *	RO U-Boot.
 */
struct vboot_fw_info {
	void *vblock;
	uint32_t size;
	void *cache;
	size_t uncomp_size;
	struct fmap_firmware_entry *fw_entry;
	struct fmap_entry *entry;
};

/**
 * Main verified boot data structure
 *
 * @wpsw: Write protect switch information - write-protects the SPI flash
 * @recw: Recovery switch information - forces recovery mode
 * @devw: Developer switch information - forces developer mode
 * @oprom: Option ROM switch information
 * @file: Method for accessing the firmware (SPI / MMC)
 * @gbb_size: Size of GBB region in bytes
 * @oprom_matters: 1 if the option ROM must be loaded
 * @fmap: Flash map layout (tells us where all the images are)
 * @cparams: Common params passed to Vboot library
 * @fparams: Firmware params passed to Vboot library
 * @kparams: Kernel params passed to Vboot library
 * @iparams: Initial params passed to Vboot library
 * @selected_firmware: The firmware that VbSelectFirmware() asks that we boot
 * @firmware_type: String passed to RW U-Boot and the kernel to indicate
 *	our firmware type ("normal", "developer", "recovery")
 * @nvcontext_method: Pointer to method to use to store rhw non-volatile
 *	context. This is typically 16-bytes and stored in the EC. It is fairly
 *	non-volatile, although losing it not critical (e.g. it tells us to
 *	enter recovery mode)
 * @nvcontext_lba: Logical block address (sector number) of NV context when
 *	it is on disk/eMMC.
 * @nvcontext_offset: Offset within that block of the NV context
 * @nvcontext_size: Size of nvcontext
 * @fw_dest: Place where the firmware will be copied for execution
 * @vb_error: Vboot library error, if any
 * @fw: Information about RO, recovery, RW-A and RW-B firmware
 * @valid: false if this structure is not yet set up, true if it is
 * @use_efs: true to use Early Firmware Selection, where the RO firmware is
 *	small and runs from on-chip SRAM. The RW firmware can then initialize
 *	(or re-init) the SDRAM if required
 * @early_firmware_verification: With EFS, load and verify SPL, then load and
 *	verify the U-Boot that SPL will load against the hash in SPL, before
 *	deciding that the SPL is good. Without this option, only the SPL is
 *	verified, and that is left to (later) decide if the U-Boot is good.
 *	See vboot_persist for how this works.
 * @legacy_vboot: Indicates that vboot_twostop is being used
 *	(crosbug.com/p/21810)
 * @persist: Persistent information about firmware we have tried.
 * @fw_size: Size of firmware image in bytes - this starts off as the number
 *	of bytes in the section containing the firmware, but may be smaller if
 *	the vblock indicates that not all of that data was signed.
 * @active_ec_firmware: Indicates if the EC is in RO/RW (ACTIVE_EC_FIRMWARE_..)
 * @ddr_type: Name of the DDR memory type we have
 * @readonly_firmware_id: Firmware ID read from RO firmware
 * @firmware_id: Firmware ID of selected RO/RW firmware
 * @hardware_id: Hardware ID
 * @vb_shared_data: Information set up by the vboot library which we must
 *	preserve across calls to this library.
 */
struct vboot_info {
	struct vboot_flag_details wpsw, recsw, devsw, oprom;
	firmware_storage_t file;
	size_t gbb_size;
	int oprom_matters;
	struct twostop_fmap fmap;
	VbCommonParams cparams;
	VbSelectFirmwareParams fparams;
	VbSelectAndLoadKernelParams kparams;
	VbInitParams iparams;
	enum VbSelectFirmware_t selected_firmware;
	const char *firmware_type;
	struct nvstorage_method *nvcontext_method;
	uint64_t nvcontext_lba;
	uint16_t nvcontext_offset;
	uint16_t nvcontext_size;
	void *fw_dest;

	enum VbErrorPredefined_t vb_error;
	struct vboot_fw_info fw[VB_SELECT_FIRMWARE_COUNT];
	bool valid;
	bool use_efs;
	bool early_firmware_verification;
#ifdef CONFIG_CROS_LEGACY_VBOOT
	bool legacy_vboot;
#endif
	struct vboot_persist *persist;
	uint32_t fw_size;
	uint8_t active_ec_firmware;
	const char *ddr_type;
	char readonly_firmware_id[ID_LEN];
	char firmware_id[ID_LEN];
	char hardware_id[ID_LEN];
	uint8_t vb_shared_data[VB_SHARED_DATA_MIN_SIZE];
};

/**
 * Set up the common params for the vboot library
 *
 * @vboot: Pointer to vboot structure
 * @cparams: Pointer to params structure to set up
 */
void vboot_init_cparams(struct vboot_info *vboot, VbCommonParams *cparams);

/**
 * Tell the EC to reboot and start up in RO.
 *
 * In recovery mode we need the EC to be in RO, so this function ensures that
 * it is. It requires rebooting the AP also.
 */
int vboot_request_ec_reboot_to_ro(void);

/**
 * Make a note of an error in the verified boot processs
 *
 * @vboot: Pointer to vboot structure
 * @stage: Name of vboot stage whic hfailed
 * @err: Number of error that occurred
 * @return -1 (always, so that caller can return it)
 */
int vboot_set_error(struct vboot_info *vboot, const char *stage,
		    enum VbErrorPredefined_t err);

/**
 * Read the vboot data from an FDT
 *
 * This is used in RW U-Boot to read state left behind by RO U-Boot
 *
 * @vboot: Pointer to vboot structure
 * @blob: Pointer to device tree blob containing the data
 */
int vboot_read_from_fdt(struct vboot_info *vboot, const void *blob);

/**
 * Write the vboot data to the FDT
 *
 * RO U-Boot uses this function to write out data for use by RW U-Boot. It
 * is also used to write out data to pass to the kernel.
 *
 * @vboot: Pointer to vboot structure
 * @blob: Pointer to device tree to update
 * @return 0 if OK, -ve on error
 */
int vboot_write_to_fdt(const struct vboot_info *vboot, void *blob);

/**
 * Update ACPI data
 *
 * For x86 systems, this writes a basic level of information in binary to
 * the ACPI tables for use by the kernel.
 *
 * @vboot: Pointer to vboot structure
 * @return 0 if OK, -ve on error
 */
int vboot_update_acpi(struct vboot_info *vboot);

/**
 * Dump vboot status information to the console
 *
 * @vboot: Pointer to vboot structure
 */
int vboot_dump(struct vboot_info *vboot);

/**
 * Get a pointer to the vboot structure
 *
 * @vboot: Pointer to vboot structure, if valid, else NULL
 */
struct vboot_info *vboot_get(void);

/**
 * Get a pointer to the vboot structure
 *
 * @vboot: Pointer to vboot structure (there is only one)
 */
struct vboot_info *vboot_get_nocheck(void);

/*
 * For the functions below, there are three combinations (thanks clchiou@):
 *
 * CONFIG_CROS_LEGACY_VBOOT defined and vboot->legacy_vboot == true
 * CONFIG_CROS_LEGACY_VBOOT defined and vboot->legacy_vboot == false
 * CONFIG_CROS_LEGACY_VBOOT is not defined
 *
 * The purpose of the first two cases is to allow the legacy and the new
 * vboot code paths to both be present in U-Boot so that U-Boot may run
 * either legacy or new vboot.
 *
 * Ultimately we will remove the legacy vboot, but in the meantime this
 * ability to boot either is valuable for testing and verification.
 *
 * The functions below allow the compiler/linker to optimize away the
 * legacy code when it is not needed.
 */

/**
 * @return true if we are running in legacy mode (vboot_twostop)
 */
static inline bool vboot_is_legacy(void)
{
#ifdef CONFIG_CROS_LEGACY_VBOOT
	struct vboot_info *vboot = vboot_get_nocheck();

	return vboot->legacy_vboot;
#else
	return false;
#endif
}

/**
 * Set whether we are in legacy mode or not
 *
 * @legacy: Set legacy mode to true/false
 */
static inline void vboot_set_legacy(bool legacy)
{
#ifdef CONFIG_CROS_LEGACY_VBOOT
	struct vboot_info *vboot = vboot_get_nocheck();

	vboot->legacy_vboot = legacy;
#endif
}

/**
 * Run the legacy vboot_twostop command
 *
 * @return 0 if OK, -ve on error
 */
int run_legacy_vboot_twostop(void);

/**
 * Load configuration for vboot, to control how it operates.
 *
 * @blob: Device tree blob containing the '/chromeos-config' node
 * @vboot: Pointer to vboot structure to update
 */
int vboot_load_config(const void *blob, struct vboot_info *vboot);

/**
 * Dump out information about the vboot persist information to the console
 *
 * @name: Name of this dump (for tracing)
 * @vboot: Pointer to vboot structure to dump
 */
void vboot_persist_dump(const char *name, struct vboot_info *vboot);

/**
 * Clear the vboot persist region
 *
 * Clear out any data in the persist region
 *
 * @vboot: Pointer to vboot structure
 */
void vboot_persist_clear(struct vboot_info *vboot);

/**
 * Set up the persist region if it does not already exist
 *
 * If there is a persist region, return it. If not, create it and then
 * return it.
 *
 * @blob: Pointer to device tree block containing config information
 * @vboot: Pointer to vboot structure
 */
int vboot_persist_init(const void *blob, struct vboot_info *vboot);

#endif
