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
#include <cros_ec.h>
#include <errno.h>
#include <hash.h>
#include <malloc.h>
#include <mapmem.h>
#include <os.h>
#include <u-boot/sha256.h>
#include <spi_flash.h>
#include <spl.h>
#include <tis.h>
#include <asm/io.h>
#include <linux/lzo.h>
#include <cros/common.h>
#include <cros/cros_init.h>
#include <cros/hasher_state.h>
#include <cros/memory_wipe.h>
#include <cros/nvstorage.h>
#include <cros/vboot.h>
#include <cros/vboot_flag.h>
#ifdef CONFIG_EXYNOS5
#include <asm/arch/spl.h>
#endif
#ifdef CONFIG_X86
#include <asm/arch/sysinfo.h>
#endif

DECLARE_GLOBAL_DATA_PTR;

__weak const char *cros_fdt_get_mem_type(void)
{
	return NULL;
}

int vboot_ro_init(struct vboot_info *vboot)
{
	const void *blob = gd->fdt_blob;
	GoogleBinaryBlockHeader gbb;

	memset(vboot, '\0', sizeof(*vboot));
	vboot->valid = true;

	bootstage_mark_name(BOOTSTAGE_ID_ALLOC, "vboot_readonly");
	VBDEBUG("Starting read-only firmware\n");

	if (cros_init())
		goto err;

#ifdef CONFIG_CROS_EC_SANDBOX
	struct cros_ec_dev *cros_ec = board_get_cros_ec_dev();

	/*
	 * Check for EC keyboard, since on sandbox we want to support recovery
	 * mode, but the EC needs a chance to scan keys before it will know
	 * whether recovery mode is requested.
	 *
	 * This needs to be done after the LCD is inited (since until then
	 * the SDL keyboard will not work), and is Chrome OS-specific, so we
	 * may as well do it here.
	 */
	cros_ec_check_keyboard(cros_ec);
#endif

	if (vboot_load_config(blob, vboot)) {
		VBDEBUG("failed to read /chromeos-config\n");
		goto err;
	}
	vboot_persist_dump("ro", vboot);

	if (vboot_flag_fetch(VBOOT_FLAG_WRITE_PROTECT, &vboot->wpsw) ||
	    vboot_flag_fetch(VBOOT_FLAG_DEVELOPER, &vboot->devsw) ||
	    vboot_flag_fetch(VBOOT_FLAG_OPROM_LOADED, &vboot->oprom)) {
		VBDEBUG("failed to fetch gpio\n");
		goto err;
	}
	vboot_flag_dump(VBOOT_FLAG_WRITE_PROTECT, &vboot->wpsw);
	vboot_flag_dump(VBOOT_FLAG_DEVELOPER, &vboot->devsw);
	vboot_flag_dump(VBOOT_FLAG_OPROM_LOADED, &vboot->oprom);

	if (cros_fdtdec_config_has_prop(blob, "oprom-matters")) {
		VBDEBUG("FDT says oprom-matters\n");
		vboot->oprom_matters = 1;
	}

	if (cros_fdtdec_flashmap(blob, &vboot->fmap)) {
		VBDEBUG("failed to decode fmap\n");
		goto err;
	}
	dump_fmap(&vboot->fmap);

	/*
	 * With EFS we need a recovery image since the RO one does not have
	 * display support, USB, etc.
	 */
	if (vboot->use_efs && !vboot->fmap.readonly.boot_rec.length) {
		VBDEBUG("EFS requires a recovery image\n");
		goto err;
	}

	if (firmware_storage_open(&vboot->file)) {
		VBDEBUG("failed to open firmware storage\n");
		goto err;
	}

	/* Read read-only firmware ID */
	if (vboot->file.read(&vboot->file,
			     vboot->fmap.readonly.firmware_id.offset,
			     min((uint)sizeof(vboot->readonly_firmware_id),
			     vboot->fmap.readonly.firmware_id.length),
			     vboot->readonly_firmware_id)) {
		VBDEBUG("failed to read firmware ID\n");
		goto err;
	}
	VBDEBUG("read-only firmware id: \"%s\"\n", vboot->readonly_firmware_id);

	/*
	 * Read hardware ID
	 * TODO(sjg@chromium.org): It's really ugly having vboot read from the
	 * GBB structure which is owned by vboot. We should considering having
	 * a vboot API to read this.
	 */
	if (vboot->file.read(&vboot->file, vboot->fmap.readonly.gbb.offset,
			     sizeof(gbb), &gbb)) {
		VBDEBUG("failed to read GBB header\n");
		goto err;
	}
	if (vboot->file.read(&vboot->file,
			     vboot->fmap.readonly.gbb.offset + gbb.hwid_offset,
			     min((uint)sizeof(vboot->hardware_id),
				 gbb.hwid_size),
			     &vboot->hardware_id)) {
		VBDEBUG("failed to read hardware ID\n");
		goto err;
	}
	VBDEBUG("hardware id: \"%s\"\n", vboot->hardware_id);

	vboot->nvcontext_method = nvstorage_get_method();
	vboot->nvcontext_lba = CHROMEOS_VBNVCONTEXT_LBA;
	vboot->nvcontext_offset = 0;
	vboot->nvcontext_size = VBNV_BLOCK_SIZE;

	vboot->active_ec_firmware = ACTIVE_EC_FIRMWARE_RO;
	vboot->ddr_type = cros_fdt_get_mem_type();

	return 0;

err:
	return vboot_set_error(vboot, __func__, VBERROR_UNKNOWN);
}

int vboot_ro_vbinit(struct vboot_info *vboot)
{
	VbInitParams *iparams = &vboot->iparams;
#ifdef CONFIG_CROS_EC
	struct cros_ec_dev *cros_ec = board_get_cros_ec_dev();
	VbError_t err;

	if (cros_ec) {
		uint32_t ec_events = 0;
		const uint32_t kb_rec_mask =
			EC_HOST_EVENT_MASK(EC_HOST_EVENT_KEYBOARD_RECOVERY);

		/* Read keyboard recovery flag from EC, then clear it */
		if (cros_ec_get_host_events(cros_ec, &ec_events)) {
			/*
			 * TODO: what can we do if that fails?  Request
			 * recovery?  We don't simply want to fail, because
			 * that'll prevent us from going into recovery mode.
			 * We don't want to go into recovery mode
			 * automatically, because that'll break snow.
			 */
			VBDEBUG("VbInit: unable to read EC events\n");
			ec_events = 0;
		}
		if (ec_events & kb_rec_mask) {
			iparams->flags |= VB_INIT_FLAG_REC_BUTTON_PRESSED;
			if (cros_ec_clear_host_events(cros_ec, kb_rec_mask))
				VBDEBUG("VbInit: unable to clear EC KB recovery event\n");
		}
	}
#endif
	/*
	 * We can't support RO normal with Early Firmware Selection - the RW
	 * U-Boot must always run since the RO U-Boot is not capable of
	 * running recovery mode (no display, etc.)
	 */
	if (!vboot->use_efs &&
	    cros_fdtdec_config_has_prop(gd->fdt_blob, "twostop-optional"))
		iparams->flags |= VB_INIT_FLAG_RO_NORMAL_SUPPORT;
	VBDEBUG("RO Normal %sabled\n",
		iparams->flags & VB_INIT_FLAG_RO_NORMAL_SUPPORT ? "en" : "dis");
	if (vboot->wpsw.value)
		iparams->flags |= VB_INIT_FLAG_WP_ENABLED;
	if (vboot->recsw.value)
		iparams->flags |= VB_INIT_FLAG_REC_BUTTON_PRESSED;
	if (vboot->devsw.value)
		iparams->flags |= VB_INIT_FLAG_DEV_SWITCH_ON;
	if (vboot->oprom.value)
		iparams->flags |= VB_INIT_FLAG_OPROM_LOADED;
	if (vboot->oprom_matters)
		iparams->flags |= VB_INIT_FLAG_OPROM_MATTERS;
	if (cros_fdtdec_config_has_prop(gd->fdt_blob, "virtual-dev-switch"))
		iparams->flags |= VB_INIT_FLAG_VIRTUAL_DEV_SWITCH;
	if (cros_fdtdec_config_has_prop(gd->fdt_blob, "ec-software-sync"))
		iparams->flags |= VB_INIT_FLAG_EC_SOFTWARE_SYNC;
	if (cros_fdtdec_config_has_prop(gd->fdt_blob, "ec-slow-update"))
		iparams->flags |= VB_INIT_FLAG_EC_SLOW_UPDATE;
	if (vboot->file.sw_wp_enabled(&vboot->file))
		iparams->flags |= VB_INIT_FLAG_SW_WP_ENABLED;
	VBDEBUG("iparams->flags: %08x\n", iparams->flags);

	vboot_init_cparams(vboot, &vboot->cparams);

	err = VbInit(&vboot->cparams, &vboot->iparams);
	if (err) {
		VBDEBUG("VbInit: %#x\n", err);
		return vboot_set_error(vboot, __func__, err);
	}

	return 0;
}

#if defined(CONFIG_SYS_COREBOOT)
static void setup_arch_unused_memory(struct vboot_info *vboot,
				     struct memory_wipe *wipe)
{
	int i;

	/* Add ranges that describe RAM. */
	for (i = 0; i < lib_sysinfo.n_memranges; i++) {
		struct memrange *range = &lib_sysinfo.memrange[i];
		if (range->type == CB_MEM_RAM) {
			memory_wipe_add(wipe, range->base,
					range->base + range->size);
		}
	}
	/*
	 * Remove ranges that don't. These should take precedence, so they're
	 * done last and in their own loop.
	 */
	for (i = 0; i < lib_sysinfo.n_memranges; i++) {
		struct memrange *range = &lib_sysinfo.memrange[i];
		if (range->type != CB_MEM_RAM) {
			memory_wipe_sub(wipe, range->base,
					range->base + range->size);
		}
	}
}

#else
static void setup_arch_unused_memory(struct vboot_info *vboot,
				     struct memory_wipe *wipe)
{
	struct fdt_memory ramoops, lp0;
	int bank;

	for (bank = 0; bank < CONFIG_NR_DRAM_BANKS; bank++) {
		if (!gd->bd->bi_dram[bank].size)
			continue;
		memory_wipe_add(wipe, gd->bd->bi_dram[bank].start,
				gd->bd->bi_dram[bank].start +
					gd->bd->bi_dram[bank].size);
	}

	/* Excludes kcrashmem if in FDT */
	if (cros_fdtdec_memory(gd->fdt_blob, "/ramoops", &ramoops))
		VBDEBUG("RAMOOPS not contained within FDT\n");
	else
		memory_wipe_sub(wipe, ramoops.start, ramoops.end);

	/* Excludes the LP0 vector; only applicable to tegra platforms */
	if (cros_fdtdec_memory(gd->fdt_blob, "/lp0", &lp0))
		VBDEBUG("LP0 not contained within FDT\n");
	else
		memory_wipe_sub(wipe, lp0.start, lp0.end);
}
#endif

static uintptr_t get_current_sp(void)
{
#ifdef CONFIG_SANDBOX
	return gd->start_addr_sp;
#else
	uintptr_t addr;

	addr = (uintptr_t)&addr;
	return addr;
#endif
}

static void wipe_unused_memory(struct vboot_info *vboot)
{
	struct memory_wipe wipe;

	memory_wipe_init(&wipe);
	if (vboot->use_efs) {
		/* TODO: Clear SDRAM */
	} else {
		setup_arch_unused_memory(vboot, &wipe);

		/* Exclude relocated u-boot structures. */
		memory_wipe_sub(&wipe,
				get_current_sp() - MEMORY_WIPE_STACK_MARGIN,
				gd->ram_top);
	}

	memory_wipe_execute(&wipe);
}

int vboot_ro_flags(struct vboot_info *vboot)
{
	uint32_t out_flags = vboot->iparams.out_flags;

	if (cros_fdtdec_config_has_prop(gd->fdt_blob, "virtual-dev-switch")) {
		vboot->devsw.value =
			(out_flags & VB_INIT_OUT_ENABLE_DEVELOPER) ? 1 : 0;
		VBDEBUG("Developer switch = %d\n", vboot->devsw.value);
	}

	if ((out_flags & VB_INIT_OUT_CLEAR_RAM) &&
	    !cros_fdtdec_config_has_prop(gd->fdt_blob, "disable-memory-clear"))
		wipe_unused_memory(vboot);

	return 0;
}

/* This can only be called after key block has been verified */
static size_t firmware_body_size(const VbKeyBlockHeader *keyblock)
{
	const VbFirmwarePreambleHeader const *preamble;

	preamble = (VbFirmwarePreambleHeader *)
			((void *)keyblock + keyblock->key_block_size);

	return preamble->body_signature.data_size;
}

static int vboot_alloc_read(struct vboot_info *vboot, void **ptrp,
			    uint32_t offset, int size, const char *name)
{
	*ptrp = cros_memalign_cache(size);
	if (!*ptrp) {
		VBDEBUG("failed to allocate %s\n", name);
		return -ENOMEM;
	}

	if (vboot->file.read(&vboot->file, offset, size, *ptrp)) {
		VBDEBUG("fail to read %s\n", name);
		return -EIO;
	}

	return 0;
}

/* When memory is limited, use the piecemeal approach */
VbError_t vboot_hash_firmware(struct vboot_info *vboot,
			      unsigned int fw_size,
			      struct fmap_entry *entry)
{
	const int buf_size = 8192;
	int offset, todo;
	uint8_t *buf;

	buf = malloc(buf_size);
	if (!buf) {
		VBDEBUG("Cannot allocate firmware buffer\n");
		return 1;
	}
	for (offset = 0; offset < fw_size; offset += todo) {
		todo = min(fw_size - offset, (uint)buf_size);

		if (vboot->file.read(&vboot->file, entry->offset + offset,
				     todo, buf)) {
			VBDEBUG("fail to read firmware offset %#x\n",
				entry->offset + offset);
			free(buf);
			return 1;
		}

		VbUpdateFirmwareBodyHash(&vboot->cparams, buf, todo);
	}
	free(buf);

	return 0;
}

static int vboot_verify_firmware(struct vboot_info *vboot,
				 struct vboot_fw_info *fw)
{
#if defined(CONFIG_EXYNOS5)
	struct spl_hash *hash = NULL;
	struct fmap_entry *entry;
	uint8_t digest[SHA256_SUM_LEN];
	fdt_addr_t addr;
	fdt_size_t size;
	void *buf;
	int len;
	int ret;

	hash = spl_extract_hash(fw->cache);
	if (!hash)
		return 0;

	/*
	 * TODO(sjg@chromium.org): Need to read firmware in chunks. For now
	 * use SDRAM.
	 */
	ret = fdtdec_decode_memory_region(gd->fdt_blob, -1, "u-boot", NULL,
					  &addr, &size);
	if (ret) {
		VBDEBUG("failed to find u-boot memory region: %d\n", ret);
		return -1;
	}
	buf = map_sysmem(addr, size);
	entry = &fw->fw_entry->boot;
	if (vboot->file.read(&vboot->file, entry->offset, entry->used,
			     buf)) {
		VBDEBUG("fail to read firmware offset %#x\n", entry->offset);
		return -1;
	}

	len = SHA256_SUM_LEN;
	if (hash_block("sha256", buf, entry->used, digest, &len)) {
		VBDEBUG("hash_block failed\n");
		return -1;
	}

	if (memcmp(hash->digest, digest, len)) {
		VBDEBUG("Early firmware verify failure\n");
		return -1;
	}
	VBDEBUG("Early firmware verify completed\n");
#endif

	return 0;
}

VbError_t VbExHashFirmwareBody(VbCommonParams *cparams, uint32_t index)
{
	struct vboot_info *vboot;
	struct vboot_fw_info *fw;

	if (vboot_is_legacy())
		return load_firmware_VbExHashFirmwareBody(cparams, index);

	vboot = cparams->caller_context;
	if (index != VB_SELECT_FIRMWARE_A && index != VB_SELECT_FIRMWARE_B) {
		VBDEBUG("incorrect firmware index: %d\n", index);
		return -1;
	}

	if (vboot->persist && (vboot->persist->flags & (1 << index))) {
		VBDEBUG("firmware index: %d has been tried - skipping\n",
			index);
		return -1;
	}

	/*
	 * The key block has been verified. It is safe now to infer the actual
	 * firmware body size from the key block.
	 */
	fw = &vboot->fw[index];
	fw->size = firmware_body_size(fw->vblock);
	VBDEBUG("Firmware size is %#0x\n", fw->size);
	if (vboot_alloc_read(vboot, &fw->cache, fw->entry->offset, fw->size,
			     "sel fw") == -ENOMEM) {
		VBDEBUG("Limited memory - using streaming verify\n");
		if (vboot_hash_firmware(vboot, fw->size, fw->entry))
			return -1;
	} else {
		VbUpdateFirmwareBodyHash(cparams, fw->cache, fw->size);
	}

	/*
	 * If we are only reading the SPL, then we can verify the U-Boot that
	 * it will load either now, while there is time to report a problem
	 * to vboot, or later (when running the SPL) at which point we will
	 * need to reboot and try the other firmware
	 */
	if (vboot->early_firmware_verification &&
	    vboot_verify_firmware(vboot, fw)) {
		VBDEBUG("RW U-Boot failed to verify\n");
		return -1;
	}

	return 0;
}

int vboot_ro_select_firmware(struct vboot_info *vboot)
{
	VbSelectFirmwareParams *fparams = &vboot->fparams;
	struct twostop_fmap *fmap = &vboot->fmap;
	struct fmap_entry *entry;
	VbError_t err = VBERROR_UNKNOWN;
	struct vboot_fw_info *fw;
	int selection = -1;
	uint32_t vlength;
	int len;
	int i;

	vlength = fmap->readwrite_a.vblock.length;
	assert(vlength == fmap->readwrite_b.vblock.length);

	/* crbug.com/205554 */
	vlength = 8192;

	/* Sort out all our regions */
	fw = &vboot->fw[VB_SELECT_FIRMWARE_A];
	fw->fw_entry = &fmap->readwrite_a;
	if (vboot_alloc_read(vboot, &fw->vblock, fw->fw_entry->vblock.offset,
			     vlength, "vblock a"))
		goto out;
	fparams->verification_block_A = fw->vblock;
	fw->entry = vboot->use_efs ? &fw->fw_entry->spl : &fw->fw_entry->boot;

	fw = &vboot->fw[VB_SELECT_FIRMWARE_B];
	fw->fw_entry = &fmap->readwrite_b;
	if (vboot_alloc_read(vboot, &fw->vblock, fw->fw_entry->vblock.offset,
			     vlength, "vblock b"))
		goto out;
	fparams->verification_block_B = fw->vblock;
	fw->entry = vboot->use_efs ? &fw->fw_entry->spl : &fw->fw_entry->boot;

	/*
	 * Recovery uses the recovery image, unless there is none available,
	 * in which case the RO image is used.
	 */
	fw = &vboot->fw[VB_SELECT_FIRMWARE_RECOVERY];
	fw->fw_entry = &fmap->readonly;
	fw->entry = vboot->use_efs
			? &fw->fw_entry->spl_rec
			: &fw->fw_entry->boot_rec;
	if (!fw->entry->length) {
		fw->fw_entry = &fmap->readonly;
		fw->entry = NULL;
	}

	/* For RO normal, we allow the RO image to run all stages */
	fw = &vboot->fw[VB_SELECT_FIRMWARE_READONLY];
	if (vboot->iparams.flags & VB_INIT_FLAG_RO_NORMAL_SUPPORT)
		fw->fw_entry = &fmap->readonly;

	/* Sanity check firmwares */
	for (i = VB_SELECT_FIRMWARE_A; i <= VB_SELECT_FIRMWARE_B; i++) {
		if (!(vboot->iparams.flags & VB_INIT_FLAG_RO_NORMAL_SUPPORT) &&
		    i == VB_SELECT_FIRMWARE_READONLY)
			continue;

		fw = &vboot->fw[i];
		if (!fw->fw_entry || !fw->entry) {
			VBDEBUG("Firmware entry %d missing\n", i);
			goto out;
		}
		if (!fw->entry->length) {
			VBDEBUG("Firmware entry %d, offset = %#x, size = %#x\n",
				i, fw->entry->offset, fw->entry->length);
			goto out;
		}
	}

	fparams->verification_size_A = vlength;
	fparams->verification_size_B = vlength;

	err = VbSelectFirmware(&vboot->cparams, fparams);
	if (err)
		goto out;
	err = VBERROR_UNKNOWN;
	selection = fparams->selected_firmware;
	vboot->selected_firmware = selection;
	VBDEBUG("selected_firmware: %x\n", selection);
	bootstage_mark_name(BOOTSTAGE_ID_ALLOC, "rw_firmware_loaded");

	fw = &vboot->fw[selection];
	if (selection >= VB_SELECT_FIRMWARE_COUNT || !fw->fw_entry) {
		VBDEBUG("impossible selection value: %d\n", selection);
		goto out;
	}

	/* If the recovery U-Boot is separate, we must load it */
	if (selection == VB_SELECT_FIRMWARE_RECOVERY && fw->entry) {
		VBDEBUG("loading recovery image size %x\n", fw->entry->used);
		if (vboot_alloc_read(vboot, &fw->cache, fw->entry->offset,
				     fw->entry->used, "rec fw")) {
			VBDEBUG("could not load recovery image %d\n",
				selection);
			goto out;
		}
	}

	entry = &fw->fw_entry->firmware_id;
	len = min((uint)sizeof(vboot->firmware_id), entry->length);
	if (vboot->file.read(&vboot->file, entry->offset,
			     len, vboot->firmware_id)) {
		VBDEBUG("failed to read active firmware id\n");
		vboot->firmware_id[0] = '\0';
	}

	if (selection == VB_SELECT_FIRMWARE_RECOVERY)
		vboot->firmware_type = "recovery";
	else if (vboot->devsw.value)
		vboot->firmware_type = "developer";
	else
		vboot->firmware_type = "normal";

	VBDEBUG("active main firmware type : %s\n", vboot->firmware_type);
	VBDEBUG("active main firmware id   : \"%s\"\n", vboot->firmware_id);

	/*
	 * fw->size is only set if the firmware was hashed. For recovery and
	 * RO-normal this does not happen.
	 */
	if (!fw->size && fw->entry)
		fw->size = fw->entry->used;

	/* Everything looks fine */
	err = VBERROR_SUCCESS;
out:
	for (i = 0; i < VB_SELECT_FIRMWARE_COUNT; i++) {
		struct vboot_fw_info *fw = &vboot->fw[i];

		free(fw->vblock);
		if (i != selection)
			free(fw->cache);
	}

	if (err) {
		vboot_set_error(vboot, __func__, err);
		return -1;
	}

	return 0;
}

/**
 * Stash the RW SPL in IRAM so we can quickly jump to it on resume
 */
static int vboot_stash_rw_spl(struct vboot_info *vboot,
			      struct vboot_fw_info *fw)
{
	struct vboot_spl_hdr *hdr;
	fdt_addr_t base;
	fdt_size_t size;

	if (cros_fdtdec_decode_region(gd->fdt_blob, "rw-spl", ",efs",
				      &base, &size)) {
		VBDEBUG("Cannot find RW SPL stash\n");
		return -ENOENT;
	}

	hdr = map_sysmem(base, size);
	hdr->signature = 0;	/* Not valid yet */
	if (fw->size + sizeof(*hdr) > size) {
		VBDEBUG("Stash is too small for RW SPL\n");
		return -ENOSPC;
	}

	hdr->size = fw->size;
	hdr->crc32 = crc32(VBOOT_SPL_SIGNATURE, vboot->fw_dest, fw->size);
	hdr->spare = 0;
	memcpy(hdr + 1, vboot->fw_dest, fw->size);

	/* All OK, so write the signature */
	hdr->signature = VBOOT_SPL_SIGNATURE;
	VBDEBUG("Stashed RW SPL for resume path at %lx, size %lx, free %lx\n",
		(ulong)base, (ulong)size,
		size - (ulong)fw->size - sizeof(*hdr));

	/*
	 * This can be used as a test of SPL self-relocation. It adjusts it
	 * so that we boot the RW SPL in the stashed location. It should
	 * relocate itself and run normally.
	 *
	 * vboot->fw_dest = hdr + 1;
	 */

	return 0;
}

int vboot_ro_prepare(struct vboot_info *vboot)
{
	enum VbSelectFirmware_t selected_firmware = vboot->selected_firmware;
	struct vboot_fw_info *fw;
	void *cdata_fdt;
	fdt_addr_t fw_addr, base;
	fdt_size_t size;
	int ret;

	fw = &vboot->fw[selected_firmware];
	fw->uncomp_size = fw->size;
	ret = fdtdec_decode_memory_region(gd->fdt_blob, -1, "u-boot",
					   vboot->use_efs ? ",spl" : NULL,
					   &fw_addr, &size);
	if (ret) {
		VBDEBUG("failed to find u-boot memory region: %d\n", ret);
		goto err;
	}

	vboot->fw_dest = map_sysmem(fw_addr, fw->size);

	if (!fw->fw_entry) {
		VBDEBUG("firmware has not been loaded\n");
		goto err;
	}
	VBDEBUG("jump to firmware %d at %#08x, pos %#08x, size %#x\n",
		selected_firmware, (unsigned)fw_addr,
		(unsigned)map_to_sysmem(fw->cache), fw->size);

	/*
	 * TODO(sjg@chromium.org): This version of U-Boot must be loaded at a
	 * fixed location. It could be problematic if newer version U-Boot
	 * changed this address. It should be easy enough to make U-Boot
	 * position-independent.
	 *
	 * Note: fw->entry will be NULL if no RW firmware was loaded, which
	 * happens in RO-normal.
	 */
	if (fw->entry) {
		switch (fw->entry->compress_algo) {
#ifdef CONFIG_LZO
		case FMAP_COMPRESS_LZO: {
			size_t unc_len;
			int ret;

			bootstage_start(BOOTSTAGE_ID_ACCUM_DECOMP,
					"decompress_image");
			ret = lzop_decompress(fw->cache, fw->size,
					      vboot->fw_dest, &unc_len);
			if (ret < 0) {
				VBDEBUG("LZO: uncompress or overwrite error %d - must RESET board to recover\n",
					ret);
				goto err;
			}
			fw->uncomp_size = unc_len;
			bootstage_accum(BOOTSTAGE_ID_ACCUM_DECOMP);
			break;
		}
#endif
		case FMAP_COMPRESS_NONE:
			/* Take this out for testing */
			memmove(vboot->fw_dest, fw->cache, fw->size);
			break;
		default:
			VBDEBUG("Unsupported compression type %d\n",
				fw->entry->compress_algo);
			return -1;
		}
	}
	/* Stash the RW SPL away if needed */
	if (vboot->use_efs) {
		if (vboot_stash_rw_spl(vboot, fw))
			return -1;
	}

#ifdef CONFIG_SPL_HEADER_SIZE
	/* Skip the header when we jump to the SPL */
	if (vboot->use_efs)
		vboot->fw_dest += CONFIG_SPL_HEADER_SIZE;
#endif

	if (cros_fdtdec_decode_region(gd->fdt_blob, "cros-system-data",
				      vboot->use_efs ? ",efs" : NULL,
				      &base, &size)) {
		VBDEBUG("Cannot find cdata FDT\n");
		goto err;
	}
	cdata_fdt = map_sysmem(base, size);
	if (fdt_create_empty_tree(cdata_fdt, size)) {
		VBDEBUG("Cannot create empty cdata FDT\n");
		goto err;
	}
	if (vboot_write_to_fdt(vboot, cdata_fdt)) {
		VBDEBUG("Cannot write vboot data to FDT\n");
		goto err;
	}
	VBDEBUG("crossystem data written to FDT at %#08x, size %#08x\n",
		(unsigned)map_to_sysmem(cdata_fdt), size);

	return 0;

err:
	return vboot_set_error(vboot, __func__, VBERROR_UNKNOWN);
}

int vboot_ro_jump(struct vboot_info *vboot)
{
	struct vboot_fw_info *fw;

	vboot_persist_dump("jump", vboot);
	fw = &vboot->fw[vboot->selected_firmware];
	bootstage_mark_name(BOOTSTAGE_ID_ALLOC, "vboot_readonly_jump");

	/* RO-normal optimization */
	if (vboot->iparams.flags & VB_INIT_FLAG_RO_NORMAL_SUPPORT) {
		if (vboot->selected_firmware == VB_SELECT_FIRMWARE_RECOVERY ||
		    vboot->selected_firmware == VB_SELECT_FIRMWARE_READONLY) {
			VBDEBUG("RO-normal support, skipping jump\n");
			tis_close();
			return 0;
		}
	}

	VBDEBUG("Jump to rw %s at %x\n", vboot->use_efs ? "SPL" : "U-Boot",
		(unsigned)map_to_sysmem(vboot->fw_dest));
	cleanup_before_linux();
#ifdef CONFIG_SANDBOX
	os_jump_to_image(vboot->fw_dest, fw->uncomp_size);
#else
	ulong spi_offset;

	if (vboot->selected_firmware == VB_SELECT_FIRMWARE_RECOVERY)
		spi_offset = fw->fw_entry->boot_rec.offset;
	else
		spi_offset = fw->fw_entry->boot.offset;
	((void(*)(ulong tag, ulong fw, ulong spi_offset))vboot->fw_dest)
		(SPL_RUNNING_FROM_UBOOT,
		 vboot->selected_firmware,
		 spi_offset);
#endif

	/* It is an error if readwrite firmware returns */
	return -1;
}
