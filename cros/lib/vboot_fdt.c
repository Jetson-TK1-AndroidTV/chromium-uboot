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
#include <cros/nvstorage.h>
#include <cros/vboot.h>
#include <cros/vboot_flag.h>
#ifdef CONFIG_X86
#include <asm/arch/sysinfo.h>
#endif

static void read_flag(const void *blob, int node,
		      struct vboot_flag_details *flag, const char *name)
{
	char boot_name[50];
	u32 array[3];

	snprintf(boot_name, sizeof(boot_name), "boot-%s", name);
	flag->value = fdtdec_get_bool(blob, node, boot_name);

	if (!fdtdec_get_int_array(blob, node, name, array, 3)) {
		flag->port = array[1];
		flag->active_high = array[2];
	}
}

static int write_flag(void *blob, int node,
		      const struct vboot_flag_details *flag, const char *name)
{
	char boot_name[50];
	u32 array[3];

	if (flag->value) {
		snprintf(boot_name, sizeof(boot_name), "boot-%s", name);
		fdt_setprop(blob, node, boot_name, NULL, 0);
	}

	/* For some reason the first cell is unused (phandle?) */
	array[0] = 0;
	array[1] = cpu_to_fdt32(flag->port);
	array[2] = cpu_to_fdt32(flag->active_high);
	return fdt_setprop(blob, node, name, array, sizeof(array));
}

static void read_id(const void *blob, int node, const char *prop_name,
		    char *id, int size)
{
	const char *prop;
	int len;

	prop = fdt_getprop(blob, node, prop_name, &len);
	if (prop)
		memcpy(id, prop, min(len, size - 1));
}

int vboot_read_from_fdt(struct vboot_info *vboot, const void *blob)
{
	struct nvstorage_method *method = NULL;
	const char *prop;
	int node;
	int len;
	int ret;

	node = fdt_node_offset_by_compatible(blob, -1, "chromeos-firmware");
	if (node < 0) {
		VBDEBUG("chromeos-firmware node not found\n");
		return -1;
	}

	read_flag(blob, node, &vboot->wpsw, "write-protect-switch");
	read_flag(blob, node, &vboot->recsw, "recovery-switch");
	read_flag(blob, node, &vboot->devsw, "developer-switch");
	read_flag(blob, node, &vboot->oprom, "oprom-loaded");

	prop = fdt_getprop(blob, node, "active-ec-firmware", NULL);
	if (!prop || !strcmp(prop, "RO"))
		vboot->active_ec_firmware = ACTIVE_EC_FIRMWARE_RO;
	else if (!strcmp(prop, "RW"))
		vboot->active_ec_firmware = ACTIVE_EC_FIRMWARE_RW;

	vboot->firmware_type = fdt_getprop(blob, node, "firmware-type", NULL);

	read_id(blob, node, "hardware-id", vboot->hardware_id,
		sizeof(vboot->hardware_id));
	read_id(blob, node, "firmware-version",
		vboot->firmware_id, sizeof(vboot->firmware_id));
	read_id(blob, node, "readonly-firmware-version",
		vboot->readonly_firmware_id,
		sizeof(vboot->readonly_firmware_id));

	prop = fdt_getprop(blob, node, "nonvolatile-context-storage", NULL);

	/* crbug.com/p/21097 */
	if (!strcmp(prop, "mkbp"))
		prop = "cros-ec";
	if (prop) {
		method = nvstorage_find_name(prop);
		if (method && method->read_fdt) {
			ret = method->read_fdt(vboot, blob, node);
			if (ret) {
				VBDEBUG("nvcontext read_fdt failed: '%s'\n",
					fdt_strerror(ret));
			}
		}
	}
	if (!method)
		VBDEBUG("No nvcontext method '%s'\n", prop ? prop : "");
	vboot->nvcontext_method = method;

	prop = fdt_getprop(blob, node, "vboot-shared-data", &len);
	if (len == sizeof(vboot->vb_shared_data)) {
		memcpy(vboot->vb_shared_data, prop, len);
	} else {
		VBDEBUG("Vboot shared data, expected size %u, got %d\n",
			(unsigned)sizeof(vboot->vb_shared_data), len);
	}

	vboot->ddr_type = fdt_getprop(blob, node, "ddr-type", NULL);

	return 0;
}

int vboot_write_to_fdt(const struct vboot_info *vboot, void *blob)
{
	struct nvstorage_method *method;
	int node;
	int err;

#define set_scalar_prop(name, f) \
	fdt_setprop_cell(blob, node, name, vboot->f)
#define set_array_prop(name, f) \
	fdt_setprop(blob, node, name, vboot->f, sizeof(vboot->f))
#define set_conststring_prop(name, str) \
	fdt_setprop_string(blob, node, name, str)
#define set_bool_prop(name, f) \
	((vboot->f) ? fdt_setprop(blob, node, name, NULL, 0) : 0)
#define CALL(expr) \
		do { err = (expr); \
			if (err < 0) { \
				VBDEBUG("Failure at %s\n", #expr); \
				return err; \
			} \
		} while (0)
	err = 0;
	CALL(fdt_ensure_subnode(blob, 0, "firmware"));
	node = err;
	CALL(fdt_ensure_subnode(blob, node, "chromeos"));
	node = err;

	CALL(fdt_setprop_string(blob, node, "compatible",
				"chromeos-firmware"));

	CALL(write_flag(blob, node, &vboot->wpsw, "write-protect-switch"));
	CALL(write_flag(blob, node, &vboot->recsw, "recovery-switch"));
	CALL(write_flag(blob, node, &vboot->devsw, "developer-switch"));
	CALL(write_flag(blob, node, &vboot->oprom, "oprom-loaded"));

	CALL(set_scalar_prop("fmap-offset", fmap.readonly.fmap.offset));

	switch (vboot->active_ec_firmware) {
	case ACTIVE_EC_FIRMWARE_UNCHANGE: /* Default to RO */
	case ACTIVE_EC_FIRMWARE_RO:
		CALL(set_conststring_prop("active-ec-firmware", "RO"));
		break;
	case ACTIVE_EC_FIRMWARE_RW:
		CALL(set_conststring_prop("active-ec-firmware", "RW"));
		break;
	}

	CALL(set_conststring_prop("firmware-type", vboot->firmware_type));

	CALL(set_array_prop("hardware-id", hardware_id));
	CALL(set_array_prop("firmware-version", firmware_id));
	CALL(set_array_prop("readonly-firmware-version",
			    readonly_firmware_id));

	method = vboot->nvcontext_method;
	if (method) {
		const char *name = method->name;

		/* crbug.com/p/21097 */
		if (!strcmp(name, "cros-ec"))
			name = "mkbp";
		CALL(fdt_setprop_string(blob, node,
					"nonvolatile-context-storage",
					name));
		if (method->write_fdt)
			CALL(method->write_fdt(vboot, blob, node));
	} else {
		VBDEBUG("No nvcontext method\n");
	}

	CALL(set_array_prop("vboot-shared-data", vb_shared_data));

	if (vboot->ddr_type)
		CALL(set_conststring_prop("ddr-type", vboot->ddr_type));

#undef set_scalar_prop
#undef set_array_prop
#undef set_conststring_prop
#undef set_bool_prop
#undef CALL
	fdt_pack(blob);
	VBDEBUG("crossytem data written to FDT, size %#x\n",
		fdt_totalsize(blob));

	return 0;
}

#ifdef CONFIG_X86
/* Repeat these here so we can remove crossystem_data.h */

#define CROSSYSTEM_DATA_SIGNATURE "CHROMEOS"

/* This is used to keep bootstub and readwite main firmware in sync */
#define CROSSYSTEM_DATA_VERSION 1

enum VdatFwIndex {
	VDAT_RW_A = 0,
	VDAT_RW_B = 1,
	VDAT_RECOVERY = 0xFF
};

enum BinfFwIndex {
	BINF_RECOVERY = 0,
	BINF_RW_A = 1,
	BINF_RW_B = 2
};

/* TODO(sjg@chromium.org): Put this in the fdt and move x86 over to use fdt */
static int fw_index_vdat_to_binf(int index)
{
	switch (index) {
	case VDAT_RW_A:     return BINF_RW_A;
	case VDAT_RW_B:     return BINF_RW_B;
	case VDAT_RECOVERY: return BINF_RECOVERY;
	default:            return BINF_RECOVERY;
	}
};

int vboot_update_acpi(struct vboot_info *vboot)
{
	int len;
	chromeos_acpi_t *acpi_table = (chromeos_acpi_t *)lib_sysinfo.vdat_addr;
	VbSharedDataHeader *vdat = (VbSharedDataHeader *)&acpi_table->vdat;

	acpi_table->vbt0 = BOOT_REASON_OTHER;
	acpi_table->vbt1 = fw_index_vdat_to_binf(vdat->firmware_index);
	/* Use value set by coreboot if we don't want to change it */
	if (vboot->active_ec_firmware != ACTIVE_EC_FIRMWARE_UNCHANGE)
		acpi_table->vbt2 = vboot->active_ec_firmware;
	acpi_table->vbt3 =
		(vboot->wpsw.value ? CHSW_FIRMWARE_WP_DIS : 0) |
		(vboot->recsw.value ? CHSW_RECOVERY_X86 : 0) |
		(vboot->devsw.value ? CHSW_DEVELOPER_SWITCH : 0);

	len = min(ID_LEN, sizeof(acpi_table->vbt4));
	memcpy(acpi_table->vbt4, vboot->hardware_id, len);
	len = min(ID_LEN, sizeof(acpi_table->vbt5));
	memcpy(acpi_table->vbt5, vboot->firmware_id, len);
	len = min(ID_LEN, sizeof(acpi_table->vbt6));
	memcpy(acpi_table->vbt6, vboot->readonly_firmware_id, len);

#ifdef CONFIG_FACTORY_IMAGE
	acpi_table->vbt7 = 3; /* '3' means 'netboot' to crossystem */
#else
	if (!strcmp(vboot->firmware_type, "recovery"))
		acpi_table->vbt7 = FIRMWARE_TYPE_RECOVERY;
	else if (!strcmp(vboot->firmware_type, "normal"))
		acpi_table->vbt7 = FIRMWARE_TYPE_NORMAL;
	else /* should be "developer" */
		acpi_table->vbt7 = FIRMWARE_TYPE_DEVELOPER;
#endif
	acpi_table->vbt8 = RECOVERY_REASON_NONE;
	acpi_table->vbt9 = vboot->fmap.readonly.fmap.offset;

	strncpy((char *)acpi_table->vbt10,
		(const char *)vboot->firmware_id, 64);
	return 0;
}
#endif
