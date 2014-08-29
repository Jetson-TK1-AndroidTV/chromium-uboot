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

static void dump_flag(struct vboot_info *vboot, const char *name,
		      struct vboot_flag_details *flag)
{
	VBDEBUG("%-30s: value %d, polarity %d, port %d\n", name, flag->value,
		flag->active_high, flag->port);
}

int vboot_dump(struct vboot_info *vboot)
{
	struct nvstorage_method *method;

	dump_flag(vboot, "wpsw", &vboot->wpsw);
	dump_flag(vboot, "recsw", &vboot->recsw);
	dump_flag(vboot, "devsw", &vboot->devsw);
	dump_flag(vboot, "oprom", &vboot->oprom);
	VBDEBUG("%-30s: %#x\n", "flashmap_offset",
		vboot->fmap.readonly.fmap.offset);
	VBDEBUG("%-30s: %d\n", "active_ec_firmware", vboot->active_ec_firmware);
	VBDEBUG("%-30s: %s\n", "firmware_type", vboot->firmware_type);
	VBDEBUG("%-30s: %d\n", "oprom_matters", vboot->oprom_matters);
	VBDEBUG("%-30s: %s\n", "hardware_id", vboot->hardware_id);
	VBDEBUG("%-30s: %s\n", "readonly_firmware_id",
		vboot->readonly_firmware_id);
	VBDEBUG("%-30s: %s\n", "firmware_id", vboot->firmware_id);

	method = vboot->nvcontext_method;
	VBDEBUG(" %-30s: %s\n", "nvcontext_method",
		method ? method->name : "unknown");
	if (method && method->dump)
		(*method->dump)(vboot);

	return 0;
}
