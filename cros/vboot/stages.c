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
#include <errno.h>
#include <cros/stages.h>
#include <cros/power_management.h>
#include <cros/vboot.h>

struct vboot_stage {
	const char *name;
	int (*run)(struct vboot_info *vboot);
};

struct vboot_stage stages[] = {
	{ "ro_init", vboot_ro_init, },
	{ "ro_vbinit", vboot_ro_vbinit, },
	{ "ro_flags", vboot_ro_flags, },
	{ "ro_selectfirmware", vboot_ro_select_firmware, },
	{ "ro_prepare", vboot_ro_prepare, },
	{ "ro_jump", vboot_ro_jump, },

#ifdef CONFIG_CROS_RO
	{ "invalid", NULL },
	{ "invalid", NULL },
	{ "invalid", NULL },
#else
	{ "rw_init", vboot_rw_init, },
	{ "rw_selectkernel", vboot_rw_select_kernel, },
	{ "rw_boot", vboot_rw_boot, },
#endif
};

const char *vboot_get_stage_name(enum vboot_stage_t stagenum)
{
	if (stagenum >= VBOOT_STAGE_FIRST && stagenum < VBOOT_STAGE_COUNT)
		return stages[stagenum].name;

	return NULL;
}

enum vboot_stage_t vboot_find_stage(const char *name)
{
	enum vboot_stage_t stagenum;

	for (stagenum = VBOOT_STAGE_FIRST; stagenum < VBOOT_STAGE_COUNT;
	     stagenum++) {
		struct vboot_stage *stage = &stages[stagenum];

		if (!strcmp(name, stage->name))
			return stagenum;
	}

	return VBOOT_STAGE_NONE;
}

int vboot_run_stage(struct vboot_info *vboot, enum vboot_stage_t stagenum)
{
	struct vboot_stage *stage = &stages[stagenum];
	int ret;

	vboot_set_legacy(false);
	VBDEBUG("Running stage '%s'\n", stage->name);
	if (!stage->run) {
		VBDEBUG("   - Stage '%s' not available\n", stage->name);
		return -EPERM;
	}

	bootstage_mark_name(BOOTSTAGE_VBOOT_FIRST + stagenum, stage->name);
	ret = (*stage->run)(vboot);
	if (ret)
		VBDEBUG("Error: stage '%s' returned %d\n", stage->name, ret);

	return ret;
}

int vboot_run_stages(struct vboot_info *vboot, bool do_ro, uint flags)
{
	enum vboot_stage_t start, stagenum;
	int ret;

	start = do_ro ? VBOOT_STAGE_RO_INIT : VBOOT_STAGE_RW_INIT;
	for (stagenum = start; stagenum < VBOOT_STAGE_COUNT; stagenum++) {
		ret = vboot_run_stage(vboot, stagenum);
		if (ret)
			break;
	}

	/* Allow dropping to the command line here for debugging */
	if (flags & VBOOT_FLAG_CMDLINE)
		return -1;

	switch (vboot->vb_error) {
	case VBERROR_BIOS_SHELL_REQUESTED:
		return -1;
	case VBERROR_EC_REBOOT_TO_RO_REQUIRED:
	case VBERROR_SHUTDOWN_REQUESTED:
		power_off();
		break;
	default:
		cold_reboot();
		break;
	}

	return 0;
}

int vboot_run_auto(struct vboot_info *vboot, uint flags)
{
	return vboot_run_stages(vboot, is_processor_reset(), flags);
}
