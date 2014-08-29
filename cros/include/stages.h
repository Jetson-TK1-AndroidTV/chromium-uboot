/*
 * Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

struct vboot_info;

enum vboot_stage_t {
	VBOOT_STAGE_FIRST = 0,
	VBOOT_STAGE_RO_INIT = VBOOT_STAGE_FIRST,
	VBOOT_STAGE_RO_VBINIT,
	VBOOT_STAGE_RO_FLAGS,
	VBOOT_STAGE_RO_SELECTFIRMWARE,
	VBOOT_STAGE_RO_PREPARE,
	VBOOT_STAGE_RO_JUMP,

	VBOOT_STAGE_RW_INIT,
	VBOOT_STAGE_RW_SELECTKERNEL,
	VBOOT_STAGE_RW_BOOT,

	VBOOT_STAGE_COUNT,
	VBOOT_STAGE_NONE,
};

/* Flags to use for running stages */
enum vboot_stage_flag_t {
	VBOOT_FLAG_CMDLINE	= 1 << 0,	/* drop to cmdline on error */
};

const char *vboot_get_stage_name(enum vboot_stage_t stagenum);
enum vboot_stage_t vboot_find_stage(const char *name);
int vboot_run_stage(struct vboot_info *vboot, enum vboot_stage_t stage);
int vboot_run_stages(struct vboot_info *vboot, bool do_ro, uint flags);
int vboot_run_auto(struct vboot_info *vboot, uint flags);

int vboot_ro_init(struct vboot_info *vboot);
int vboot_ro_vbinit(struct vboot_info *vboot);
int vboot_ro_flags(struct vboot_info *vboot);
int vboot_ro_select_firmware(struct vboot_info *vboot);
int vboot_ro_prepare(struct vboot_info *vboot);
int vboot_ro_jump(struct vboot_info *vboot);
int vboot_rw_init(struct vboot_info *vboot);
int vboot_rw_select_kernel(struct vboot_info *vboot);
int vboot_rw_boot(struct vboot_info *vboot);
