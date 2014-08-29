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
#include <asm/arch/spl.h>
#include <cros/vboot.h>

/**
 * Called from SPL to handle a wakeup event. If we are running in RO and
 * using early-firmware-selection, we jump to RW SPL. Otherwise we just
 * return.
 */
void board_process_wakeup(void)
{
	struct spl_machine_param *param;
	struct vboot_spl_hdr *hdr;
	void *spl_addr;

	param = spl_get_machine_params();
	if (!param->jump_to_rw_spl)
		return;

	hdr = (struct vboot_spl_hdr *)param->rw_spl_start;
	if (hdr->signature != VBOOT_SPL_SIGNATURE)
		return;

	if (hdr->size > param->rw_spl_size)
		return;

	/* Jump to RW SPL. We need to skip our own header and the SPL header */
	spl_addr = hdr + 1;
	spl_addr += CONFIG_SPL_HEADER_SIZE;
	((void(*)(ulong tag))spl_addr)(0);
}
