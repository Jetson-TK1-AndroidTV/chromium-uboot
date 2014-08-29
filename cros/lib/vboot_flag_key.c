/*
 * Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

/* Implementation of vboot flag accessor from a keyboard key (for sandbox) */

#include <common.h>
#include <fdtdec.h>
#include <asm/sdl.h>
#include <cros/common.h>
#include <cros/vboot_flag.h>
#include <linux/input.h>

DECLARE_GLOBAL_DATA_PTR;

static int vboot_flag_setup_key(enum vboot_flag_id id,
				struct vboot_flag_context *context)
{
	const void *blob = gd->fdt_blob;

	/*
	 * TODO(sjg@chromium.org): Allow each driver to have private data and
	 * its own method for writing into crossystem data. Could use a clean
	 * up in vboot_flag.h, but would require crossystem output to be
	 * more intelligent, and perhaps changes to what user-space crossystem
	 * expects.
	 */
	context->key = fdtdec_get_int(blob, context->node, "key", -1);
	if (context->key == -1) {
		VBDEBUG("failed to decode key %s", vboot_flag_node_name(id));
		return -1;
	}

	context->initialized = 1;

	return 0;
}

static int vboot_flag_fetch_key(enum vboot_flag_id id,
				struct vboot_flag_context *context,
				struct vboot_flag_details *details)
{
	if (!context->initialized) {
		VBDEBUG("gpio state is not initialized\n");
		return -1;
	}
	details->port = 0;
	details->active_high = 0;
	details->value = sandbox_sdl_key_pressed(context->key);

	return 0;
}

CROS_VBOOT_FLAG_DRIVER(key) = {
	.name	= "key",
	.compat	= COMPAT_GOOGLE_KEY_FLAG,
	.setup	= vboot_flag_setup_key,
	.fetch	= vboot_flag_fetch_key,
};
