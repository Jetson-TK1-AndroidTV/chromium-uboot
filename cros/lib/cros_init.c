/*
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

#include <common.h>
#include <bootstage.h>
#include <cros_ec.h>
#include <cros/common.h>
#include <cros/boot_device.h>
#include <cros/nvstorage.h>
#include <cros/vboot_flag.h>
#include <cros/keyboard.h>

int cros_init(void)
{
#ifdef CONFIG_CROS_EC
	if (!board_get_cros_ec_dev()) {
		VBDEBUG("cros_ec not available\n");
		return -1;
	}
#endif
	/*
	 * Empty keyboard buffer before boot.  In case EC did not clear its
	 * buffer between power cycles, this prevents vboot of current power
	 * cycle being affected by keystrokes of previous power cycle.
	 */
	while (tstc())
		getc();

	display_clear();

	if (nvstorage_init()) {
		VBDEBUG("nvstorage_init failed\n");
		return -1;
	}

	if (vboot_keymap_init()) {
		VBDEBUG(" vboot_keyboard_init failed\n");
		return -1;
	}

	if (vboot_flag_init()) {
		VBDEBUG(" vboot_flag_init() failed\n");
		return -1;
	}

	return 0;
}
