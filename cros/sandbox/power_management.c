/*
 * Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

/* Implementation of per-board power management function */

#include <common.h>
#include <asm/getopt.h>
#include <asm/state.h>
#include <cros/common.h>
#include <cros/power_management.h>

int is_processor_reset(void)
{
	struct sandbox_state *state = state_get_current();

	return !state->jumped_fname;
}

void cold_reboot(void)
{
	printf("Please press cold reboot button\n");
}

void power_off(void)
{
	printf("Please unplug the power cable\n");
}
