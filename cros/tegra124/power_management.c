/*
 * Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

/* Implementation of per-board power management function */

#include <common.h>
#include <errno.h>
#include <i2c.h>
#include <spl.h>
#include <asm/arch/clock.h>
#include <asm/arch-tegra/sys_proto.h>
#include <asm-generic/gpio.h>
#include <cros/common.h>
#include <cros/power_management.h>
#include <power/as3722.h>

DECLARE_GLOBAL_DATA_PTR;

/*
 * This file is directly copied from cros/tegra114/power_management.c.
 * All functions here need to be fleshed out and verified for Tegra124.
 */

#define PMIC_I2C_BUS		0x00
#define PMIC_I2C_DEVICE_ADDRESS	0x40	/* AS3722 PMIC */
#define PMIC_RESET_CTRL		0x36	/* AS3722 PMIC ResetControl */

int is_processor_reset(void)
{
	return spl_was_boot_source();
}

static int pmic_set_bit(int reg, int bit, int value)
{
	struct udevice *pmic;
	uint8_t byte;
	int ret;

	ret = as3722_get(&pmic);
	if (ret)
		return -ENOENT;

	ret = dm_i2c_read(pmic, reg, &byte, sizeof(byte));
	if (ret) {
		VBDEBUG("i2c_read fail: reg=%02x\n", reg);
		return ret;
	}

	if (value)
		byte |= 1 << bit;
	else
		byte &= ~(1 << bit);

	ret = dm_i2c_write(pmic, reg, &byte, sizeof(byte));
	if (ret) {
		VBDEBUG("i2c_write fail: reg=%02x\n", reg);
		return ret;
	}

	return 0;
}

/* This function never returns */
void cold_reboot(void)
{
	const void *blob = gd->fdt_blob;
	struct gpio_desc desc;
	int ret, node;

	VBDEBUG("cold_reboot\n");
	mdelay(100);
	node = fdt_path_offset(blob, "/config");
	ret = gpio_request_by_name_nodev(blob, node, "reset-gpio", 0, &desc,
					 GPIOD_IS_OUT | GPIOD_IS_OUT_ACTIVE);
	if (ret && ret != -ENOENT)
		VBDEBUG("cold_reboot: reset failed: %d\n", ret);
	VBDEBUG("gpio reset %d\n", ret);
	mdelay(100);

	/* Set force-reset bit in PMIC reg 0x36 */
	if (!pmic_set_bit(PMIC_RESET_CTRL, 0, 1)) {
		/* Wait for 10 ms. If not rebootting, go to endless loop */
		mdelay(10);
	}

	printf("Please press cold reboot button\n");
	while (1)
		;
}

/* This function never returns */
void power_off(void)
{
	VBDEBUG("power_off\n");
	mdelay(100);
	/* Set shut-down bit in PMIC reg 0x36*/
	if (!pmic_set_bit(PMIC_RESET_CTRL, 1, 1)) {
		/* Wait for 10 ms. If not powering off, go to endless loop */
		mdelay(10);
	}

	printf("Please unplug the power cable and battery\n");
	while (1)
		;
}
