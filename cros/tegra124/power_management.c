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
#include <i2c.h>
#include <asm/arch/clock.h>
#include <cros/common.h>
#include <cros/power_management.h>

/*
 * This file is directly copied from cros/tegra114/power_management.c.
 * All functions here need to be fleshed out and verified for Tegra124.
 */

#define PMIC_I2C_BUS		0x00
#define PMIC_I2C_DEVICE_ADDRESS	0x40	/* AS3722 PMIC */
#define PMIC_RESET_CTRL		0x36	/* AS3722 PMIC ResetControl */

int is_processor_reset(void)
{
	/* TODO(twarren@nvidia.com): add board-specific code */
	return 1;
}

static int pmic_set_bit(int reg, int bit, int value)
{
	uint8_t byte;

	if (i2c_read(PMIC_I2C_DEVICE_ADDRESS, reg, 1, &byte, sizeof(byte))) {
		VBDEBUG("i2c_read fail: reg=%02x\n", reg);
		return 1;
	}

	if (value)
		byte |= 1 << bit;
	else
		byte &= ~(1 << bit);

	if (i2c_write(PMIC_I2C_DEVICE_ADDRESS, reg, 1, &byte, sizeof(byte))) {
		VBDEBUG("i2c_write fail: reg=%02x\n", reg);
		return 1;
	}

	return 0;
}

/* This function never returns */
void cold_reboot(void)
{
	if (i2c_set_bus_num(PMIC_I2C_BUS)) {
		VBDEBUG("i2c_set_bus_num fail\n");
		goto fatal;
	}

	/*  Set force-reset bit in PMIC reg 0x36 */
	pmic_set_bit(PMIC_RESET_CTRL, 0, 1);

	/* Wait for 10 ms. If not rebootting, go to endless loop */
	udelay(10 * 1000);

fatal:
	printf("Please press cold reboot button\n");
	while (1)
		;
}

/* This function never returns */
void power_off(void)
{
	if (i2c_set_bus_num(PMIC_I2C_BUS)) {
		VBDEBUG("i2c_set_bus_num fail\n");
		goto fatal;
	}

	/* Set shut-down bit in PMIC reg 0x36*/
	pmic_set_bit(PMIC_RESET_CTRL, 1, 1);

	/* Wait for 10 ms. If not powering off, go to endless loop */
	udelay(10 * 1000);

fatal:
	printf("Please unplug the power cable and battery\n");
	while (1)
		;
}
