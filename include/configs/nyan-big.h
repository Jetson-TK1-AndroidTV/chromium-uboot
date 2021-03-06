/*
 * (C) Copyright 2014
 * NVIDIA Corporation <www.nvidia.com>
 *
 * SPDX-License-Identifier:     GPL-2.0+
 */

#ifndef __CONFIG_H
#define __CONFIG_H

#include <linux/sizes.h>

#include "tegra124-common.h"

#define CONFIG_EXTRA_BOOTARGS	\
	"earlyprintk=ttyS0,115200n8 console=tty1 keep_bootcon " \
	"loglevel=7 init=/sbin/init oops=panic panic=-1 " \
	"noinitrd cros_debug vt.global_cursor_default=0 " \
	"kern_guid=be426bbb-cd3a-d14a-8fe7-55bc7b7f12ff "

/* High-level configuration options */
#define V_PROMPT			"Tegra124 (Nyan-big) # "
#define CONFIG_TEGRA_BOARD_STRING	"Google/NVIDIA Nyan-big"

/* Board-specific serial config */
#define CONFIG_SERIAL_MULTI
#define CONFIG_TEGRA_ENABLE_UARTA
#define CONFIG_SYS_NS16550_COM1		NV_PA_APB_UARTA_BASE

#define CONFIG_DISPLAY_BOARDINFO_LATE

/* I2C */
#define CONFIG_SYS_I2C_TEGRA
#define CONFIG_CMD_I2C

/* SD/MMC */
#define CONFIG_MMC
#define CONFIG_GENERIC_MMC
#define CONFIG_TEGRA_MMC
#define CONFIG_CMD_MMC

/* Environment in eMMC, at the end of 2nd "boot sector" */
#define CONFIG_ENV_IS_IN_MMC
#define CONFIG_SYS_MMC_ENV_DEV		0
#define CONFIG_SYS_MMC_ENV_PART		2
#define CONFIG_ENV_OFFSET		(-CONFIG_ENV_SIZE)

#define CONFIG_I2C_EDID

/* LCD support */
#define CONFIG_LCD
#define CONFIG_PWM_TEGRA
#define CONFIG_AS3722_POWER
#define LCD_BPP				LCD_COLOR16
#define CONFIG_SYS_WHITE_ON_BLACK
#define CONFIG_CMD_BMP

/* Align LCD to 1MB boundary */
#define CONFIG_LCD_ALIGNMENT	MMU_SECTION_SIZE

/* SPI */
#define CONFIG_TEGRA114_SPI		/* Compatible w/ Tegra114 SPI */
#define CONFIG_TEGRA114_SPI_CTRLS	6
#define CONFIG_SPI_FLASH
#define CONFIG_SPI_FLASH_WINBOND
#define CONFIG_SF_DEFAULT_MODE         SPI_MODE_0
#define CONFIG_SF_DEFAULT_SPEED        24000000
#define CONFIG_CMD_SPI
#define CONFIG_CMD_SF
#define CONFIG_SPI_FLASH_SIZE          (4 << 20)

/* USB Host support */
#define CONFIG_USB_EHCI
#define CONFIG_USB_EHCI_TEGRA
#define CONFIG_USB_MAX_CONTROLLER_COUNT	2
#define CONFIG_USB_STORAGE
#define CONFIG_CMD_USB

/* USB networking support */
#define CONFIG_USB_HOST_ETHER
#define CONFIG_USB_ETHER_ASIX

/* General networking support */
#define CONFIG_CMD_NET
#define CONFIG_CMD_DHCP

#define CONFIG_FIT
#define CONFIG_FIT_BEST_MATCH
#define CONFIG_OF_LIBFDT

#define CONFIG_KEYBOARD

#undef CONFIG_LOADADDR
#define CONFIG_LOADADDR 	0x80A00800	/* nvflash default */

/* TPM */
#define CONFIG_TPM
#define CONFIG_CMD_TPM
#define CONFIG_TPM_TIS_I2C

/*
#ifndef CONFIG_SPL_BUILD
#define CONFIG_SYS_THUMB_BUILD
#endif
*/

#include "tegra-common-usb-gadget.h"
#include "tegra-common-post.h"

#endif /* __CONFIG_H */
