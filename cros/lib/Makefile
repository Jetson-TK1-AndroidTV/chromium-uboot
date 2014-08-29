#
# (C) Copyright 2014 Google, Inc
#
# SPDX-License-Identifier:	GPL-2.0+
#

obj-$(CONFIG_CHROMEOS) += boot_kernel.o
obj-$(CONFIG_CHROMEOS) += cros_init.o
obj-$(CONFIG_CHROMEOS) += crossystem_data.o
ifeq ($(CONFIG_CHROMEOS),y)
obj-$(CONFIG_OF_CONTROL) += cros_fdtdec.o
endif
obj-$(CONFIG_CHROMEOS_SPI) += firmware_storage_spi.o
obj-$(CONFIG_CHROMEOS_MMC) += firmware_storage_mmc.o
obj-$(CONFIG_CHROMEOS) += fmap.o
obj-$(CONFIG_CHROMEOS) += gbb.o
obj-$(CONFIG_CHROMEOS) += memory_wipe.o
obj-$(CONFIG_CHROMEOS) += vboot_flag.o
obj-$(CONFIG_CHROMEOS_CONST_FLAG) += vboot_flag_const.o
obj-$(CONFIG_CHROMEOS_GPIO_FLAG) += vboot_flag_gpio.o
obj-$(CONFIG_CHROMEOS_KEY_FLAG) += vboot_flag_key.o
obj-$(CONFIG_CHROMEOS_CROS_EC_FLAG) += vboot_flag_cros_ec.o
obj-$(CONFIG_CHROMEOS) += vboot_flag_debug.o
obj-$(CONFIG_CHROMEOS) += vboot.o vboot_dump.o vboot_fdt.o
obj-$(CONFIG_CHROMEOS) += readonly.o
obj-$(CONFIG_CHROMEOS) += readwrite.o
