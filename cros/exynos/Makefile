#
# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Alternatively, this software may be distributed under the terms of the
# GNU General Public License ("GPL") version 2 as published by the Free
# Software Foundation.
#

obj-$(CONFIG_CHROMEOS) += power_management.o
obj-$(CONFIG_CHROMEOS) += utility.o
obj-$(CONFIG_CHROMEOS_GPIO_FLAG) += vboot_flag_gpio_arch.o
obj-$(CONFIG_CHROMEOS) += legacy.o
obj-$(CONFIG_POWER_TPS65090_EC) += tps65090_ec.o

ifdef CONFIG_SPL_BUILD
ifdef CONFIG_VAR_SIZE_SPL
obj-$(CONFIG_CHROMEOS) += verify.o
obj-$(CONFIG_CHROMEOS) += wakeup.o
endif
endif
