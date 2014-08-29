/*
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __configs_chromeos_nyan_big_h__
#define __configs_chromeos_nyan_big_h__

#include <configs/nyan-big.h>

#include <configs/chromeos.h>

#define CONFIG_CHROMEOS_GPIO_FLAG
#define CONFIG_CHROMEOS_CROS_EC_FLAG

#undef CONFIG_BOOTDELAY
#define CONFIG_BOOTDELAY	0

#undef CONFIG_BOOTCOMMAND
/*
#define CONFIG_BOOTCOMMAND "vboot go auto"
*/

#endif
