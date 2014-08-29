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
#include <cros_ec.h>
#include <cros/common.h>
#include <cros/nvstorage.h>

#include <vboot_api.h>

static VbError_t nvstorage_read_cros_ec(uint8_t *buf)
{
	struct cros_ec_dev *dev;
	int ret;

	dev = board_get_cros_ec_dev();
	if (!dev) {
		VBDEBUG("%s: no cros_ec device\n", __func__);
		return 1;
	}

	ret = cros_ec_read_vbnvcontext(dev, buf);
	if (ret) {
		VBDEBUG("%s failed, ret=%d\n", __func__, ret);
		return 1;
	}

	return VBERROR_SUCCESS;
}

static VbError_t nvstorage_write_cros_ec(const uint8_t *buf)
{
	struct cros_ec_dev *dev;
	int ret;

	VBDEBUG("%s\n", __func__);
	dev = board_get_cros_ec_dev();
	if (!dev) {
		VBDEBUG("%s: no cros_ec device\n", __func__);
		return 1;
	}

	ret = cros_ec_write_vbnvcontext(dev, buf);
	if (ret) {
		VBDEBUG("%s failed, ret=%d\n", __func__, ret);
		return 1;
	}

	return VBERROR_SUCCESS;
}

CROS_NVSTORAGE_METHOD(cros_ec) = {
	.name = "cros-ec",
	.read = nvstorage_read_cros_ec,
	.write = nvstorage_write_cros_ec,
};
