/*
 * Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

#include <common.h>
#include <sha256.h>
#include <asm/arch/ace.h>
#include <asm/arch/spl.h>
#include <cros/power_management.h>
#include <cros/vboot.h>

static void verified_failed(struct vboot_persist *persist, uint firmware_num,
			    bool enable_debug)
{
	/*
	 * If we don't find the persist information, then there is no need to
	 * do anything here. The information is set up by a previous RO
	 * U-Boot and updated by a previous RW SPL. If neither of those wrote
	 * anything then we have nothing to do. It indicates that verification
	 * is not required (e.g. we are booting the recovery SPL which is in
	 * RO SPI flash).
	 */
	if (persist->magic != VBOOT_PERSIST_MAGIC)
		return;

	/*
	 * Mark this firmware as bad and reboot. This information is stored in
	 * internal SRAM so will persist across the reboot (the call to
	 * cold_reboot())
	 */
	persist->flags |= 1 << firmware_num;
	if (enable_debug)
		printf("Marking firmware %u bad, rebooting\n", firmware_num);
	cold_reboot();
}

static void dump_bytes(const char *name, unsigned char data[], int size)
{
	int i;

	printf("%s: ", name);
	for (i = 0; i < size; i++)
		printf("%02x", data[i]);
	printf("\n");
}

int board_image_verify(int firmware_num, ulong start, ulong size,
		       int enable_debug)
{
	unsigned char digest[SHA256_SUM_LEN];
	struct spl_machine_param *param;
	struct vboot_persist *persist;
	struct spl_hash *hash;
	int ret;

	param = spl_get_machine_params();
	if (!param->vboot_persist_start) {
		if (enable_debug)
			puts(", no persist");
		return -1;
	}
	persist = map_sysmem(param->vboot_persist_start, sizeof(*persist));

	hash = spl_get_hash();
	if (!hash) {
		if (enable_debug)
			puts(", no hash");
		return -1;
	}

	ret = ace_sha_hash_digest((void *)start, size, digest,
				  ACE_SHA_TYPE_SHA256);
	if (ret) {
		puts(", ACE failed\n");
		verified_failed(persist, firmware_num, enable_debug);
	}

	if (memcmp(digest, hash->digest, SHA256_SUM_LEN)) {
		puts(", hash failed\n");
		if (enable_debug) {
			printf("start=%lx, size=%lx\n", start, size);
			dump_bytes("calced", digest, SHA256_SUM_LEN);
			dump_bytes("stored", hash->digest, SHA256_SUM_LEN);
		}
		verified_failed(persist, firmware_num, enable_debug);
	}

	return 0;
}
