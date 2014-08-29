/*
 * Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */

#include <common.h>
#include <errno.h>
#include <libfdt.h>
#include <asm/io.h>
#include <cros/common.h>
#include <cros/cros_fdtdec.h>
#include <cros/fmap.h>
#include <fdtdec.h>
#include <linux/string.h>
#include <malloc.h>

/*
 * Some platforms where DRAM is based at zero do not define DRAM base address
 * explicitly.
 */
#ifdef CONFIG_SYS_SDRAM_BASE
#define DRAM_BASE_ADDRESS CONFIG_SYS_SDRAM_BASE
#else
#define DRAM_BASE_ADDRESS 0
#endif

int cros_fdtdec_config_node(const void *blob)
{
	int node = fdt_path_offset(blob, "/chromeos-config");

	if (node < 0)
		VBDEBUG("failed to find /chromeos-config: %d\n", node);

	return node;
}

/* These are the various flashmap nodes that we are interested in */
enum section_t {
	SECTION_BASE,		/* group section, no name: rw-a and rw-b */
	SECTION_FIRMWARE_ID,
	SECTION_BOOT,
	SECTION_GBB,
	SECTION_VBLOCK,
	SECTION_FMAP,
	SECTION_ECRW,
	SECTION_ECRO,
	SECTION_SPL,
	SECTION_BOOT_REC,
	SECTION_SPL_REC,

	SECTION_COUNT,
	SECTION_NONE = -1,
};

/* Names for each section, preceeded by ro-, rw-a- or rw-b- */
static const char *section_name[SECTION_COUNT] = {
	"",
	"firmware-id",
	"boot",
	"gbb",
	"vblock",
	"fmap",
	"ecrw",
	"ecro",
	"spl",
	"boot-rec",
	"spl-rec",
};

/**
 * Look up a section name and return its type
 *
 * @param name		Name of section (after ro- or rw-a/b- part)
 * @return section type section_t, or SECTION_NONE if none
 */
static enum section_t lookup_section(const char *name)
{
	char *at;
	int i, len;

	at = strchr(name, '@');
	len = at ? at - name : strlen(name);
	for (i = 0; i < SECTION_COUNT; i++)
		if (0 == strncmp(name, section_name[i], len))
			return i;

	return SECTION_NONE;
}

/**
 * Process a flashmap node, storing its information in our config.
 *
 * @param blob		FDT blob
 * @param node		Offset of node to read
 * @param depth		Depth of node: 1 for a normal section, 2 for a
 *			sub-section
 * @param config	Place to put the information we read
 * @param fwp		Indicates the type of data in the last depth 1 node
 *			that we read. It points to &config->readonly,
 *			&config->readwrite_a or &config->readwrite_b. This
 *			is used to work out which section we are referring
 *			to at depth 2.
 *
 * Both rwp and ecp start as NULL and are updated when we see an RW and an
 * EC region respectively. This function is called for every node in the
 * device tree and these variables maintain the state that we need to
 * process the nodes correctly.
 *
 * @return 0 if ok, -ve on error
 */
static int process_fmap_node(const void *blob, int node, int depth,
		struct twostop_fmap *config, struct fmap_firmware_entry **fwp)
{
	struct fmap_firmware_entry *fw = *fwp;
	enum section_t section;
	struct fmap_entry *entry;
	const char *name, *subname;
	int len;

	name = fdt_get_name(blob, node, &len);
	if (name && !strcmp("rw-vblock-dev", name)) {
		/* handle optional dev key */
		if (fdtdec_read_fmap_entry(blob, node, name,
					   &config->readwrite_devkey))
			return -FDT_ERR_NOTFOUND;
		else
			return 0;
	}

	if (name && !strcmp("rw-elog", name)) {
		/* handle the event log */
		if (fdtdec_read_fmap_entry(blob, node, name, &config->elog))
			return -FDT_ERR_NOTFOUND;
		else
			return 0;
	}

	/* We are looking only for ro-, rw-a- and rw-b- */
	if (len < 4 || *name != 'r' || name[2] != '-')
		return 0;
	if (name[1] == 'o') {
		fw = &config->readonly;
		subname = name + 3;
	} else if (name[1] == 'w') {
		if (name[3] == 'a')
			fw = &config->readwrite_a;
		else if (name[3] == 'b')
			fw = &config->readwrite_b;
		else
			return 0;
		subname = name + 4;
		if (*subname == '-')
			subname++;
	} else {
		return 0;
	}

	/* Figure out what section we are dealing with, either ro or rw */
	section = lookup_section(subname);
	entry = NULL;

	/*
	 * TODO(sjg@chromium.org): We could use offsetof() here and avoid
	 * this switch by putting the offset of each field in a table.
	 */
	switch (section) {
	case SECTION_BASE:
		entry = &fw->all;
		fw->block_offset = fdtdec_get_uint64(blob, node,
						"block-offset", ~0ULL);
		if (fw->block_offset == ~0ULL)
			VBDEBUG("Node '%s': bad block-offset\n", name);
		break;
	case SECTION_FIRMWARE_ID:
		entry = &fw->firmware_id;
		break;
	case SECTION_BOOT:
		entry = &fw->boot;
		break;
	case SECTION_GBB:
		entry = &fw->gbb;
		break;
	case SECTION_VBLOCK:
		entry = &fw->vblock;
		break;
	case SECTION_FMAP:
		entry = &fw->fmap;
		break;
	case SECTION_ECRW:
		entry = &fw->ec_rw;
		break;
	case SECTION_ECRO:
		entry = &fw->ec_ro;
		break;
	case SECTION_SPL:
		entry = &fw->spl;
		break;
	case SECTION_BOOT_REC:
		entry = &fw->boot_rec;
		break;
	case SECTION_SPL_REC:
		entry = &fw->spl_rec;
		break;
	case SECTION_COUNT:
	case SECTION_NONE:
		return 0;
	}

	/* Read in the properties */
	assert(entry);
	if (entry && fdtdec_read_fmap_entry(blob, node, name, entry))
		return -FDT_ERR_NOTFOUND;

	*fwp = fw;

	return 0;
}

int cros_fdtdec_flashmap(const void *blob, struct twostop_fmap *config)
{
	struct fmap_firmware_entry *fw = NULL;
	struct fmap_entry entry;
	int offset;
	int depth;

	memset(config, '\0', sizeof(*config));
	offset = fdt_node_offset_by_compatible(blob, -1,
			"chromeos,flashmap");
	if (offset < 0) {
		VBDEBUG("chromeos,flashmap node is missing\n");
		return offset;
	}

	/* Read in the 'reg' property */
	if (fdtdec_read_fmap_entry(blob, offset,
				   fdt_get_name(blob, offset, NULL), &entry))
		return -1;
	config->flash_base = entry.offset;

	depth = 0;
	while (offset > 0 && depth >= 0) {
		int node;

		node = fdt_next_node(blob, offset, &depth);
		if (node > 0 && depth > 0) {
			if (process_fmap_node(blob, node, depth, config,
					      &fw)) {
				VBDEBUG("Failed to process Flashmap\n");
				return -1;
			}
		}
		offset = node;
	}

	return 0;
}

int cros_fdtdec_config_has_prop(const void *blob, const char *name)
{
	int nodeoffset = cros_fdtdec_config_node(blob);

	return nodeoffset >= 0 &&
		fdt_get_property(blob, nodeoffset, name, NULL) != NULL;
}

int cros_fdtdec_decode_region(const void *blob, const char *mem_type,
			      const char *suffix, fdt_addr_t *basep,
			      fdt_size_t *sizep)
{
	int node = cros_fdtdec_config_node(blob);
	int ret;

	if (node < 0)
		return -ENOENT;
	ret = fdtdec_decode_memory_region(blob, node, mem_type, suffix, basep,
					  sizep);
	if (ret) {
		VBDEBUG("failed to find %s suffix %s in /chromeos-config\n",
			mem_type, suffix);
		return ret;
	}

	return 0;
}

int cros_fdtdec_memory(const void *blob, const char *name,
		struct fdt_memory *config)
{
	int node, len;
	const fdt_addr_t *cell;

	node = fdt_path_offset(blob, name);
	if (node < 0)
		return node;

	cell = fdt_getprop(blob, node, "reg", &len);
	if (cell && len >= sizeof(fdt_addr_t) * 2) {
		config->start = fdt_addr_to_cpu(cell[0]);
		config->end = config->start + fdt_addr_to_cpu(cell[1]);
	} else
		return -FDT_ERR_BADLAYOUT;

	return 0;
}
