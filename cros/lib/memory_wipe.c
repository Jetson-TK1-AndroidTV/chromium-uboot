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
#include <inttypes.h>
#include <cros/common.h>
#include <cros/memory_wipe.h>
#include <malloc.h>
#include <physmem.h>
#include <asm/io.h>

#include <vboot_api.h>

/*
 * This implementation tracks regions of memory that need to be wiped by
 * filling them with zeroes. It does that by keeping a linked list of the
 * edges between regions where memory should be wiped and not wiped. New
 * regions take precedence over older regions they overlap with. With
 * increasing addresses, the regions of memory alternate between needing to be
 * wiped and needing to be left alone. Edges similarly alternate between
 * starting a wipe region and starting a not wiped region.
 */

static void memory_wipe_insert_between(struct memory_wipe_edge *before,
	struct memory_wipe_edge *after, phys_addr_t pos)
{
	struct memory_wipe_edge *new_edge =
		(struct memory_wipe_edge *)malloc(sizeof(*new_edge));

	assert(new_edge);
	assert(before != after);

	new_edge->next = after;
	new_edge->pos = pos;
	before->next = new_edge;
}

void memory_wipe_init(struct memory_wipe *wipe)
{
	wipe->head.next = NULL;
	wipe->head.pos = 0;
}

static void memory_wipe_set_region_to(struct memory_wipe *wipe_info,
	phys_addr_t start, phys_addr_t end, int new_wiped)
{
	/* whether the current region was originally going to be wiped. */
	int wipe = 0;

	assert(start != end);

	/* prev is never NULL, but cur might be. */
	struct memory_wipe_edge *prev = &wipe_info->head;
	struct memory_wipe_edge *cur = prev->next;

	/*
	 * Find the start of the new region. After this loop, prev will be
	 * before the start of the new region, and cur will be after it or
	 * overlapping start. If they overlap, this ensures that the existing
	 * edge is deleted and we don't end up with two edges in the same spot.
	 */
	while (cur && cur->pos < start) {
		prev = cur;
		cur = cur->next;
		wipe = !wipe;
	}

	/* Add the "start" edge between prev and cur, if needed. */
	if (new_wiped != wipe) {
		memory_wipe_insert_between(prev, cur, start);
		prev = prev->next;
	}

	/*
	 * Delete any edges obscured by the new region. After this loop, prev
	 * will be before the end of the new region or overlapping it, and cur
	 * will be after if, if there is a edge after it. For the same
	 * reason as above, we want to ensure that we end up with one edge if
	 * there's an overlap.
	 */
	while (cur && cur->pos <= end) {
		cur = cur->next;
		free(prev->next);
		prev->next = cur;
		wipe = !wipe;
	}

	/* Add the "end" edge between prev and cur, if needed. */
	if (wipe != new_wiped)
		memory_wipe_insert_between(prev, cur, end);
}

/* Set a region to "wiped". */
void memory_wipe_add(struct memory_wipe *wipe, phys_addr_t start,
		     phys_addr_t end)
{
	debug("%s: start=%" PRIx64 ", end=%" PRIx64 "\n", __func__,
	      (u64)start, (u64)end);
	memory_wipe_set_region_to(wipe, start, end, 1);
}

/* Set a region to "not wiped". */
void memory_wipe_sub(struct memory_wipe *wipe, phys_addr_t start,
		     phys_addr_t end)
{
	debug("%s: start=%" PRIx64 ", end=%" PRIx64 "\n", __func__,
	      (u64)start, (u64)end);
	memory_wipe_set_region_to(wipe, start, end, 0);
}

/* Actually wipe memory. */
void memory_wipe_execute(struct memory_wipe *wipe)
{
	struct memory_wipe_edge *cur;

	VBDEBUG("Wipe memory regions:\n");
	for (cur = wipe->head.next; cur; cur = cur->next->next) {
		phys_addr_t start, end;

		if (!cur->next) {
			VBDEBUG("Odd number of region edges!\n");
			return;
		}

		start = cur->pos;
		end = cur->next->pos;

		VBDEBUG("\t[%#016llx, %#016llx)\n",
			(unsigned long long)start, (unsigned long long)end);
// 		arch_phys_memset(map_sysmem(start, 0), 0, end - start);
	}
}
