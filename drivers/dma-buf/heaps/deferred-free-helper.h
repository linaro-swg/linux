/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Deferred dmabuf freeing helper
 *
 * Copyright (C) 2020 Linaro, Ltd.
 *
 * Based on the ION page pool code
 * Copyright (C) 2011 Google, Inc.
 */

#ifndef DEFERRED_FREE_HELPER_H
#define DEFERRED_FREE_HELPER_H

/**
 * df_reason - enum for reason why item was freed
 *
 * This provides a reason for why the free function was called
 * on the item. This is useful when deferred_free is used in
 * combination with a pagepool, so under pressure the page can
 * be immediately freed.
 *
 * DF_NORMAL:         Normal deferred free
 *
 * DF_UNDER_PRESSURE: Free was called because the system
 *                    is under memory pressure. Usually
 *                    from a shrinker. Avoid allocating
 *                    memory in the free call, as it may
 *                    fail.
 */
enum df_reason {
	DF_NORMAL,
	DF_UNDER_PRESSURE,
};

/**
 * deferred_freelist_item - item structure for deferred freelist
 *
 * This is to be added to the structure for whatever you want to
 * defer freeing on.
 *
 * @nr_pages: number of pages used by item to be freed
 * @free: function pointer to be called when freeing the item
 * @list: list entry for the deferred list
 */
struct deferred_freelist_item {
	size_t nr_pages;
	void (*free)(struct deferred_freelist_item *i,
		     enum df_reason reason);
	struct list_head list;
};

/**
 * deferred_free - add item to the deferred free list
 *
 * @item: Pointer to deferred_freelist_item field of a structure
 * @free: Function pointer to the free call
 * @nr_pages: number of pages to be freed
 */
void deferred_free(struct deferred_freelist_item *item,
		   void (*free)(struct deferred_freelist_item *i,
				enum df_reason reason),
		   size_t nr_pages);
#endif
