/*
 * Copyright (c) 2007-2017 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef TS_TABLE_H
#define TS_TABLE_H 1

#include <linux/flex_array.h>
#include <linux/gfp.h>
#include <linux/rcupdate.h>

/* Tuple space search table.
 *
 * This data structure provides wildcarded lookups with the following
 * assumptions:
 *  - No ordering is provided between overlapping elements - for example,
 *    where the key is the same but mask is different for two elements.
 *  - The total number of varying masks should be low.
 */

struct table_instance {
	struct rcu_head rcu;
	struct flex_array *buckets;
	unsigned int n_buckets;
	int node_ver;
	u32 hash_seed;
};

/**
 * struct ts_table - Tuple-space table handle
 *
 * @ti: Current table instance
 * @mask_list: List of masks used for lookup
 * @last_rehash: Jiffies at time of most recent rehash
 * @count: Number of elements residing within 'ti'
 * @gfp: Allocation flags for tables and masks.
 * @key_len: Length of key used for hash, comparison and masked_key storage
 * @free: Function used to free elements in the table upon deletion
 * @masked_key: Buffer to hold masked version of key during lookup
 */
struct ts_table {
	struct table_instance __rcu	*ti;
	struct list_head		mask_list;
	unsigned long			last_rehash;
	unsigned int			count;
	gfp_t				gfp;
	size_t				key_len;
	rcu_callback_t			free;
	void __percpu			*masked_key;
};

struct table_instance *table_instance_alloc(int n_elements, gfp_t gfp);
void table_instance_destroy(struct table_instance *ti, bool deferred);

struct ts_range {
	unsigned short int start;
	unsigned short int end;
};

/* Returns true if 'key1' and 'key2' are the same within 'range'. */
bool ts_compare(const void *key1, const void *key2, const struct ts_range *);
void ts_mask_key(void *dst, const void *src, const void *mask,
		 const struct ts_range *range);

struct ts_element {
	struct rcu_head rcu;
	struct hlist_node node[2];
	u32 hash;
	void *key;
	struct ts_mask *mask;
};

struct ts_mask {
	struct rcu_head rcu;
	struct list_head list;
	int ref_count;
	struct ts_range range;
	size_t key_len;
	u8 key[];
};

/* The user of these functions must ensure writer exclusion. */
int tst_init(struct ts_table *table, size_t key_len, int n_buckets,
	     rcu_callback_t freefn, gfp_t gfp);
int tst_n_masks(const struct ts_table *table);
int tst_insert(struct ts_table *table, struct ts_element *e,
	       const struct ts_mask *mask);
void tst_remove(struct ts_table *table, struct ts_element *e);
int tst_flush(struct ts_table *table);
void tst_destroy(struct ts_table *table);

/* RCU read lock must be held to perform lookup. */
struct ts_element *tst_lookup(struct ts_table *table, const void *key);
struct ts_element *tst_lookup_stats(struct ts_table *table,
				    const void *key, u32 *n_mask_hit);
struct ts_element *tst_masked_lookup(struct ts_table *table,
				     const void *unmasked, const void *mask,
				     const struct ts_range *range);
struct ts_mask *tst_lookup_mask(const struct ts_table *tbl, const void *mask);

/**
 * tst_for_each_elem - iterate over masks in table and look for element.
 * @e:		the &struct ts_element to use as a loop cursor.
 * @table:	the &struct ts_table
 * @unmasked:	the key to look for within 'table'.
 */
#define tst_for_each_elem(e, table, unmasked)				\
	struct ts_mask *mask;						\
	list_for_each_entry(mask, &(table)->mask_list, list)		\
		for (e = tst_masked_lookup(table, unmasked,		\
					   (mask)->key, &(mask)->range);\
		     e != NULL; e = NULL)

struct tst_dump_ctx {
	u32 bucket;
	u32 last;
};

struct ts_element *tst_dump_next(struct ts_table *table,
				 struct tst_dump_ctx *ctx);

#endif /* TS_TABLE_H */
