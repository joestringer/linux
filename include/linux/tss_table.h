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

/* XXX Tuple space search table. */

#ifndef TS_TABLE_H
#define TS_TABLE_H 1

#include <linux/flex_array.h>
#include <linux/rcupdate.h>

struct table_instance {
	struct rcu_head rcu;
	struct flex_array *buckets;
	unsigned int n_buckets;
	int node_ver;
	u32 hash_seed;
};

typedef void (*tst_freefn_t)(struct ts_element *elem, bool deferred);
struct table_instance *table_instance_alloc(int n_elements);
void __table_instance_destroy(struct table_instance *ti);
void table_instance_destroy(struct table_instance *ti, bool deferred);
void table_instance_destroy_rcu_cb(struct rcu_head *rcu);
void table_instance_destroy_and_free(struct table_instance *ti, bool deferred,
				     tst_freefn_t freefn);

/**
 * XXX
 */
struct ts_element {
	struct rcu_head rcu;
	struct hlist_node node[2];
	u32 hash;
	void *key;
	struct ts_mask *mask;
};

typedef void (*tst_freefn_t)(struct ts_element *elem, bool deferred);
struct table_instance *table_instance_alloc(int n_elements);
void __table_instance_destroy(struct table_instance *ti);
void table_instance_destroy(struct table_instance *ti, bool deferred);
void table_instance_destroy_rcu_cb(struct rcu_head *rcu);
void table_instance_destroy_and_free(struct table_instance *ti, bool deferred,
				     tst_freefn_t freefn);

/**
 * XXX
 */
struct ts_range {
	unsigned short int start;
	unsigned short int end;
};

int ts_range_n_bytes(const struct ts_range *range);

/**
 * XXX
 */
struct ts_mask {
	struct rcu_head rcu;
	int ref_count;
	struct list_head list;
	struct ts_range range;
	size_t key_len;
	u8 key[];
};

/* Returns true if 'key1' and 'key2' are the same within 'range'. */
typedef bool (*tst_cmpfn_t)(const void *key1, const void *key2,
			    const struct ts_range *range);

/**
 * struct ts_table - Tuple-space table handle
 *
 * @ti: Current table instance
 * @mask_list: List of masks used for lookup
 * @last_rehash: Jiffies at time of most recent rehash
 * @count: Number of elements residing within 'ti'
 * @key_len: Length of key used for hash, comparison and masked_key storage
 * @masked_key: Buffer to hold masked version of key during lookup
 */
struct ts_table {
	struct table_instance __rcu	*ti;
	struct list_head		mask_list;
	unsigned long			last_rehash;
	unsigned int			count;
	size_t				key_len;
	uint8_t				*masked_key;  /* (n_cpus * key_len) */
	tst_cmpfn_t			compare;
	tst_freefn_t			free;
};

struct tst_dump_ctx {
	u32 bucket;
	u32 last;
	struct table_instance *ti;
};

void tst_mask_key(void *dst, const void *src, const void *mask,
		  const struct ts_range *range);

int tst_init(struct ts_table *table, size_t key_len, tst_cmpfn_t cmpfn,
	     tst_freefn_t freefn, int n_buckets);

/* LOCKME */
/* XXX More conventional alloc/init/free semantics */
int tst_insert(struct ts_table *table, struct ts_element *e,
	       const struct ts_mask *mask);
int tst_flush(struct ts_table *table);
void tst_remove(struct ts_table *table, struct ts_element *e);
struct ts_element *tst_masked_lookup(struct ts_table *table,
				     const void *unmasked, const void *mask,
				     const struct ts_range *range);
struct ts_element *tst_lookup(struct ts_table *table, const void *key);
struct ts_element *tst_lookup_stats(struct ts_table *table,
				    const void *key, u32 *n_mask_hit);
int tst_n_masks(const struct ts_table *table);

#define tss_table_for_each_elem(e, table, unmasked)			\
	struct ts_mask *mask;						\
	list_for_each_entry(mask, &(table)->mask_list, list)		\
		for (e = tst_masked_lookup(table, unmasked,		\
					   (mask)->key, &(mask)->range);\
		     e != NULL; e = NULL)

/* XXX: de-ref'ing ti and passing in is weird */
struct ts_element *tst_dump_next(struct tst_dump_ctx *ctx);

#endif /* TS_TABLE_H */
