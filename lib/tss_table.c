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

#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/tss_table.h>
#include <linux/types.h>

#define REHASH_INTERVAL		(10 * 60 * HZ)

/* XXX Lock dep */
#define ovsl_dereference(p) \
	rcu_dereference_protected(p, 1)
#define rcu_dereference_ovsl(p) \
	rcu_dereference_check(p, 1)

static void free_buckets(struct flex_array *buckets)
{
	flex_array_free(buckets);
}

void __table_instance_destroy(struct table_instance *ti)
{
	free_buckets(ti->buckets);
	kfree(ti);
}
EXPORT_SYMBOL(__table_instance_destroy);

void table_instance_destroy_rcu_cb(struct rcu_head *rcu)
{
	struct table_instance *ti;

	ti = container_of(rcu, struct table_instance, rcu);
	__table_instance_destroy(ti);
}
EXPORT_SYMBOL(table_instance_destroy_rcu_cb);

void table_instance_destroy(struct table_instance *ti, bool deferred)
{
	if (deferred)
		call_rcu(&ti->rcu, table_instance_destroy_rcu_cb);
	else
		__table_instance_destroy(ti);
}
EXPORT_SYMBOL(table_instance_destroy);

static struct flex_array *alloc_buckets(unsigned int n_buckets)
{
	struct flex_array *buckets;
	int i, err;

	buckets = flex_array_alloc(sizeof(struct hlist_head),
				   n_buckets, GFP_ATOMIC);
	if (!buckets)
		return NULL;

	err = flex_array_prealloc(buckets, 0, n_buckets, GFP_ATOMIC);
	if (err) {
		flex_array_free(buckets);
		return NULL;
	}

	for (i = 0; i < n_buckets; i++)
		INIT_HLIST_HEAD((struct hlist_head *)
					flex_array_get(buckets, i));

	return buckets;
}

struct table_instance *table_instance_alloc(int n_elements)
{
	struct table_instance *ti = kmalloc(sizeof(*ti), GFP_ATOMIC);

	if (!ti)
		return NULL;

	ti->buckets = alloc_buckets(n_elements);
	if (!ti->buckets) {
		kfree(ti);
		return NULL;
	}
	ti->n_buckets = n_elements;
	ti->node_ver = 0;
	get_random_bytes(&ti->hash_seed, sizeof(u32));

	return ti;
}
EXPORT_SYMBOL(table_instance_alloc);

int ts_range_n_bytes(const struct ts_range *range)
{
	int n = range->end - range->start;

	if (n <= 0)
		WARN_ONCE(1, "masking invalid range %d -> %d\n", range->start,
			  range->end);
	return n < 0 ? 0 : n;
}
EXPORT_SYMBOL(ts_range_n_bytes);

void tst_mask_key(void *dst, const void *src, const void *mask,
		  const struct ts_range *range)
{
	int start = range->start;
	int len = ts_range_n_bytes(range);
	const long *m = (const long *)((const u8 *)mask + start);
	const long *s = (const long *)((const u8 *)src + start);
	long *d = (long *)((u8 *)dst + start);
	int i;

	for (i = 0; i < len; i += sizeof(long))
		*d++ = *s++ & *m++;
}
EXPORT_SYMBOL(tst_mask_key);

int tst_init(struct ts_table *table, size_t key_len, tst_cmpfn_t cmpfn,
	     tst_freefn_t freefn, int n_buckets)
{
	struct table_instance *ti;

	ti = table_instance_alloc(n_buckets);
	if (!ti)
		return -ENOMEM;

	table->masked_key = kmalloc(key_len * nr_cpu_ids, GFP_KERNEL);
	if (!table->masked_key)
		goto free_ti;

	rcu_assign_pointer(table->ti, ti);
	INIT_LIST_HEAD(&table->mask_list);
	table->last_rehash = jiffies;
	table->count = 0;
	table->key_len = key_len;
	table->compare = cmpfn;
	table->free = freefn;

	return 0;

free_ti:
	__table_instance_destroy(ti);
	return -ENOMEM;
}
EXPORT_SYMBOL(tst_init);

void table_instance_destroy_and_free(struct table_instance *ti, bool deferred,
				     tst_freefn_t freefn)
{
	int i;

	for (i = 0; i < ti->n_buckets; i++) {
		struct hlist_head *head = flex_array_get(ti->buckets, i);
		int ver = ti->node_ver;
		struct ts_element *e;
		struct hlist_node *n;

		hlist_for_each_entry_safe(e, n, head, node[ver]) {
			hlist_del_rcu(&e->node[ver]);
			freefn(e, deferred);
		}
	}

	table_instance_destroy(ti, deferred);
}
EXPORT_SYMBOL(table_instance_destroy_and_free);

/* Caller must acquire mutex write lock. */
int tst_flush(struct ts_table *table)
{
	struct table_instance *old_ti = ovsl_dereference(table->ti);
	int err;

	/* XXX check masks list */

	err = tst_init(table, table->key_len, table->compare, table->free,
		       old_ti->n_buckets);
	if (err)
		return err;

	if (old_ti)
		table_instance_destroy_and_free(old_ti, true, table->free);

	return 0;
}
EXPORT_SYMBOL(tst_flush);

struct ts_element *tst_dump_next(struct tst_dump_ctx *ctx)
{
	struct ts_element *e;
	struct hlist_head *head;
	int ver;
	int i;

	ver = ctx->ti->node_ver;
	while (ctx->bucket < ctx->ti->n_buckets) {
		i = 0;
		head = flex_array_get(ctx->ti->buckets, ctx->bucket);
		hlist_for_each_entry_rcu(e, head, node[ver]) {
			if (i < ctx->last) {
				i++;
				continue;
			}
			ctx->last = i + 1;
			return e;
		}
		ctx->bucket++;
		ctx->last = 0;
	}

	return NULL;
}
EXPORT_SYMBOL(tst_dump_next);

static struct hlist_head *find_bucket(struct table_instance *ti, u32 hash)
{
	hash = jhash_1word(hash, ti->hash_seed);
	return flex_array_get(ti->buckets,
				(hash & (ti->n_buckets - 1)));
}

static void table_instance_insert(struct table_instance *ti,
				      struct ts_element *e)
{
	struct hlist_head *head;

	head = find_bucket(ti, e->hash);
	hlist_add_head_rcu(&e->node[ti->node_ver], head);
}

static void table_instance_copy_elems(struct table_instance *old,
				      struct table_instance *new)
{
	int old_ver;
	int i;

	old_ver = old->node_ver;
	new->node_ver = !old_ver;

	/* Insert in new table. */
	for (i = 0; i < old->n_buckets; i++) {
		struct ts_element *e;
		struct hlist_head *head;

		head = flex_array_get(old->buckets, i);
		hlist_for_each_entry(e, head, node[old_ver])
			table_instance_insert(new, e);
	}
}

static struct table_instance *table_instance_rehash(struct table_instance *ti,
						    int n_buckets)
{
	struct table_instance *new_ti;

	new_ti = table_instance_alloc(n_buckets);
	if (!new_ti)
		return NULL;

	table_instance_copy_elems(ti, new_ti);

	return new_ti;
}

static struct table_instance *table_instance_expand(struct table_instance *ti)
{
	return table_instance_rehash(ti, ti->n_buckets * 2);
}

static u32 tst_hash(const void *key, const struct ts_range *range)
{
	int key_start = range->start;
	int key_end = range->end;
	const u32 *hash_key = (const u32 *)((const u8 *)key + key_start);
	int hash_u32s = (key_end - key_start) >> 2;

	/* Make sure number of hash bytes are multiple of u32. */
	BUILD_BUG_ON(sizeof(long) % sizeof(u32));

	return jhash2(hash_key, hash_u32s, 0);
}

static uint8_t *get_pcpu_key(struct ts_table *table)
{
	int cpu = get_cpu();
	uint8_t *key;

	key = &table->masked_key[cpu * table->key_len];
	put_cpu();
	return key;
}

/* Caller must acquire RCU read lock or mutex write lock. */
struct ts_element *tst_masked_lookup(struct ts_table *table,
				     const void *unmasked, const void *mask,
				     const struct ts_range *range)
{
	struct table_instance *ti = rcu_dereference_ovsl(table->ti);
	uint8_t *masked_key;
	struct ts_element *element;
	struct hlist_head *head;
	u32 hash;

	masked_key = get_pcpu_key(table);
	tst_mask_key(masked_key, unmasked, mask, range);
	hash = tst_hash(masked_key, range);
	head = find_bucket(ti, hash);
	hlist_for_each_entry_rcu(element, head, node[ti->node_ver]) {
		if (&element->mask->key == mask && element->hash == hash &&
		    table->compare(element->key, masked_key, range))
			return element;
	}
	return NULL;
}
EXPORT_SYMBOL(tst_masked_lookup);

/* Must be called with RCU read lock or mutex */
struct ts_element *tst_lookup_stats(struct ts_table *table,
				    const void *key, u32 *n_mask_hit)
{
	const struct ts_mask *mask;
	struct ts_element *e;

	*n_mask_hit = 0;
	list_for_each_entry_rcu(mask, &table->mask_list, list) {
		(*n_mask_hit)++;
		e = tst_masked_lookup(table, key, &mask->key, &mask->range);
		if (e)  /* Found */
			return e;
	}
	return NULL;
}
EXPORT_SYMBOL(tst_lookup_stats);

/* Must be called with RCU read lock or mutex */
struct ts_element *tst_lookup(struct ts_table *table, const void *key)
{
	u32 __always_unused n_mask_hit;
	return tst_lookup_stats(table, key, &n_mask_hit);
}
EXPORT_SYMBOL(tst_lookup);

/* Must be called with mutex */
int tst_n_masks(const struct ts_table *table)
{
	struct ts_mask *mask;
	int num = 0;

	list_for_each_entry(mask, &table->mask_list, list)
		num++;

	return num;
}
EXPORT_SYMBOL(tst_n_masks);

/* Remove 'mask' from the mask list, if it is not needed any more. */
/* Caller must acquire mutex write lock. */
static void tst_mask_remove(struct ts_mask *mask)
{
	if (mask) {
		WARN_ONCE(!mask->ref_count,
			  "Locking required to protect mask refcount and list");
		mask->ref_count--;

		if (!mask->ref_count) {
			list_del_rcu(&mask->list);
			kfree_rcu(mask, rcu);
		}
	}
}

/* Caller must acquire mutex write lock. */
void tst_remove(struct ts_table *table, struct ts_element *e)
{
	struct table_instance *ti = ovsl_dereference(table->ti);

	BUG_ON(table->count == 0);
	hlist_del_rcu(&e->node[ti->node_ver]);
	table->count--;

	/* RCU delete the mask. 'flow->mask' is not NULLed, as it should be
	 * accessible as long as the RCU read lock is held.
	 */
	tst_mask_remove(e->mask);
}
EXPORT_SYMBOL(tst_remove);

static struct ts_mask *mask_alloc(size_t key_len)
{
	size_t mask_size = sizeof(struct ts_mask) + key_len;
	struct ts_mask *mask;

	mask = kmalloc(mask_size, GFP_ATOMIC);
	if (mask) {
		mask->ref_count = 1;
		mask->key_len = key_len;
	}

	return mask;
}

static bool mask_equal(const struct ts_mask *a,
		       const struct ts_mask *b)
{
	const u8 *a_ = (const u8 *)&a->key + a->range.start;
	const u8 *b_ = (const u8 *)&b->key + b->range.start;

	return  (a->range.end == b->range.end)
		&& (a->range.start == b->range.start)
		&& (memcmp(a_, b_, ts_range_n_bytes(&a->range)) == 0);
}

static struct ts_mask *tuple_mask_find(const struct ts_table *tbl,
				       const struct ts_mask *mask)
{
	struct list_head *ml;

	list_for_each(ml, &tbl->mask_list) {
		struct ts_mask *m;
		m = container_of(ml, struct ts_mask, list);
		if (mask_equal(mask, m))
			return m;
	}

	return NULL;
}

/* Add 'mask' into the mask list, if it is not already there. */
static int tuple_mask_insert(struct ts_table *tbl, struct ts_element *e,
			     const struct ts_mask *new)
{
	struct ts_mask *mask;

	mask = tuple_mask_find(tbl, new);
	if (!mask) {
		/* XXX Limit n_masks */
		/* Allocate a new mask if none exists. */
		mask = mask_alloc(new->key_len);
		if (!mask)
			return -ENOMEM;
		memcpy(&mask->key, &new->key, new->key_len);
		mask->range = new->range;
		list_add_rcu(&mask->list, &tbl->mask_list);
	} else {
		BUG_ON(!mask->ref_count);
		mask->ref_count++;
	}

	e->mask = mask;
	return 0;
}

/* Caller must acquire mutex write lock. */
static void table_insert(struct ts_table *table, struct ts_element *e,
			 void *key)
{
	struct table_instance *new_ti = NULL;
	struct table_instance *ti;

	e->hash = tst_hash(key, &e->mask->range);
	ti = ovsl_dereference(table->ti);
	table_instance_insert(ti, e);
	table->count++;

	/* Expand table, if necessary, to make room. */
	if (table->count > ti->n_buckets)
		new_ti = table_instance_expand(ti);
	else if (time_after(jiffies, table->last_rehash + REHASH_INTERVAL))
		new_ti = table_instance_rehash(ti, ti->n_buckets);
	else
		return;

	if (new_ti) {
		rcu_assign_pointer(table->ti, new_ti);
		call_rcu(&ti->rcu, table_instance_destroy_rcu_cb);
		table->last_rehash = jiffies;
	} else {
		WARN_ONCE(1, "tss rehash/expand failed\n");
	}
}

/* Caller must acquire mutex write lock. */
int tst_insert(struct ts_table *table, struct ts_element *e,
	       const struct ts_mask *mask)
{
	int err;

	err = tuple_mask_insert(table, e, mask);
	if (err)
		return err;
	table_insert(table, e, e->key);

	return 0;
}
EXPORT_SYMBOL(tst_insert);
