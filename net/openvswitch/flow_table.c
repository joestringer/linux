/*
 * Copyright (c) 2007-2014 Nicira, Inc.
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

#include "flow.h"
#include "datapath.h"
#include "flow_netlink.h"
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <net/llc_pdu.h>
#include <linux/kernel.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/llc.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/rcupdate.h>
#include <linux/cpumask.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sctp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/rculist.h>
#include <linux/smp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ndisc.h>

#define TBL_MIN_BUCKETS		1024
#define REHASH_INTERVAL		(10 * 60 * HZ)

static struct kmem_cache *flow_cache;
struct kmem_cache *flow_stats_cache __read_mostly;

static void table_instance_destroy_and_free(struct table_instance *ti,
					    bool deferred);

static bool cmp_key(const void *k1, const void *k2,
		    const struct ts_range *range);

#define tss_table_for_each_elem(e, table, unmasked)			\
	struct ts_mask *mask;						\
	list_for_each_entry(mask, &(table)->mask_list, list)		\
		for (e = ts_masked_lookup(table, unmasked, mask);	\
		     e != NULL; e = NULL)

static u16 range_n_bytes(const struct ts_range *range)
{
	return range->end - range->start;
}

static void tss_mask_key(void *dst, const void *src, const void *mask,
			 const struct ts_range *range)
{
	int start = range->start;
	int len = range_n_bytes(range);
	const long *m = (const long *)((const u8 *)mask + start);
	const long *s = (const long *)((const u8 *)src + start);
	long *d = (long *)((u8 *)dst + start);
	int i;

	for (i = 0; i < len; i += sizeof(long))
		*d++ = *s++ & *m++;
}

void ovs_flow_mask_key(struct sw_flow_key *dst, const struct sw_flow_key *src,
		       bool full, const struct sw_flow_mask *mask)
{
	struct ts_range range;

	/* If 'full' is true then all of 'dst' is fully initialized. Otherwise,
	 * if 'full' is false the memory outside of the 'mask->range' is left
	 * uninitialized. This can be used as an optimization when further
	 * operations on 'dst' only use contents within 'mask->range'.
	 */
	range.start = full ? 0 : mask->head.range.start;
	range.end = full ? mask->head.key_len
			 : mask->head.range.end;
	return tss_mask_key(dst, src, &mask->head.key, &range);
}

struct sw_flow *ovs_flow_alloc(void)
{
	struct sw_flow *flow;
	struct flow_stats *stats;

	flow = kmem_cache_zalloc(flow_cache, GFP_KERNEL);
	if (!flow)
		return ERR_PTR(-ENOMEM);

	flow->stats_last_writer = -1;
	flow->head.key = &flow->key;

	/* Initialize the default stat node. */
	stats = kmem_cache_alloc_node(flow_stats_cache,
				      GFP_KERNEL | __GFP_ZERO,
				      node_online(0) ? 0 : NUMA_NO_NODE);
	if (!stats)
		goto err;

	spin_lock_init(&stats->lock);

	RCU_INIT_POINTER(flow->stats[0], stats);

	return flow;
err:
	kmem_cache_free(flow_cache, flow);
	return ERR_PTR(-ENOMEM);
}

static int ts_table_count(const struct ts_table *table)
{
	return table->count;
}

int ovs_flow_tbl_count(const struct flow_table *table)
{
	return ts_table_count(&table->tt);
}

static struct flex_array *alloc_buckets(unsigned int n_buckets)
{
	struct flex_array *buckets;
	int i, err;

	buckets = flex_array_alloc(sizeof(struct hlist_head),
				   n_buckets, GFP_KERNEL);
	if (!buckets)
		return NULL;

	err = flex_array_prealloc(buckets, 0, n_buckets, GFP_KERNEL);
	if (err) {
		flex_array_free(buckets);
		return NULL;
	}

	for (i = 0; i < n_buckets; i++)
		INIT_HLIST_HEAD((struct hlist_head *)
					flex_array_get(buckets, i));

	return buckets;
}

static void flow_free(struct sw_flow *flow)
{
	int cpu;

	if (ovs_identifier_is_key(&flow->id))
		kfree(flow->id.unmasked_key);
	if (flow->sf_acts)
		ovs_nla_free_flow_actions((struct sw_flow_actions __force *)flow->sf_acts);
	/* We open code this to make sure cpu 0 is always considered */
	for (cpu = 0; cpu < nr_cpu_ids; cpu = cpumask_next(cpu, cpu_possible_mask))
		if (flow->stats[cpu])
			kmem_cache_free(flow_stats_cache,
					(struct flow_stats __force *)flow->stats[cpu]);
	kmem_cache_free(flow_cache, flow);
}

static void rcu_free_flow_callback(struct rcu_head *rcu)
{
	struct ts_element *e = container_of(rcu, struct ts_element, rcu);
	struct sw_flow *flow = container_of(e, struct sw_flow, head);

	flow_free(flow);
}

void ovs_flow_free(struct sw_flow *flow, bool deferred)
{
	if (!flow)
		return;

	if (deferred)
		call_rcu(&flow->head.rcu, rcu_free_flow_callback);
	else
		flow_free(flow);
}

static void free_buckets(struct flex_array *buckets)
{
	flex_array_free(buckets);
}


static void __table_instance_destroy(struct table_instance *ti)
{
	free_buckets(ti->buckets);
	kfree(ti);
}

static struct table_instance *table_instance_alloc(int n_elements)
{
	struct table_instance *ti = kmalloc(sizeof(*ti), GFP_KERNEL);

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

static int ts_table_init(struct ts_table *table, size_t key_len)
{
	struct table_instance *ti;

	ti = table_instance_alloc(TBL_MIN_BUCKETS);
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

	return 0;

free_ti:
	__table_instance_destroy(ti);
	return -ENOMEM;
}

static int ts_table_flush(struct ts_table *table)
{
	struct table_instance *old_ti = ovsl_dereference(table->ti);
	int err;

	err = ts_table_init(table, table->key_len);
	if (err)
		return err;

	if (old_ti)
		table_instance_destroy_and_free(old_ti, true);

	return 0;
}

int ovs_flow_tbl_init(struct flow_table *table)
{
	struct table_instance *ufid_ti;
	int err;

	ufid_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!ufid_ti)
		return -ENOMEM;

	err = ts_table_init(&table->tt, sizeof(struct sw_flow));
	if (err)
		goto free_ti;

	rcu_assign_pointer(table->ufid_ti, ufid_ti);
	table->ufid_count = 0;
	return 0;

free_ti:
	__table_instance_destroy(ufid_ti);
	return err;
}

static void flow_tbl_destroy_rcu_cb(struct rcu_head *rcu)
{
	struct table_instance *ti = container_of(rcu, struct table_instance, rcu);

	__table_instance_destroy(ti);
}

static void table_instance_destroy(struct table_instance *ti, bool deferred)
{
	if (deferred)
		call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
	else
		__table_instance_destroy(ti);
}

/* This should be called before table_instance_destroy_and_free(), to ensure
 * that the flows aren't freed before being removed from the UFID table
 * instance.
 */
static void ufid_table_destroy(struct table_instance *ti, bool deferred)
{
	int i;

	for (i = 0; i < ti->n_buckets; i++) {
		struct hlist_head *head = flex_array_get(ti->buckets, i);
		int ver = ti->node_ver;
		struct hlist_node *n;
		struct sw_flow *flow;

		hlist_for_each_entry_safe(flow, n, head, ufid_table.node[ver])
			if (likely(ovs_identifier_is_ufid(&flow->id)))
				hlist_del_rcu(&flow->ufid_table.node[ver]);
	}

	table_instance_destroy(ti, deferred);
}

static void table_instance_destroy_and_free(struct table_instance *ti,
					    bool deferred)
{
	int i;

	if (!ti)
		return;

	for (i = 0; i < ti->n_buckets; i++) {
		struct hlist_head *head = flex_array_get(ti->buckets, i);
		struct ts_element *e;
		struct hlist_node *n;
		int ver = ti->node_ver;

		hlist_for_each_entry_safe(e, n, head, node[ver]) {
			hlist_del_rcu(&e->node[ver]);
			ovs_flow_free(container_of(e, struct sw_flow, head),
				      deferred);
		}
	}

	table_instance_destroy(ti, deferred);
}

/* No need for locking this function is called from RCU callback or
 * error path.
 */
void ovs_flow_tbl_destroy(struct flow_table *table)
{
	struct table_instance *ti = rcu_dereference_raw(table->tt.ti);
	struct table_instance *ufid_ti = rcu_dereference_raw(table->ufid_ti);

	if (ti) {
		ufid_table_destroy(ufid_ti, false);
		table_instance_destroy_and_free(ti, false);
	}
}

static struct ts_element *ts_table_dump_next(struct table_instance *ti,
					     u32 *bucket, u32 *last)
{
	struct ts_element *e;
	struct hlist_head *head;
	int ver;
	int i;

	ver = ti->node_ver;
	while (*bucket < ti->n_buckets) {
		i = 0;
		head = flex_array_get(ti->buckets, *bucket);
		hlist_for_each_entry_rcu(e, head, node[ver]) {
			if (i < *last) {
				i++;
				continue;
			}
			*last = i + 1;
			return e;
		}
		(*bucket)++;
		*last = 0;
	}

	return NULL;
}

struct sw_flow *ovs_flow_tbl_dump_next(struct table_instance *ti,
				       u32 *bucket, u32 *last)
{
	struct ts_element *e = ts_table_dump_next(ti, bucket, last);

	return container_of(e, struct sw_flow, head);
}

static struct hlist_head *find_bucket(struct table_instance *ti, u32 hash)
{
	hash = jhash_1word(hash, ti->hash_seed);
	return flex_array_get(ti->buckets,
				(hash & (ti->n_buckets - 1)));
}

static void ts_table_instance_insert(struct table_instance *ti,
				     struct ts_element *e)
{
	struct hlist_head *head;

	head = find_bucket(ti, e->hash);
	hlist_add_head_rcu(&e->node[ti->node_ver], head);
}

static void ufid_table_instance_insert(struct table_instance *ti,
				       struct sw_flow *flow)
{
	struct hlist_head *head;

	head = find_bucket(ti, flow->ufid_table.hash);
	hlist_add_head_rcu(&flow->ufid_table.node[ti->node_ver], head);
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
			ts_table_instance_insert(new, e);
	}
}

static void ufid_table_copy_flows(struct table_instance *old,
				  struct table_instance *new)
{
	int old_ver;
	int i;

	old_ver = old->node_ver;
	new->node_ver = !old_ver;

	/* Insert in new table. */
	for (i = 0; i < old->n_buckets; i++) {
		struct sw_flow *flow;
		struct hlist_head *head;

		head = flex_array_get(old->buckets, i);
		hlist_for_each_entry(flow, head, ufid_table.node[old_ver])
			ufid_table_instance_insert(new, flow);
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

static struct table_instance *ufid_table_rehash(struct table_instance *ti,
						int n_buckets)
{
	struct table_instance *new_ti;

	new_ti = table_instance_alloc(n_buckets);
	if (!new_ti)
		return NULL;

	ufid_table_copy_flows(ti, new_ti);

	return new_ti;
}

static struct table_instance *ufid_table_expand(struct table_instance *ti)
{
	return ufid_table_rehash(ti, ti->n_buckets * 2);
}

int ovs_flow_tbl_flush(struct flow_table *flow_table)
{
	struct table_instance *old_ufid_ti, *new_ufid_ti;
	int err;

	new_ufid_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!new_ufid_ti)
		return -ENOMEM;

	err = ts_table_flush(&flow_table->tt);
	if (err)
		goto err_free_ti;

	old_ufid_ti = ovsl_dereference(flow_table->ufid_ti);
	rcu_assign_pointer(flow_table->ufid_ti, new_ufid_ti);
	flow_table->ufid_count = 0;
	if (old_ufid_ti)
		ufid_table_destroy(old_ufid_ti, true);

	return 0;

err_free_ti:
	__table_instance_destroy(new_ufid_ti);
	return -ENOMEM;
}

static u32 flow_hash(const void *key, const struct ts_range *range)
{
	int key_start = range->start;
	int key_end = range->end;
	const u32 *hash_key = (const u32 *)((const u8 *)key + key_start);
	int hash_u32s = (key_end - key_start) >> 2;

	/* Make sure number of hash bytes are multiple of u32. */
	BUILD_BUG_ON(sizeof(long) % sizeof(u32));

	return jhash2(hash_key, hash_u32s, 0);
}

static int flow_key_start(const struct sw_flow_key *key)
{
	if (key->tun_proto)
		return 0;
	else
		return rounddown(offsetof(struct sw_flow_key, phy),
					  sizeof(long));
}

static bool cmp_key(const void *key1, const void *key2,
		    const struct ts_range *range)
{
	const long *cp1 = (const long *)((const u8 *)key1 + range->start);
	const long *cp2 = (const long *)((const u8 *)key2 + range->start);
	long diffs = 0;
	int i;

	for (i = range->start; i < range->end;  i += sizeof(long))
		diffs |= *cp1++ ^ *cp2++;

	return diffs == 0;
}

static bool flow_cmp_masked_key(const struct sw_flow *flow,
				const struct sw_flow_key *key,
				const struct sw_flow_key_range *range)
{
	return cmp_key(&flow->key, key, range);
}

static bool ovs_flow_cmp_unmasked_key(const struct sw_flow *flow,
				      const struct sw_flow_match *match)
{
	struct sw_flow_key *key = match->key;
	struct ts_range range = {
		.start = flow_key_start(key),
		.end = match->range.end,
	};

	BUG_ON(ovs_identifier_is_ufid(&flow->id));
	return cmp_key(flow->id.unmasked_key, key, &range);
}

static uint8_t *get_pcpu_key(struct ts_table *table)
{
	int cpu = get_cpu();
	uint8_t *key;

	key = &table->masked_key[cpu * table->key_len];
	put_cpu();
	return key;
}

static struct ts_element *ts_masked_lookup(struct ts_table *table,
					   const void *unmasked,
					   const struct ts_mask *mask)
{
	struct table_instance *ti = rcu_dereference_ovsl(table->ti);
	struct ts_element *element;
	struct hlist_head *head;
	uint8_t *masked_key;
	u32 hash;

	masked_key = get_pcpu_key(table);
	tss_mask_key(masked_key, unmasked, &mask->key, &mask->range);
	hash = flow_hash(masked_key, &mask->range);
	head = find_bucket(ti, hash);
	hlist_for_each_entry_rcu(element, head, node[ti->node_ver]) {
		if (element->mask == mask && element->hash == hash &&
		    cmp_key(element->key, masked_key, &mask->range))
			return element;
	}
	return NULL;
}

static struct ts_element *ts_lookup_stats(struct ts_table *table,
					  const void *key, u32 *n_mask_hit)
{
	const struct ts_mask *mask;
	struct ts_element *e;

	*n_mask_hit = 0;
	list_for_each_entry_rcu(mask, &table->mask_list, list) {
		(*n_mask_hit)++;
		e = ts_masked_lookup(table, key, mask);
		if (e)  /* Found */
			return e;
	}
	return NULL;
}

struct sw_flow *ovs_flow_tbl_lookup_stats(struct flow_table *tbl,
				    const struct sw_flow_key *key,
				    u32 *n_mask_hit)
{
	struct ts_element *e = ts_lookup_stats(&tbl->tt, key, n_mask_hit);
	return container_of(e, struct sw_flow, head);
}

struct sw_flow *ovs_flow_tbl_lookup(struct flow_table *tbl,
				    const struct sw_flow_key *key)
{
	u32 __always_unused n_mask_hit;

	return ovs_flow_tbl_lookup_stats(tbl, key, &n_mask_hit);
}

/* Must be called with OVS mutex held. */
struct sw_flow *ovs_flow_tbl_lookup_exact(struct flow_table *tbl,
					  const struct sw_flow_match *match)
{
	struct ts_element *e;

	tss_table_for_each_elem(e, &tbl->tt, match->key) {
		struct sw_flow *flow = container_of(e, struct sw_flow, head);

		if (flow && ovs_identifier_is_key(&flow->id) &&
		    ovs_flow_cmp_unmasked_key(flow, match))
			return flow;
	}
	return NULL;
}

static u32 ufid_hash(const struct sw_flow_id *sfid)
{
	return jhash(sfid->ufid, sfid->ufid_len, 0);
}

static bool ovs_flow_cmp_ufid(const struct sw_flow *flow,
			      const struct sw_flow_id *sfid)
{
	if (flow->id.ufid_len != sfid->ufid_len)
		return false;

	return !memcmp(flow->id.ufid, sfid->ufid, sfid->ufid_len);
}

bool ovs_flow_cmp(const struct sw_flow *flow, const struct sw_flow_match *match)
{
	if (ovs_identifier_is_ufid(&flow->id))
		return flow_cmp_masked_key(flow, match->key, &match->range);

	return ovs_flow_cmp_unmasked_key(flow, match);
}

struct sw_flow *ovs_flow_tbl_lookup_ufid(struct flow_table *tbl,
					 const struct sw_flow_id *ufid)
{
	struct table_instance *ti = rcu_dereference_ovsl(tbl->ufid_ti);
	struct sw_flow *flow;
	struct hlist_head *head;
	u32 hash;

	hash = ufid_hash(ufid);
	head = find_bucket(ti, hash);
	hlist_for_each_entry_rcu(flow, head, ufid_table.node[ti->node_ver]) {
		if (flow->ufid_table.hash == hash &&
		    ovs_flow_cmp_ufid(flow, ufid))
			return flow;
	}
	return NULL;
}

static int ts_table_n_masks(const struct ts_table *table)
{
	struct ts_mask *mask;
	int num = 0;

	list_for_each_entry(mask, &table->mask_list, list)
		num++;

	return num;
}

int ovs_flow_tbl_num_masks(const struct flow_table *table)
{
	return ts_table_n_masks(&table->tt);
}

static struct table_instance *table_instance_expand(struct table_instance *ti)
{
	return table_instance_rehash(ti, ti->n_buckets * 2);
}

/* Remove 'mask' from the mask list, if it is not needed any more. */
static void ts_mask_remove(struct ts_mask *mask)
{
	if (mask) {
		/* ovs-lock is required to protect mask-refcount and
		 * mask list.
		 */
		ASSERT_OVSL();
		BUG_ON(!mask->ref_count);
		mask->ref_count--;

		if (!mask->ref_count) {
			list_del_rcu(&mask->list);
			kfree_rcu(mask, rcu);
		}
	}
}

/* Must be called with OVS mutex held. */
static void ts_table_remove(struct ts_table *table, struct ts_element *e)
{
	struct table_instance *ti = ovsl_dereference(table->ti);

	BUG_ON(table->count == 0);
	hlist_del_rcu(&e->node[ti->node_ver]);
	table->count--;

	/* RCU delete the mask. 'flow->mask' is not NULLed, as it should be
	 * accessible as long as the RCU read lock is held.
	 */
	ts_mask_remove(e->mask);
}

/* Must be called with OVS mutex held. */
void ovs_flow_tbl_remove(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *ufid_ti = ovsl_dereference(table->ufid_ti);

	ts_table_remove(&table->tt, &flow->head);
	if (ovs_identifier_is_ufid(&flow->id)) {
		hlist_del_rcu(&flow->ufid_table.node[ufid_ti->node_ver]);
		table->ufid_count--;
	}
}

static struct ts_mask *mask_alloc(size_t key_len)
{
	size_t mask_size = sizeof(struct ts_mask) + key_len;
	struct ts_mask *mask;

	mask = kmalloc(mask_size, GFP_KERNEL);
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
		&& (memcmp(a_, b_, range_n_bytes(&a->range)) == 0);
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
		/* Allocate a new mask if none exsits. */
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

/* Must be called with OVS mutex held. */
static void ts_insert(struct ts_table *table, struct ts_element *e, void *key)
{
	struct table_instance *new_ti = NULL;
	struct table_instance *ti;

	e->hash = flow_hash(key, &e->mask->range);
	ti = ovsl_dereference(table->ti);
	ts_table_instance_insert(ti, e);
	table->count++;

	/* Expand table, if necessary, to make room. */
	if (table->count > ti->n_buckets)
		new_ti = table_instance_expand(ti);
	else if (time_after(jiffies, table->last_rehash + REHASH_INTERVAL))
		new_ti = table_instance_rehash(ti, ti->n_buckets);

	if (new_ti) {
		rcu_assign_pointer(table->ti, new_ti);
		call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
		table->last_rehash = jiffies;
	}
}

/* Must be called with OVS mutex held. */
static void flow_ufid_insert(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *new_ti = NULL;
	struct table_instance *ti;

	flow->ufid_table.hash = ufid_hash(&flow->id);
	ti = ovsl_dereference(table->ufid_ti);
	ufid_table_instance_insert(ti, flow);
	table->ufid_count++;

	/* Expand table, if necessary, to make room. */
	if (table->ufid_count > ti->n_buckets)
		new_ti = ufid_table_expand(ti);
	else if (time_after(jiffies, table->ufid_last_rehash + REHASH_INTERVAL))
		new_ti = ufid_table_rehash(ti, ti->n_buckets);

	if (new_ti) {
		rcu_assign_pointer(table->ufid_ti, new_ti);
		call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
		table->ufid_last_rehash = jiffies;
	}
}

/* Must be called with OVS mutex held. */
static int ts_table_insert(struct ts_table *table, struct ts_element *e,
			   const struct ts_mask *mask)
{
	int err;

	err = tuple_mask_insert(table, e, mask);
	if (err)
		return err;
	ts_insert(table, e, e->key);

	return 0;
}

/* Must be called with OVS mutex held. */
int ovs_flow_tbl_insert(struct flow_table *table, struct sw_flow *flow,
			const struct sw_flow_mask *mask)
{
	int err;

	err = ts_table_insert(&table->tt, &flow->head, &mask->head);
	if (err)
		return err;
	if (ovs_identifier_is_ufid(&flow->id))
		flow_ufid_insert(table, flow);

	return 0;
}

/* Initializes the flow module.
 * Returns zero if successful or a negative error code. */
int ovs_flow_init(void)
{
	BUILD_BUG_ON(__alignof__(struct sw_flow_key) % __alignof__(long));
	BUILD_BUG_ON(sizeof(struct sw_flow_key) % sizeof(long));

	flow_cache = kmem_cache_create("sw_flow", sizeof(struct sw_flow)
				       + (nr_cpu_ids
					  * sizeof(struct flow_stats *)),
				       0, 0, NULL);
	if (flow_cache == NULL)
		return -ENOMEM;

	flow_stats_cache
		= kmem_cache_create("sw_flow_stats", sizeof(struct flow_stats),
				    0, SLAB_HWCACHE_ALIGN, NULL);
	if (flow_stats_cache == NULL) {
		kmem_cache_destroy(flow_cache);
		flow_cache = NULL;
		return -ENOMEM;
	}

	return 0;
}

/* Uninitializes the flow module. */
void ovs_flow_exit(void)
{
	kmem_cache_destroy(flow_stats_cache);
	kmem_cache_destroy(flow_cache);
}
