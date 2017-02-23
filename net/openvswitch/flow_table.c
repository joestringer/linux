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

static bool cmp_key(const void *k1, const void *k2, const struct ts_range *);

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
	tst_mask_key(dst, src, &mask->head.key, &range);
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

int ovs_flow_tbl_count(const struct flow_table *table)
{
	return table->tt.count;
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

static void ts_flow_free(struct ts_element *elem, bool deferred)
{
	struct sw_flow *flow;

	if (!elem)
		return;

	flow = container_of(elem, struct sw_flow, head);
	ovs_flow_free(flow, deferred);
}

int ovs_flow_tbl_init(struct flow_table *table)
{
	struct table_instance *ufid_ti;
	int err;

	ufid_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!ufid_ti)
		return -ENOMEM;

	err = tst_init(&table->tt, sizeof(struct sw_flow), cmp_key,
		       ts_flow_free, TBL_MIN_BUCKETS);
	if (err)
		goto free_ti;

	rcu_assign_pointer(table->ufid_ti, ufid_ti);
	table->ufid_count = 0;
	return 0;

free_ti:
	__table_instance_destroy(ufid_ti);
	return err;
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

/* No need for locking this function is called from RCU callback or
 * error path.
 */
void ovs_flow_tbl_destroy(struct flow_table *table)
{
	struct table_instance *ti = rcu_dereference_raw(table->tt.ti);
	struct table_instance *ufid_ti = rcu_dereference_raw(table->ufid_ti);

	if (ti) {
		ufid_table_destroy(ufid_ti, false);
		table_instance_destroy_and_free(ti, false, table->tt.free);
	}
}

struct sw_flow *ovs_flow_tbl_dump_next(struct flow_table *table,
				       struct tst_dump_ctx *ctx)
{
	struct ts_element *e;

	if (!ctx->ti)
		ctx->ti = rcu_dereference(table->tt.ti);
	e = tst_dump_next(ctx);
	return container_of(e, struct sw_flow, head);
}

static struct hlist_head *find_bucket(struct table_instance *ti, u32 hash)
{
	hash = jhash_1word(hash, ti->hash_seed);
	return flex_array_get(ti->buckets,
				(hash & (ti->n_buckets - 1)));
}

static void ufid_table_instance_insert(struct table_instance *ti,
				       struct sw_flow *flow)
{
	struct hlist_head *head;

	head = find_bucket(ti, flow->ufid_table.hash);
	hlist_add_head_rcu(&flow->ufid_table.node[ti->node_ver], head);
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

	err = tst_flush(&flow_table->tt);
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

struct sw_flow *ovs_flow_tbl_lookup_stats(struct flow_table *tbl,
				    const struct sw_flow_key *key,
				    u32 *n_mask_hit)
{
	struct ts_element *e = tst_lookup_stats(&tbl->tt, key, n_mask_hit);
	return container_of(e, struct sw_flow, head);
}

struct sw_flow *ovs_flow_tbl_lookup(struct flow_table *tbl,
				    const struct sw_flow_key *key)
{
	struct ts_element *e = tst_lookup(&tbl->tt, key);
	return container_of(e, struct sw_flow, head);
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

int ovs_flow_tbl_num_masks(const struct flow_table *table)
{
	return tst_n_masks(&table->tt);
}

/* Must be called with OVS mutex held. */
void ovs_flow_tbl_remove(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *ufid_ti = ovsl_dereference(table->ufid_ti);

	tst_remove(&table->tt, &flow->head);
	if (ovs_identifier_is_ufid(&flow->id)) {
		hlist_del_rcu(&flow->ufid_table.node[ufid_ti->node_ver]);
		table->ufid_count--;
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
		call_rcu(&ti->rcu, table_instance_destroy_rcu_cb);
		table->ufid_last_rehash = jiffies;
	}
}

/* Must be called with OVS mutex held. */
int ovs_flow_tbl_insert(struct flow_table *table, struct sw_flow *flow,
			const struct sw_flow_mask *mask)
{
	int err;

	err = tst_insert(&table->tt, &flow->head, &mask->head);
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
