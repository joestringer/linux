/*
 * Copyright (c) 2017 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <linux/bpf.h>
#include <linux/filter.h>
//#include <linux/kernel.h>
//#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/tss_table.h>
#include <linux/types.h>

/*
 * lib/ts_table.c doesn't provide locking for us, also it differentiates
 * between lookup keys and masks. This file deals with these differences and
 * maps them to the BPF map API.
 *
 * This is a tuple-space table that provides no ordering between overlapping
 * elements; if the user cares about which value is returned, they must ensure
 * not to insert keys with overlapping masks.
 */

/* XXX: Give this a knob for runtime reconfiguration. */
#define MAX_MASKS 128

struct bpf_tss_tab {
	struct bpf_map map;
	raw_spinlock_t lock;		/* XXX lockdep */
	size_t tkey_len;
	struct ts_table table;
};

struct bpf_tss_elem {
	struct bpf_tss_tab *map;
	struct ts_element elem;
	u8 value[0];
};

static bool cmp_elem(const void *key1, const void *key2,
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

static struct bpf_tss_elem *bte_alloc(const void *key, size_t key_size,
				      const void *value, size_t value_size)
{
	struct bpf_tss_elem *bte;

	bte = kzalloc(sizeof(*bte) + value_size, GFP_ATOMIC);
	if (!bte)
		return NULL;

	bte->elem.key = kmemdup(key, key_size, GFP_ATOMIC);
	if (!bte->elem.key)
		goto out;

	memcpy(&bte->value, value, value_size);
	return bte;
out:
	kfree(bte);
	return NULL;
}

static void bte_free(struct bpf_tss_elem *bte)
{
	if (!bte)
		return;

	/* XXX: free bte->elem.mask ??? */
	kfree(bte->elem.key);
	kfree(bte);
}

static void bte_free_rcu(struct rcu_head *rcu)
{
	struct ts_element *elem = container_of(rcu, struct ts_element, rcu);

	bte_free(container_of(elem, struct bpf_tss_elem, elem));
}

static void free_elem(struct ts_element *elem, bool deferred)
{
	if (deferred)
		call_rcu(&elem->rcu, bte_free_rcu);
	else
		bte_free(container_of(elem, struct bpf_tss_elem, elem));
}

static struct bpf_map *btt_alloc(union bpf_attr *attr)
{
	u64 cost, node_cost, mask_cost;
	struct bpf_tss_tab *btt;
	size_t tkey_len;
	int entries;
	int err;

	/* XXX: CAP_SYS_ADMIN ? */

	if (attr->map_flags & ~(BPF_F_NO_PREALLOC))
		/* reserved bits should not be used */
		return ERR_PTR(-EINVAL);

	if (!(attr->map_flags & BPF_F_NO_PREALLOC))
		/* XXX: Support prealloc */
		return ERR_PTR(-EINVAL);

	if (!attr->max_entries || !attr->key_size || !attr->value_size)
		return ERR_PTR(-EINVAL);

	/*
	 * The key in the map attributes is used to represent the tuple in
	 * tuple space search. In the implementation, we further split this
	 * into two equal-sized tuple components: The first half represents the
	 * key that is used to match in the hash tables, while the second half
	 * represents the mask of relevant bits that must match for a lookup to
	 * be successful.
	 */
	if (attr->key_size % 2)
		return ERR_PTR(-EINVAL);
	tkey_len = attr->key_size / 2;

	if (attr->key_size > MAX_BPF_STACK ||
	    attr->value_size >= KMALLOC_MAX_SIZE - MAX_BPF_STACK
				- sizeof(struct bpf_tss_elem))
		return ERR_PTR(-E2BIG);

	/*
	 * Each node has a key and value, and a pointer to a mask; multiple
	 * nodes may share a mask and there are expected to be MAX_MASKS or
	 * less of them.
	 */
	node_cost = sizeof(struct bpf_tss_elem) + tkey_len + attr->value_size;
	mask_cost = tkey_len * MAX_MASKS;
	cost = (u64)attr->max_entries * node_cost + mask_cost + sizeof(*btt);
	if (cost >= U32_MAX - PAGE_SIZE)
		return ERR_PTR(-E2BIG);

	btt = kzalloc(sizeof(*btt), GFP_USER);
	if (!btt)
		return ERR_PTR(-ENOMEM);

	entries = roundup_pow_of_two(attr->max_entries);
	err = tst_init(&btt->table, tkey_len, cmp_elem, free_elem,
		       entries <= 1024 ? entries : 1024);
	if (err)
		goto free_btt;

	btt->map.max_entries = entries;
	btt->map.map_flags = attr->map_flags;
	btt->map.map_type = attr->map_type;
	btt->map.key_size = attr->key_size;
	btt->map.value_size = attr->value_size;
	btt->tkey_len = tkey_len;
	raw_spin_lock_init(&btt->lock);

	return &btt->map;

free_btt:
	kfree(btt);
	return ERR_PTR(err);
}

static void btt_free(struct bpf_map *map)
{
	struct bpf_tss_tab *btt = container_of(map, struct bpf_tss_tab, map);

	/* XXX: Wait for RCU */
	tst_flush(&btt->table);
	kfree(btt);
}

static int btt_iterate(struct bpf_map *map, void *key, void *next_key)
{
	//struct bpf_tss_tab *btt = container_of(map, struct bpf_tss_tab, map);
	/* XXX */

	return -ENOTSUPP;
}

/* Must hold RCU read lock */
static void *btt_lookup(struct bpf_map *map, void *key)
{
	struct bpf_tss_tab *btt = container_of(map, struct bpf_tss_tab, map);
	struct bpf_tss_elem *bte;
	struct ts_element *e;

	e = tst_lookup(&btt->table, key);
	if (!e)
		return NULL;

	bte = container_of(e, struct bpf_tss_elem, elem);
	return &bte->value;
}

static struct ts_mask *tmask_alloc(const void *mask, size_t len)
{
	struct ts_mask *tmask;

	/* XXX: Bound the mask cost */
	tmask = kmalloc(sizeof(struct ts_mask) + len, GFP_ATOMIC);
	if (!tmask)
		return NULL;

	memcpy(&tmask->key, mask, len);
	tmask->key_len = len;
	tmask->range.start = 0;
	tmask->range.end = len;

	return tmask;
}

static int btt_update(struct bpf_map *map, void *key, void *value, u64 flags)
{
	struct bpf_tss_tab *btt = container_of(map, struct bpf_tss_tab, map);
	const void *mask = (u8 *)key + btt->tkey_len;
	struct bpf_tss_elem *bte;
	unsigned long irq_flags;
	struct ts_mask *tmask;
	struct ts_element *e;
	int err = 0;

	/* XXX: If we're really getting nowhere, try return immediately. */
	/* XXX: Then try bte_alloc() / bte_free(). Slowly expand until
	 *	it's obvious why there is small memory leak in BPF_EXIST and
	 *	large memory leak in BPF_NOEXIST. */

	if (unlikely(flags & ~(BPF_NOEXIST | BPF_EXIST)))
		return -EINVAL;

	/* Perform allocations before locking to minimize critical section. */
	bte = bte_alloc(key, btt->tkey_len, value, btt->map.value_size);
	if (!bte)
		return -ENOMEM;
	/* XXX: Insertion shouldn't need explicit separate mask.  */
	tmask = tmask_alloc(mask, btt->tkey_len);
	if (!tmask) {
		 err = -ENOMEM;
		 goto out;
	}

	raw_spin_lock_irqsave(&btt->lock, irq_flags);

	/* XXX: Double check logic after refactor */
	e = tst_lookup(&btt->table, key);
	if (e) {
		struct ts_range range = {
			.start = 0,
			.end = btt->tkey_len,
		};

		/* First, check that the masks are the same. */
		if (!cmp_elem(&e->mask->key, mask, &range)) {
			e = NULL;
		} else if (flags & BPF_NOEXIST) {
			err = -EEXIST;
			goto unlock;
		}
	}
	if (!e && (flags & BPF_EXIST)) {
		err = -ENOENT;
		goto unlock;
	}

	if (btt->table.count > btt->map.max_entries) {
		/* XXX: Replace */
		err = -E2BIG;
		goto unlock;
	}

	/* XXX: Prevent expansion beyond max_size (due to mask insert) */
	err = tst_insert(&btt->table, &bte->elem, tmask);
	if (err)
		goto unlock;
	bte = NULL;

	/* XXX: Just replace the value in the existing element? */
	if (e) {
		tst_remove(&btt->table, e);
		free_elem(e, true);
	}

unlock:
	raw_spin_unlock_irqrestore(&btt->lock, irq_flags);
out:
	kfree(tmask);
	bte_free(bte);
	return err;
}

static int btt_delete(struct bpf_map *map, void *key)
{
	struct bpf_tss_tab *btt = container_of(map, struct bpf_tss_tab, map);
	unsigned long irq_flags;
	struct ts_element *e;
	int err = -ENOENT;

	raw_spin_lock_irqsave(&btt->lock, irq_flags);

	e = tst_lookup(&btt->table, key);
	if (!e)
		goto unlock;

	tst_remove(&btt->table, e);
	free_elem(e, true);

unlock:
	raw_spin_unlock_irqrestore(&btt->lock, irq_flags);
	return err;
}

static const struct bpf_map_ops btt_ops = {
	.map_alloc = btt_alloc,
	.map_free = btt_free,
	.map_get_next_key = btt_iterate,
	.map_lookup_elem = btt_lookup,
	.map_update_elem = btt_update,
	.map_delete_elem = btt_delete,
};

static struct bpf_map_type_list btt_type __read_mostly = {
	.ops = &btt_ops,
	.type = BPF_MAP_TYPE_TUPLE_HASH,
};

static int __init register_btt_map(void)
{
	bpf_register_map_type(&btt_type);
	return 0;
}
late_initcall(register_btt_map);
