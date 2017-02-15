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
#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/tuple_table.h>
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

#define MAX_MASKS 32

struct bpf_tss_tab {
	struct bpf_map map;
	raw_spinlock_t lock;
	size_t tkey_len;
	struct ts_table table;
	struct tst_dump_ctx dump_ctx;
	bool dumping;
	struct ts_mask __percpu *pcpu_masks;
};

struct bpf_tss_elem {
	struct bpf_tss_tab *map;
	struct ts_element elem;
	u8 value[0];
};

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

	kfree(bte->elem.key);
	kfree(bte);
}

static void bte_free_rcu(struct rcu_head *rcu)
{
	struct ts_element *elem = container_of(rcu, struct ts_element, rcu);

	bte_free(container_of(elem, struct bpf_tss_elem, elem));
}

static void bte_free_deferred(struct ts_element *elem)
{
	call_rcu(&elem->rcu, bte_free_rcu);
}

static struct bpf_map *btt_alloc(union bpf_attr *attr)
{
	u64 cost, node_cost, mask_cost;
	size_t tkey_len, pcpu_mask_len;
	struct bpf_tss_tab *btt;
	int entries;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return ERR_PTR(-EPERM);

	if (attr->map_flags & ~(BPF_F_NO_PREALLOC))
		/* reserved bits should not be used */
		return ERR_PTR(-EINVAL);

	if (!(attr->map_flags & BPF_F_NO_PREALLOC))
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

	pcpu_mask_len = sizeof(struct ts_mask) + tkey_len;
	btt->pcpu_masks = __alloc_percpu(pcpu_mask_len,
					 __alignof__(pcpu_mask_len));
	if (!btt->pcpu_masks) {
		err = -ENOMEM;
		goto free_btt;
	}

	entries = roundup_pow_of_two(attr->max_entries);
	entries = entries <= 1024 ? entries : 1024;
	err = tst_init(&btt->table, tkey_len, entries, bte_free_rcu,
		       GFP_ATOMIC);
	if (err)
		goto free_masks;

	btt->map.max_entries = entries;
	btt->map.map_flags = attr->map_flags;
	btt->map.map_type = attr->map_type;
	btt->map.key_size = attr->key_size;
	btt->map.value_size = attr->value_size;
	btt->tkey_len = tkey_len;
	raw_spin_lock_init(&btt->lock);

	return &btt->map;

free_masks:
	free_percpu(btt->pcpu_masks);
free_btt:
	kfree(btt);
	return ERR_PTR(err);
}

static void btt_free(struct bpf_map *map)
{
	struct bpf_tss_tab *btt = container_of(map, struct bpf_tss_tab, map);

	/* Ensure that element free has executed before flushing. */
	synchronize_rcu();
	tst_destroy(&btt->table);
	free_percpu(btt->pcpu_masks);
	kfree(btt);
}

static int btt_iterate(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_tss_tab *btt = container_of(map, struct bpf_tss_tab, map);
	unsigned long irq_flags;
	struct ts_element *e;
	int err = 0;

	WARN_ON_ONCE(!rcu_read_lock_held());

	raw_spin_lock_irqsave(&btt->lock, irq_flags);
	if (!btt->dumping) {
		memset(&btt->dump_ctx, 0, sizeof btt->dump_ctx);
		btt->dumping = true;
	}
	e = tst_dump_next(&btt->table, &btt->dump_ctx);
	if (!e) {
		btt->dumping = false;
		err = -ENOENT;
	}
	raw_spin_unlock_irqrestore(&btt->lock, irq_flags);

	if (!err) {
		struct bpf_tss_elem *bte;

		bte = container_of(e, struct bpf_tss_elem, elem);
		memcpy(next_key, &bte->value, btt->tkey_len);
	}
	return err;
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

static struct ts_mask *tmask_get(struct bpf_tss_tab *btt, const void *mask)
{
	struct ts_mask *tmask = this_cpu_ptr(btt->pcpu_masks);

	memcpy(&tmask->key, mask, btt->tkey_len);
	tmask->key_len = btt->tkey_len;
	tmask->range.start = 0;
	tmask->range.end = btt->tkey_len;

	return tmask;
}

static int btt_update(struct bpf_map *map, void *key, void *value, u64 flags)
{
	struct bpf_tss_tab *btt = container_of(map, struct bpf_tss_tab, map);
	const void *mask = (u8 *)key + btt->tkey_len;
	unsigned long irq_flags;
	struct ts_mask *tmask;
	struct ts_element *e;
	int err = 0;

	if (unlikely(flags & ~(BPF_NOEXIST | BPF_EXIST)))
		return -EOPNOTSUPP;

	tmask = tmask_get(btt, mask);
	raw_spin_lock_irqsave(&btt->lock, irq_flags);

	e = tst_lookup(&btt->table, key);
	if (e) {
		struct ts_range range = {
			.start = 0,
			.end = btt->tkey_len,
		};

		/* First, check that the masks are the same. */
		if (!ts_compare(&e->mask->key, mask, &range)) {
			e = NULL;
		} else if (flags & BPF_NOEXIST) {
			err = -EEXIST;
			goto unlock;
		}
	}

	if (e) {
		struct bpf_tss_elem *old_elem;

		old_elem = container_of(e, struct bpf_tss_elem, elem);
		memcpy(&old_elem->value, value, btt->tkey_len);
	} else {
		struct bpf_tss_elem *bte;

		if (flags & BPF_EXIST) {
			err = -ENOENT;
			goto unlock;
		}
		if (btt->table.count > btt->map.max_entries) {
			err = -E2BIG;
			goto unlock;
		}

		if (tst_n_masks(&btt->table) >= MAX_MASKS &&
		    !tst_lookup_mask(&btt->table, mask)) {
			err = -ENOMEM;
			goto unlock;
		}

		bte = bte_alloc(key, btt->tkey_len, value, btt->map.value_size);
		if (!bte) {
			err = -ENOMEM;
			goto unlock;
		}

		err = tst_insert(&btt->table, &bte->elem, tmask);
		if (err) {
			bte_free(bte);
			goto unlock;
		}
	}

unlock:
	raw_spin_unlock_irqrestore(&btt->lock, irq_flags);
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
	bte_free_deferred(e);

unlock:
	raw_spin_unlock_irqrestore(&btt->lock, irq_flags);
	return err;
}

const struct bpf_map_ops btt_map_ops = {
	.map_alloc = btt_alloc,
	.map_free = btt_free,
	.map_get_next_key = btt_iterate,
	.map_lookup_elem = btt_lookup,
	.map_update_elem = btt_update,
	.map_delete_elem = btt_delete,
};
