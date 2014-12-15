/*
 * Copyright (c) 2014 Nicira, Inc.
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

#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/flex_array.h>
#include <trace/bpf_trace.h>

#include "ovs-bpf.h"

struct flex_array *bpf_callbacks;

/* XXX */
#define MAX_FD 1024

static const struct bpf_func_proto *verifier_func(enum bpf_func_id func_id)
{
	printk("verifier_func(%d)\n", func_id);

	switch (func_id) {
	case BPF_FUNC_printk:
		return tracing_filter_func_proto(func_id);
	default:
		break;
	}
	return NULL;
}

/* return true if 'size' wide access at offset 'off' within bpf_context
 * with 'type' (read or write) is allowed
 */
static bool valid_context_access(int off, int size, enum bpf_access_type type)
{
	/* XXX: Sanity check */
	printk("valid_context_access(%d, %d, %d)\n", off, size, type);
	return true;
}

static struct bpf_verifier_ops ovs_ops = {
	.get_func_proto = verifier_func,
	.is_valid_access = valid_context_access,
};

static struct bpf_prog_type_list tl = {
	.ops = &ovs_ops,
	.type = BPF_PROG_TYPE_OPENVSWITCH,
};

int ovs_bpf_init(void)
{
	printk("ovs_bpf_init()\n");

	bpf_callbacks = flex_array_alloc(sizeof(struct bpf_prog *), MAX_FD,
					 GFP_KERNEL);
	if (!bpf_callbacks)
		return -ENOMEM;
	bpf_register_prog_type(&tl);

	return 0;
}

void ovs_bpf_exit(void)
{
	int i;

	for (i = 0; i < MAX_FD; i++) {
		struct bpf_prog *prog;

		prog = flex_array_get_ptr(bpf_callbacks, i);
		if (prog)
			bpf_prog_put(prog);
	}

	flex_array_free(bpf_callbacks);
	bpf_unregister_prog_type(&tl);
}

struct bpf_prog *ovs_bpf_lookup(u32 fd)
{
	struct bpf_prog *prog;

	/* Should resize rather than reject FDs > 1024. */
	if (fd > MAX_FD)
		return NULL;

	prog = flex_array_get_ptr(bpf_callbacks, fd);
	if (prog)
		return prog;

	prog = bpf_prog_get(fd);
	if (!prog)
		return NULL;

	if (prog->aux->prog_type != BPF_PROG_TYPE_OPENVSWITCH) {
		bpf_prog_put(prog);
		return NULL;
	}

	/* If this is the first time seeing this program, fetch a reference
	 * and hold on to it until ovs_bpf_exit().
	 */
	flex_array_put_ptr(bpf_callbacks, fd, prog, GFP_KERNEL);

	return prog;
}
