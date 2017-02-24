/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "foo"
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <uapi/linux/bpf.h>
#include <net/ip.h>
#include "bpf_helpers.h"

#define DEFAULT_PKTGEN_UDP_PORT 9
//#define MAX_ENTRIES 1024
#define MAX_ENTRIES 0x10000	/* 64K */
//#define MAX_ENTRIES 0x10000000	/* Too damn big! */

# define printk(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})


/* copy of 'struct ethhdr' without __packed */
struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};

struct tuple {
	struct eth_hdr key;
	struct eth_hdr mask;
};

struct bpf_map_def SEC("maps") tuple_table = {
	.type = BPF_MAP_TYPE_TUPLE_HASH,
	.key_size = sizeof(struct tuple),
	.value_size = sizeof(long),
	.max_entries = MAX_ENTRIES,
	.map_flags = BPF_F_NO_PREALLOC,
};

SEC("tuple")
int handle_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	struct eth_hdr *eth = data;
	struct iphdr *iph = data + sizeof(*eth);
	struct udphdr *udp = data + sizeof(*eth) + sizeof(*iph);
	void *data_end = (void *)(long)skb->data_end;
	struct tuple tuple;
	long value = 0;
	int err;

	/* single length check */
	if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp) > data_end)
		return 0;

	tuple.key = *eth;
	//memset(&tuple.key, 0, sizeof(tuple.key));
	memset(&tuple.mask, 0, sizeof(tuple.mask));
	tuple.mask.h_proto = 0xffff;
	err = bpf_map_update_elem(&tuple_table, &tuple, &value, BPF_NOEXIST);
	if (err)
		printk("updating elem: %d\n", err);

	if (eth->h_proto != htons(ETH_P_IP))
		return 0;
	if (iph->protocol != IPPROTO_UDP || iph->ihl != 5)
		return 0;
	if (ip_is_fragment(iph))
		return 0;

	if (udp->dest == htons(DEFAULT_PKTGEN_UDP_PORT))
		if (bpf_map_lookup_elem(&tuple_table, &tuple) == NULL)
			return TC_ACT_SHOT;
	return 0;
}
char _license[] SEC("license") = "GPL";
