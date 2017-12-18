/* Copyright (c) 2016 PLUMgrid
 * Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_helpers.h"

# define printk(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})

struct bpf_map_def SEC("maps") rxcnt = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = SK_STATE_MAX,
};

static int parse_ipv4(void *data, u64 nh_off, void *data_end,
		      struct bpf_sock_tuple *tuple)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;
	tuple->saddr.ipv4 = iph->saddr;
	tuple->daddr.ipv4 = iph->daddr;
	return iph->protocol;
}

static int parse_ipv6(void *data, u64 nh_off, void *data_end,
		      struct bpf_sock_tuple *tuple)
{
	struct ipv6hdr *ip6h = data + nh_off;

	if (ip6h + 1 > data_end)
		return 0;
	*((struct in6_addr *)&tuple->saddr.ipv6) = ip6h->saddr;
	*((struct in6_addr *)&tuple->daddr.ipv6) = ip6h->daddr;
	return ip6h->nexthdr;
}

static void parse_udp(void *data, u64 nh_off, void *data_end,
		      struct bpf_sock_tuple *tuple)
{
	struct udphdr *udph = data + nh_off;

	if (udph + 1 > data_end)
		return;
	tuple->sport = udph->source;
	tuple->dport = udph->dest;
}

static void parse_tcp(void *data, u64 nh_off, void *data_end,
		      struct bpf_sock_tuple *tuple)
{
	struct tcphdr *tcph = data + nh_off;

	if (tcph + 1 > data_end)
		return;
	tuple->sport = tcph->source;
	tuple->dport = tcph->dest;
}

static inline int parse_tuple(struct xdp_md *ctx, struct bpf_sock_tuple *tuple) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u16 sport, dport;
	u16 h_proto;
	u64 nh_off;
	u32 ipproto;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return -1;

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return -2;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return -3;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto == htons(ETH_P_IP)) {
		tuple->family = AF_INET;
		ipproto = parse_ipv4(data, nh_off, data_end, tuple);
		nh_off += sizeof(struct iphdr);
	} else if (h_proto == htons(ETH_P_IPV6)) {
		tuple->family = AF_INET6;
		ipproto = parse_ipv6(data, nh_off, data_end, tuple);
		nh_off += sizeof(struct ipv6hdr);
	} else {
		return -4;
	}
	if (!ipproto || (data + nh_off > data_end))
			return -5;

	tuple->proto = ipproto;
	if (ipproto == IPPROTO_TCP) {
		parse_tcp(data, nh_off, data_end, tuple);
	} else if (ipproto == IPPROTO_UDP) {
		parse_udp(data, nh_off, data_end, tuple);
	} else {
		return ipproto;
	}

	return 0;
}

SEC("xdp1")
int xdp_prog1(struct xdp_md *ctx)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock_info sockinfo;
	int rc = XDP_DROP;
	long *value;
	int err;

	printk("parse_tuple() start\n");
	err = parse_tuple(ctx, &tuple);
	if (err) {
		printk("parse_tuple() fail (family=%d): %d\n", tuple.family, err);
		if (!tuple.family)
			return XDP_PASS;
		return rc;
	}
	err = bpf_sk_lookup(&tuple, sizeof tuple, &sockinfo, sizeof sockinfo,
			    BPF_F_SEARCH_ALL_NS);
	if (err == -ENOENT) {
		printk("sk_lookup() failed: no such element\n");
		return rc;
	} else if (err) {
		printk("sk_lookup() %d, %d\n", err, tuple.proto);
		return rc;
	}

	printk("sk_lookup() success: %d\n", sockinfo.state);
	value = bpf_map_lookup_elem(&rxcnt, &sockinfo.state);
	if (value)
		*value += 1;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
