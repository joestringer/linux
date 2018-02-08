/* Copyright (c) 2016 PLUMgrid
 * Copyright (c) 2018 Covalent IO, Inc. http://covalent.io
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

#define printk(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})

#define NETNS_ID 1234

struct bpf_map_def SEC("maps") rxcnt = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = SS_DISCONNECTING + 1,
};

struct bpf_map_def SEC("maps") dropcnt = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 2,
};

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end,
			     struct bpf_sock_tuple *tuple)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;
	tuple->saddr.ipv4 = iph->saddr;
	tuple->daddr.ipv4 = iph->daddr;
	return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end,
			     struct bpf_sock_tuple *tuple)
{
	struct ipv6hdr *ip6h = data + nh_off;

	if (ip6h + 1 > data_end)
		return 0;
	*((struct in6_addr *)&tuple->saddr.ipv6) = ip6h->saddr;
	*((struct in6_addr *)&tuple->daddr.ipv6) = ip6h->daddr;
	return ip6h->nexthdr;
}

static inline void parse_udp(void *data, u64 nh_off, void *data_end,
			     struct bpf_sock_tuple *tuple)
{
	struct udphdr *udph = data + nh_off;

	if (udph + 1 > data_end)
		return;
	tuple->sport = udph->source;
	tuple->dport = udph->dest;
}

static inline void parse_tcp(void *data, u64 nh_off, void *data_end,
			     struct bpf_sock_tuple *tuple)
{
	struct tcphdr *tcph = data + nh_off;

	if (tcph + 1 > data_end)
		return;
	tuple->sport = tcph->source;
	tuple->dport = tcph->dest;
}

static inline int parse_tuple(struct __sk_buff *ctx, struct bpf_sock_tuple *tuple) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int rc = TC_ACT_SHOT;
	u16 sport, dport;
	u16 h_proto;
	u64 nh_off;
	u32 ipproto;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	h_proto = eth->h_proto;
	if (h_proto == htons(ETH_P_IP)) {
		tuple->family = AF_INET;
		ipproto = parse_ipv4(data, nh_off, data_end, tuple);
		nh_off += sizeof(struct iphdr);
	} else if (h_proto == htons(ETH_P_IPV6)) {
		tuple->family = AF_INET6;
		ipproto = parse_ipv6(data, nh_off, data_end, tuple);
		nh_off += sizeof(struct ipv6hdr);
	} else {
		return rc;
	}
	if (!ipproto)
		return rc;

	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;
	if (data + nh_off > data_end)
		return rc;

	tuple->proto = ipproto;
	if (ipproto == IPPROTO_TCP) {
		parse_tcp(data, nh_off, data_end, tuple);
	} else if (ipproto == IPPROTO_UDP) {
		parse_udp(data, nh_off, data_end, tuple);
	} else {
		return ipproto;
	}

	return TC_ACT_OK;
}

static inline void set_ip(void *dst_, void *src_)
{
	struct in6_addr *src = (struct in6_addr *)src_;
	struct in6_addr *dst = (struct in6_addr *)dst_;

	*dst = *src;
}

/* Swap tuple so we may find the socket sending the reverse of this traffic. */
static inline void swap_tuple(struct bpf_sock_tuple *tuple)
{
	struct in6_addr ip;
	__be16 port;

	set_ip(&ip, &tuple->saddr.ipv6);
	set_ip(&tuple->saddr.ipv6, &tuple->daddr.ipv6);
	set_ip(&tuple->daddr.ipv6, &ip);

	port = tuple->sport;
	tuple->sport = tuple->dport;
	tuple->dport = port;
}

SEC("classifier")
int tc_prog1(struct __sk_buff *ctx)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock_ops *sk;
	int rc = TC_ACT_SHOT;
	long *value;
	int dir = 0;
	u32 state;
	int err;

	err = parse_tuple(ctx, &tuple);
	if (err != TC_ACT_OK) {
		if (!tuple.family)
			return TC_ACT_OK;
		value = bpf_map_lookup_elem(&dropcnt, &dir);
		if (value)
			*value += 1;
		return rc;
	}
	sk = bpf_sk_lookup(ctx, &tuple, sizeof tuple, NETNS_ID, 0);
	if (!sk) {
		printk("sk_lookup() failed: no such element in ns=%d\n",
		       NETNS_ID);

		dir = 1;
		swap_tuple(&tuple);
		sk = bpf_sk_lookup(ctx, &tuple, sizeof tuple, NETNS_ID, 0);
		if (!sk) {
			printk("sk_lookup() failed with reverse tuple\n");
			value = bpf_map_lookup_elem(&dropcnt, &dir);
			if (value)
				*value += 1;
			return rc;
		}
	}

	state = sk->state;
	printk("sk_lookup() success: %d\n", state);
	value = bpf_map_lookup_elem(&rxcnt, &state);
	if (value)
		*value += 1;

	bpf_sk_release(sk, 0);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
