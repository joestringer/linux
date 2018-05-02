/* SPDX-License-Identifier: GPL-2.0 */
// Copyright (c) 2018 Covalent IO, Inc. http://covalent.io

#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";

/* Fill 'tuple' with L3 info, and attempt to find L4. On fail, return NULL. */
static void *fill_ip(struct bpf_sock_tuple *tuple, void *data, __u64 nh_off,
		     void *data_end, __u16 eth_proto)
{
	__u64 ihl_len;
	__u8 proto;

	if (eth_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (struct iphdr *)(data + nh_off);

		if (iph + 1 > data_end)
			return NULL;
		ihl_len = iph->ihl * 4;
		proto = iph->protocol;

		tuple->family = AF_INET;
		tuple->saddr.ipv4 = iph->saddr;
		tuple->daddr.ipv4 = iph->daddr;
	} else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + nh_off);

		if (ip6h + 1 > data_end)
			return NULL;
		ihl_len = sizeof(*ip6h);
		proto = ip6h->nexthdr;

		tuple->family = AF_INET6;
		*((struct in6_addr *)&tuple->saddr.ipv6) = ip6h->saddr;
		*((struct in6_addr *)&tuple->daddr.ipv6) = ip6h->daddr;
	}

	if (proto != IPPROTO_TCP)
		return NULL;

	return data + nh_off + ihl_len;
}

SEC("sk_lookup_success")
int bpf_sk_lookup_test0(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = (struct ethhdr *)(data);
	struct bpf_sock_tuple tuple = {};
	struct tcphdr *tcp;
	struct bpf_sock *sk;
	void *l4;

	if (eth + 1 > data_end)
		return TC_ACT_SHOT;

	l4 = fill_ip(&tuple, data, sizeof(*eth), data_end, eth->h_proto);
	if (!l4 || l4 + sizeof *tcp > data_end)
		return TC_ACT_SHOT;

	tcp = l4;
	tuple.sport = tcp->source;
	tuple.dport = tcp->dest;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple), 0, 0);
	if (sk)
		bpf_sk_release(sk, 0);
	return sk ? TC_ACT_OK : TC_ACT_UNSPEC;
}

SEC("fail_no_release")
int bpf_sk_lookup_test1(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};

	bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple), 0, 0);
	return 0;
}

SEC("fail_release_twice")
int bpf_sk_lookup_test2(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple), 0, 0);
	bpf_sk_release(sk, 0);
	bpf_sk_release(sk, 0);
	return 0;
}

SEC("fail_release_unchecked")
int bpf_sk_lookup_test3(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple), 0, 0);
	bpf_sk_release(sk, 0);
	return 0;
}

void lookup_no_release(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple), 0, 0);
}

SEC("fail_no_release_subcall")
int bpf_sk_lookup_test4(struct __sk_buff *skb)
{
	lookup_no_release(skb);
	return 0;
}
