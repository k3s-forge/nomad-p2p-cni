// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ACTION_ALLOW 1
#define ACTION_DROP   0

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} ACL_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} PORT_ACL_MAP SEC(".maps");

SEC("tc")
int tc_ingress_firewall(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return BPF_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return BPF_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return BPF_OK;

    __u32 src_ip = iph->saddr;

    __u8 *action = bpf_map_lookup_elem(&ACL_MAP, &src_ip);
    if (action && *action == ACTION_DROP)
        return BPF_DROP;

    __u16 dst_port = 0;
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        void *l4 = (void *)iph + (iph->ihl * 4);
        if (l4 + 4 <= data_end)
            dst_port = *(__u16 *)(l4 + 2);
    }

    if (dst_port != 0) {
        __u64 port_key = ((__u64)src_ip << 16) | bpf_ntohs(dst_port);
        __u8 *pa = bpf_map_lookup_elem(&PORT_ACL_MAP, &port_key);
        if (pa && *pa == ACTION_DROP)
            return BPF_DROP;
    }

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
