// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GENEVE_PORT 6081
#define TUNNEL_VNI 100

struct node_endpoint {
    __u32 public_ip;
    __u16 public_port;
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} CONTAINER_ROUTE_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct node_endpoint);
} NODE_DYNAMIC_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} ROUTE_MISS_RINGBUF SEC(".maps");

SEC("tc")
int egress_p2p_mesh(struct __sk_buff *skb) {
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

    __u32 dst_ip = iph->daddr;

    /* Only handle overlay range 10.244.0.0/16 */
    __u8 *d = (__u8 *)&dst_ip;
    if (d[0] != 10 || d[1] != 244)
        return BPF_OK;

    __u32 *target_node = bpf_map_lookup_elem(&CONTAINER_ROUTE_MAP, &dst_ip);
    if (!target_node) {
        __u32 *miss = bpf_ringbuf_reserve(&ROUTE_MISS_RINGBUF, sizeof(__u32), 0);
        if (miss) {
            *miss = dst_ip;
            bpf_ringbuf_submit(miss, 0);
        }
        return BPF_DROP;
    }

    struct node_endpoint *ep = bpf_map_lookup_elem(&NODE_DYNAMIC_MAP, target_node);
    if (!ep) {
        __u32 *miss = bpf_ringbuf_reserve(&ROUTE_MISS_RINGBUF, sizeof(__u32), 0);
        if (miss) {
            *miss = *target_node;
            bpf_ringbuf_submit(miss, 0);
        }
        return BPF_DROP;
    }

    /* Rewrite outer UDP destination to peer's public endpoint */
    /* The geneve device (gnv0) handles encapsulation */
    return bpf_redirect_peer(1); /* placeholder ifindex, set at runtime */
}

char _license[] SEC("license") = "GPL";
