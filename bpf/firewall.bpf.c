//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ACTION_ALLOW 1
#define ACTION_DROP   0

// ACL map: src_ip -> action (1=allow, 0=drop)
// Missing entries default to allow (zero-trust inverted: only explicit drops block)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);   // source IP
    __type(value, __u8);  // ACTION_ALLOW or ACTION_DROP
} ACL_MAP SEC(".maps");

// Per-port ACL: (src_ip << 16 | dst_port) -> action
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // (src_ip << 16 | dst_port)
    __type(value, __u8);  // ACTION_ALLOW or ACTION_DROP
} PORT_ACL_MAP SEC(".maps");

static __always_inline __u32 extract_ip(void *data, void *data_end, int offset) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return 0;
    if (offset == 0)
        return iph->saddr;
    return iph->daddr;
}

SEC("tc")
int tc_ingress_firewall(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u32 src_ip = extract_ip(data, data_end, 0);
    if (src_ip == 0)
        return BPF_OK;

    // Check per-source ACL
    __u8 *action = bpf_map_lookup_elem(&ACL_MAP, &src_ip);
    if (action && *action == ACTION_DROP)
        return BPF_DROP;

    // Check per-port ACL (parse L4 for port)
    struct ethhdr *eth = data;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return BPF_OK;

    __u16 dst_port = 0;
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        void *l4 = (void *)iph + (iph->ihl * 4);
        if (l4 + 4 <= data_end)
            dst_port = *(__u16 *)(l4 + 2); // dst port in network order
    }

    if (dst_port != 0) {
        __u64 port_key = ((__u64)src_ip << 16) | bpf_ntohs(dst_port);
        __u8 *port_action = bpf_map_lookup_elem(&PORT_ACL_MAP, &port_key);
        if (port_action && *port_action == ACTION_DROP)
            return BPF_DROP;
    }

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
