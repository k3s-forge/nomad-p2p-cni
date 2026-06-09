//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GENEVE_UDP_PORT 6081
#define TUNNEL_VNI 100
#define POD_NET_PREFIX 0x00F4A80A // 10.244.0.0 in network order (will mask with /16)
#define POD_NET_MASK 0x00FFFF0A   // 10.244.0.0 little-endian

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // destination container IP
    __type(value, __u32); // destination node private (overlay) IP
} CONTAINER_ROUTE_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);   // node overlay IP
    __type(value, struct node_endpoint); // public IP:Port
} NODE_DYNAMIC_MAP SEC(".maps");

struct node_endpoint {
    __u32 public_ip;
    __u16 public_port;
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} ROUTE_MISS_RINGBUF SEC(".maps");

struct geneve_hdr {
    __u8 ver_flags;
    __u8 opt_len;
    __u8 proto_type;
    __u8 vni_hi;
    __u16 vni_lo_flags;
};

static __always_inline __u32 extract_dst_ip(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return 0;

    return iph->daddr;
}

static __always_inline __u32 extract_src_ip(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return 0;

    return iph->saddr;
}

SEC("tc")
int egress_p2p_mesh(struct __sk_buff *skb) {
    __u32 inner_dst_ip = extract_dst_ip(skb);
    if (inner_dst_ip == 0)
        return BPF_OK;

    // Check if destination is in our overlay range (10.244.0.0/16)
    __u8 *dst_bytes = (__u8 *)&inner_dst_ip;
    if (dst_bytes[0] != 10 || dst_bytes[1] != 244)
        return BPF_OK;

    // Lookup which node owns this container
    __u32 *target_node_ip = bpf_map_lookup_elem(&CONTAINER_ROUTE_MAP, &inner_dst_ip);
    if (!target_node_ip) {
        // Route miss: notify user-space agent via ringbuf
        __u32 *miss_ip = bpf_ringbuf_reserve(&ROUTE_MISS_RINGBUF, sizeof(__u32), 0);
        if (miss_ip) {
            *miss_ip = inner_dst_ip;
            bpf_ringbuf_submit(miss_ip, 0);
        }
        return BPF_DROP;
    }

    // Lookup the target node's public endpoint
    struct node_endpoint *ep = bpf_map_lookup_elem(&NODE_DYNAMIC_MAP, target_node_ip);
    if (!ep) {
        // Node endpoint unknown: trigger discovery
        __u32 *miss_ip = bpf_ringbuf_reserve(&ROUTE_MISS_RINGBUF, sizeof(__u32), 0);
        if (miss_ip) {
            *miss_ip = *target_node_ip;
            bpf_ringbuf_submit(miss_ip, 0);
        }
        return BPF_DROP;
    }

    // Redirect to the geneve tunnel interface (gnv0)
    // The kernel geneve driver handles encapsulation via tunnel key
    struct bpf_tunnel_key key = {};
    key.remote_ipv4 = ep->public_ip;
    key.tunnel_id = TUNNEL_VNI;
    key.tunnel_ttl = 64;

    skb->tunnel_key = 1;
    bpf_skb_set_tunnel_key(skb, &key, sizeof(key), 0);

    // Redirect to gnv0 - the geneve device handles UDP encapsulation
    return bpf_redirect(1 /* placeholder ifindex */, BPF_F_INGRESS);
}

SEC("tc")
int ingress_firewall(struct __sk_buff *skb) {
    // Allow all traffic on the overlay interface
    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
