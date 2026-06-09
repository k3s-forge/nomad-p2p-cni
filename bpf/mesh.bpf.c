// SPDX-License-Identifier: GPL-2.0
// mesh.bpf.c - P2P mesh routing with Geneve encapsulation
//
// TC egress: route packets to local containers or encapsulate for remote nodes
// The Geneve tunnel device (gnv0) handles UDP encapsulation to port 6081

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GENEVE_UDP_PORT 6081
#define MAX_NODE_ENTRIES 4096
#define ROUTE_MISS_EVENT 1
#define BPF_F_TUNINFO_IPV4 0

// Key: overlay destination IP (network byte order)
// Value: local ifindex of the container veth (for local delivery)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} CONTAINER_ROUTE_MAP SEC(".maps");

// Key: remote node overlay IP
// Value: remote node's public endpoint for Geneve encapsulation
struct node_endpoint {
    __u32 public_ip;
    __u16 public_port;
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_NODE_ENTRIES);
    __type(key, __u32);
    __type(value, struct node_endpoint);
} NODE_DYNAMIC_MAP SEC(".maps");

// Ringbuf for route misses - userspace resolves via seed
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} ROUTE_MISS_RINGBUF SEC(".maps");

// Geneve tunnel device ifindex - set by userspace agent
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} GENEVE_IFINDEX_MAP SEC(".maps");

// Tunnel configuration - set by userspace agent
struct tunnel_config {
    __u32 tunnel_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_config);
} TUNNEL_CFG_MAP SEC(".maps");

static __always_inline int lookup_remote_node(__u32 dst_ip, struct node_endpoint *ep) {
    struct node_endpoint *found = bpf_map_lookup_elem(&NODE_DYNAMIC_MAP, &dst_ip);
    if (found) {
        *ep = *found;
        return 1;
    }
    return 0;
}

static __always_inline void emit_route_miss(__u32 dst_ip) {
    bpf_ringbuf_output(&ROUTE_MISS_RINGBUF, &dst_ip, sizeof(dst_ip), ROUTE_MISS_EVENT);
}

// TC egress program - attached to host interface or veth peer
SEC("tc")
int egress_p2p_mesh(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u32 dst_ip = iph->daddr;

    // Check if destination is a local container
    __u32 *local_ifindex = bpf_map_lookup_elem(&CONTAINER_ROUTE_MAP, &dst_ip);
    if (local_ifindex && *local_ifindex > 0) {
        return bpf_redirect(*local_ifindex, 0);
    }

    // Check if destination is a remote node
    struct node_endpoint remote = {};
    if (lookup_remote_node(dst_ip, &remote)) {
        // Look up Geneve device ifindex
        __u32 cfg_key = 0;
        __u32 *geneve_ifindex = bpf_map_lookup_elem(&GENEVE_IFINDEX_MAP, &cfg_key);
        if (!geneve_ifindex || *geneve_ifindex == 0)
            return TC_ACT_OK;

        // Read tunnel ID from config map
        __u32 tunnel_id = 100;
        struct tunnel_config *cfg = bpf_map_lookup_elem(&TUNNEL_CFG_MAP, &cfg_key);
        if (cfg)
            tunnel_id = cfg->tunnel_id;

        // Set tunnel key for Geneve encapsulation
        struct bpf_tunnel_key key = {};
        key.remote_ipv4 = remote.public_ip;
        key.tunnel_id = tunnel_id;
        key.tunnel_flags = BPF_F_TUNINFO_IPV4;

        bpf_skb_set_tunnel_key(skb, &key, sizeof(key), 0);

        // Redirect to Geneve tunnel device for encapsulation
        return bpf_redirect(*geneve_ifindex, 0);
    }

    // Route miss - emit to ringbuf for userspace resolution
    emit_route_miss(dst_ip);

    return TC_ACT_OK;
}

// XDP pass-through program for interface attachment
SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
