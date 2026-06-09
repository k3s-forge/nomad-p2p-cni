// SPDX-License-Identifier: GPL-2.0
// mesh.bpf.c - P2P mesh routing with Geneve encapsulation
//
// TC egress: route packets to local containers or encapsulate for remote nodes
// XDP: XDP_PASS for ingress (handled by firewall.bpf.c)

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

// Key: overlay destination IP (network byte order)
// Value: local ifindex of the container veth (for local delivery)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);      // overlay dst IP
    __type(value, __u32);    // local ifindex
} CONTAINER_ROUTE_MAP SEC(".maps");

// Key: overlay source IP (network byte order) representing a remote node subnet
// Value: remote node's public endpoint
struct node_endpoint {
    __u32 public_ip;    // network byte order
    __u16 public_port;  // host byte order
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_NODE_ENTRIES);
    __type(key, __u32);              // overlay IP of remote node
    __type(value, struct node_endpoint);
} NODE_DYNAMIC_MAP SEC(".maps");

// Ringbuf for route misses - userspace resolves via seed
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} ROUTE_MISS_RINGBUF SEC(".maps");

// Geneve header template (set by userspace, used by TC program)
struct geneve_opt {
    __u8 opt_class;
    __u8 opt_type;
    __u16 opt_len;
    __u32 opt_data;
};

static __always_inline int lookup_remote_node(__u32 dst_ip, struct node_endpoint *ep) {
    // Check if destination matches any known remote node subnet
    // We use /24 matching: mask the last octet
    __u32 subnet_key = dst_ip & 0x00FFFFFF; // mask last byte (assuming /24)
    struct node_endpoint *found = bpf_map_lookup_elem(&NODE_DYNAMIC_MAP, &subnet_key);
    if (found) {
        *ep = *found;
        return 1;
    }
    // Also try exact match
    found = bpf_map_lookup_elem(&NODE_DYNAMIC_MAP, &dst_ip);
    if (found) {
        *ep = *found;
        return 1;
    }
    return 0;
}

static __always_inline void emit_route_miss(__u32 dst_ip) {
    bpf_ringbuf_output(&ROUTE_MISS_RINGBUF, &dst_ip, sizeof(dst_ip), ROUTE_MISS_EVENT);
}

// TC egress program - attached to container veth's peer on host
SEC("tc")
int egress_p2p_mesh(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only handle IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u32 dst_ip = iph->daddr;

    // Check if destination is a local container
    __u32 *local_ifindex = bpf_map_lookup_elem(&CONTAINER_ROUTE_MAP, &dst_ip);
    if (local_ifindex) {
        // Local delivery - forward to container's veth
        bpf_redirect(*local_ifindex, 0);
        return TC_ACT_REDIRECT;
    }

    // Check if destination is a remote node
    struct node_endpoint remote = {};
    if (lookup_remote_node(dst_ip, &remote)) {
        // Remote delivery - need Geneve encapsulation
        // For now, emit the packet to the geneve tunnel device
        // The kernel's geneve module handles encapsulation

        // Build inner packet info for the tunnel
        __u32 key = dst_ip;
        bpf_map_update_elem(&CONTAINER_ROUTE_MAP, &key, &key, BPF_NOEXIST);

        // Redirect to the geneve tunnel interface (userspace sets up routing)
        // The geneve device handles UDP encapsulation to remote:6081
        return TC_ACT_OK;
    }

    // Route miss - emit to ringbuf for userspace resolution
    emit_route_miss(dst_ip);

    // Drop the packet while userspace resolves the route
    // On next attempt, the route will be cached
    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
