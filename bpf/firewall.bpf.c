// SPDX-License-Identifier: GPL-2.0
// firewall.bpf.c - Ingress firewall ACL enforcement
//
// TC ingress: check source IP against ACL map, allow or drop
// ACL_MAP key: source IP, value: 1=allow, 0=deny
// PORT_ACL_MAP key: src_ip<<32|dst_port, value: 1=allow, 0=deny

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// Key: source IP (network byte order)
// Value: 1=allow all, 0=deny
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);     // source IP
    __type(value, __u8);    // 1=allow, 0=deny
} ACL_MAP SEC(".maps");

// Key: src_ip<<32 | dst_port
// Value: 1=allow, 0=deny
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);     // src_ip << 32 | dst_port
    __type(value, __u8);    // 1=allow, 0=deny
} PORT_ACL_MAP SEC(".maps");

// Default policy: 1=allow all (when no ACL matches), 0=deny all
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} DEFAULT_POLICY SEC(".maps");

SEC("xdp")
int xdp_firewall_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

SEC("tc")
int tc_ingress_firewall(struct __sk_buff *skb) {
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

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;

    // Check IP-level ACL
    __u8 *allow = bpf_map_lookup_elem(&ACL_MAP, &src_ip);
    if (allow && *allow == 1) {
        return TC_ACT_OK; // explicitly allowed
    }
    if (allow && *allow == 0) {
        return TC_ACT_SHOT; // explicitly denied
    }

    // Check port-level ACL for TCP/UDP
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        void *l4 = (void *)(iph + 1);
        __u16 dst_port = 0;

        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) > data_end)
                return TC_ACT_OK;
            dst_port = bpf_ntohs(tcp->dest);
        } else {
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) > data_end)
                return TC_ACT_OK;
            dst_port = bpf_ntohs(udp->dest);
        }

        __u64 port_key = ((__u64)src_ip << 32) | dst_port;
        __u8 *port_allow = bpf_map_lookup_elem(&PORT_ACL_MAP, &port_key);
        if (port_allow) {
            return *port_allow ? TC_ACT_OK : TC_ACT_SHOT;
        }
    }

    // Apply default policy
    __u32 default_key = 0;
    __u8 *default_policy = bpf_map_lookup_elem(&DEFAULT_POLICY, &default_key);
    if (default_policy && *default_policy == 1) {
        return TC_ACT_OK; // default allow
    }

    // Default deny
    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
