// SPDX-License-Identifier: GPL-2.0
// vip_balancer.bpf.c - VIP load balancer via cgroup/connect4
//
// Intercepts connect() calls to VIP addresses and rewrites
// destination to a selected backend using round-robin

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BACKENDS 16

struct vip_info {
    __u32 backends[MAX_BACKENDS]; // backend IPs (network byte order)
    __u8  count;                  // number of active backends
    __u8  _pad[3];
    __u32 next_idx;               // round-robin counter
};

// Key: VIP IP (network byte order)
// Value: backend pool
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);          // VIP IP
    __type(value, struct vip_info);
} VIP_MAP SEC(".maps");

// Stats map: key=backend_ip:port, value=connection count
struct vip_stats {
    __u64 conns;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);          // backend_ip << 32 | port
    __type(value, struct vip_stats);
} VIP_STATS_MAP SEC(".maps");

SEC("xdp")
int xdp_vip_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

SEC("cgroup/connect4")
int vip_load_balance(struct bpf_sock_addr *ctx) {
    __u32 vip = ctx->user_ip4;

    struct vip_info *info = bpf_map_lookup_elem(&VIP_MAP, &vip);
    if (!info || info->count == 0)
        return 1;

    __u32 idx = info->next_idx % info->count;

    // Increment next_idx for next call (non-atomic is fine for LB)
    __u32 new_idx = (idx + 1) % info->count;
    info->next_idx = new_idx;

    __u32 backend = info->backends[idx];
    if (backend == 0)
        return 1;

    ctx->user_ip4 = backend;

    __u64 key = ((__u64)backend << 32) | ctx->user_port;
    struct vip_stats *stats = bpf_map_lookup_elem(&VIP_STATS_MAP, &key);
    if (stats) {
        stats->conns += 1;
    } else {
        struct vip_stats new_stats = { .conns = 1, .bytes = 0 };
        bpf_map_update_elem(&VIP_STATS_MAP, &key, &new_stats, BPF_ANY);
    }

    return 1;
}

char _license[] SEC("license") = "GPL";
