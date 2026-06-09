//go:build ignore

#include <linux/bpf.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BACKENDS 16

struct vip_info {
    __u32 backends[MAX_BACKENDS];
    __u8  count;
    __u32 next_idx;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);           // VIP IP
    __type(value, struct vip_info);
} VIP_MAP SEC(".maps");

SEC("cgroup/connect4")
int vip_load_balance(struct bpf_sock_addr *ctx) {
    __u32 vip = ctx->user_ip4;

    struct vip_info *info = bpf_map_lookup_elem(&VIP_MAP, &vip);
    if (!info || info->count == 0)
        return 1; // BPF_CGROUP_INET4_CONNECT: allow

    // Round-robin backend selection
    __u32 idx = __sync_fetch_and_add(&info->next_idx, 1) % info->count;
    __u32 real_ip = info->backends[idx];

    ctx->user_ip4 = real_ip;

    return 1; // allow
}

char _license[] SEC("license") = "GPL";
