// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_BACKENDS 16

struct vip_info {
    __u32 backends[MAX_BACKENDS];
    __u8  count;
    __u32 next_idx;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct vip_info);
} VIP_MAP SEC(".maps");

SEC("cgroup/connect4")
int vip_load_balance(struct bpf_sock_addr *ctx) {
    __u32 vip = ctx->user_ip4;

    struct vip_info *info = bpf_map_lookup_elem(&VIP_MAP, &vip);
    if (!info || info->count == 0)
        return 1;

    __u32 idx = __sync_fetch_and_add(&info->next_idx, 1) % info->count;
    ctx->user_ip4 = info->backends[idx];

    return 1;
}

char _license[] SEC("license") = "GPL";
