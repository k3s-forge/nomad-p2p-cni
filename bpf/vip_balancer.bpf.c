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

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

SEC("cgroup/connect4")
int vip_load_balance(struct bpf_sock_addr *ctx) {
    return 1;
}

char _license[] SEC("license") = "GPL";
