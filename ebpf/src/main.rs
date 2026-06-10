#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, cgroup_connect4, map, xdp},
    maps::{HashMap, RingBuf},
    programs::{TcContext, CgroupConnect4Context, XdpContext},
    EbpfContext,
};
use nomad_p2p_common::*;

macro_rules! info {
    ($ctx:expr, $($arg:tt)*) => { let _ = format_args!($($arg)*); };
}

#[map]
pub static CONTAINER_ROUTE_MAP: HashMap<u32, u32> = HashMap::<u32, u32>::pinned(65536, 0);

#[map]
pub static NODE_DYNAMIC_MAP: HashMap<u32, PeerEndpoint> = HashMap::<u32, PeerEndpoint>::pinned(16384, 0);

#[map]
pub static ROUTE_MISS_RINGBUF: RingBuf<u32> = RingBuf::<u32>::pinned(65536, 0);

#[map]
pub static GENEVE_IFINDEX_MAP: HashMap<u32, u32> = HashMap::<u32, u32>::pinned(1, 0);

#[map]
pub static TUNNEL_CFG_MAP: HashMap<u32, TunnelCfg> = HashMap::<u32, TunnelCfg>::pinned(1, 0);

#[map]
pub static VIP_MAP: HashMap<u32, VipInfo> = HashMap::<u32, VipInfo>::pinned(1024, 0);

#[map]
pub static ACL_MAP: HashMap<u32, AclRule> = HashMap::<u32, AclRule>::pinned(4096, 0);

#[map]
pub static DEFAULT_POLICY: HashMap<u32, u8> = HashMap::<u32, u8>::pinned(1, 0);

// TC egress: Geneve encapsulation for mesh traffic
#[classifier]
pub fn egress_p2p_mesh(ctx: TcContext) -> i32 {
    match unsafe { try_egress(&ctx) } {
        Ok(ret) => ret,
        Err(_) => {
            info!(&ctx, "egress error");
            tc_action::TC_ACT_PIPE
        }
    }
}

unsafe fn try_egress(ctx: &TcContext) -> Result<i32, i64> {
    let proto = ctx.load(12)?;
    if proto != 0x0800u16 {
        // not IPv4
        return Ok(tc_action::TC_ACT_PIPE);
    }

    let total = ctx.len()?;
    if total < 42 {
        return Ok(tc_action::TC_ACT_PIPE);
    }

    let dest_ip: u32 = ctx.load(16)?;

    let geneve_ifindex = GENEVE_IFINDEX_MAP.get(&0u32).ok_or(0i64)?;
    if *geneve_ifindex == 0 {
        return Ok(tc_action::TC_ACT_PIPE);
    }

    let node_endpoint = match NODE_DYNAMIC_MAP.get(&dest_ip) {
        Some(ep) => ep,
        None => {
            if let Some(mut ringbuf) = ROUTE_MISS_RINGBUF.reserve() {
                *ringbuf.as_mut() = dest_ip;
                ringbuf.submit(0);
            }
            return Ok(tc_action::TC_ACT_PIPE);
        }
    };

    let data = ctx.data();
    let data_end = ctx.data_end();
    let len = (data_end as usize) - (data as usize);
    if len < 42 {
        return Ok(tc_action::TC_ACT_PIPE);
    }

    // Overwrite destination IP in IP header (offset 16 from packet start)
    core::ptr::write_unaligned((data + 16) as *mut u32, node_endpoint.public_ip);

    // Redirect to Geneve device
    let ret = aya_ebpf::helpers::bpf_redirect(*geneve_ifindex, 0);
    if ret >= 0 {
        Ok(ret)
    } else {
        Ok(tc_action::TC_ACT_PIPE)
    }
}

// TC ingress: Firewall ACL enforcement
#[classifier]
pub fn tc_ingress_firewall(ctx: TcContext) -> i32 {
    match unsafe { try_firewall(&ctx) } {
        Ok(ret) => ret,
        Err(_) => tc_action::TC_ACT_PIPE,
    }
}

unsafe fn try_firewall(ctx: &TcContext) -> Result<i32, i64> {
    let proto: u16 = ctx.load(12)?;
    if proto != 0x0800 {
        return Ok(tc_action::TC_ACT_PIPE);
    }

    let total = ctx.len()?;
    if total < 42 {
        return Ok(tc_action::TC_ACT_PIPE);
    }

    let src_ip: u32 = ctx.load(26)?;
    let _protocol: u8 = (ctx.load::<u16>(23)? >> 8) as u8;

    let default = DEFAULT_POLICY.get(&0u32).copied().unwrap_or(1);

    if let Some(rule) = ACL_MAP.get(&src_ip) {
        if rule.action == 2 {
            return Ok(tc_action::TC_ACT_SHOT);
        }
        return Ok(tc_action::TC_ACT_PIPE);
    }

    if default == 2 {
        return Ok(tc_action::TC_ACT_SHOT);
    }

    Ok(tc_action::TC_ACT_PIPE)
}

// cgroup/connect4: VIP load balancing
#[cgroup_connect4]
pub fn vip_load_balance(ctx: CgroupConnect4Context) -> i32 {
    match unsafe { try_vip(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_vip(ctx: &CgroupConnect4Context) -> Result<i32, i64> {
    let user_ip = ctx.user_ip();
    let _user_port = ctx.user_port();

    if let Some(vip_info) = VIP_MAP.get(&user_ip) {
        if vip_info.count > 0 {
            let idx = (vip_info.next_idx as usize) % (vip_info.count as usize);
            let backend = &vip_info.backends[idx];

            ctx.set_user_ip(backend.ip);
            ctx.set_user_port(u16::from_be(backend.port));

            // NOTE: next_idx update has a known race condition. Multiple concurrent
            // cgroup/connect4 calls may read and write next_idx non-atomically,
            // causing transient load imbalance. For aya-ebpf 0.13, this can be
            // mitigated with bpf_spin_lock when kernel >= 5.1 and aya-ebpf >= 0.13.
            let next = ((idx + 1) % (vip_info.count as usize)) as u8;
            if next != vip_info.next_idx {
                let mut info = *vip_info;
                info.next_idx = next;
                let _ = VIP_MAP.insert(&user_ip, &info, 0);
            }
        }
    }

    Ok(0)
}

// XDP pass program
#[xdp]
pub fn xdp_pass(ctx: XdpContext) -> i32 {
    match unsafe { try_xdp_pass(&ctx) } {
        Ok(ret) => ret,
        Err(_) => aya_ebpf::bindings::XDP_PASS,
    }
}

unsafe fn try_xdp_pass(_ctx: &XdpContext) -> Result<i32, i64> {
    Ok(aya_ebpf::bindings::XDP_PASS)
}

mod tc_action {
    pub const TC_ACT_PIPE: i32 = 2;
    pub const TC_ACT_SHOT: i32 = 3;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
