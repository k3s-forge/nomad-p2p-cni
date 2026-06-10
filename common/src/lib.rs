
pub const HMAC_SIZE: usize = 32;
pub const HEADER_SIZE: usize = 16;
pub const MIN_MESSAGE_SIZE: usize = HEADER_SIZE + HMAC_SIZE;
pub const REPLAY_WINDOW_SECS: u64 = 300;
pub const ROUTE_MISS_BUF_SIZE: usize = 4096;
pub const ROUTE_MISS_BATCH_INTERVAL_MS: u64 = 100;
pub const ROUTE_MISS_COOLDOWN_SECS: u64 = 5;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerEndpoint {
    pub public_ip: u32,
    pub port: u16,
    pub nat_type: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VipBackend {
    pub ip: u32,
    pub port: u16,
    pub weight: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VipInfo {
    pub backends: [VipBackend; 16],
    pub count: u8,
    pub next_idx: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TunnelCfg {
    pub tunnel_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AclRule {
    pub src_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub action: u8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    Unknown = 0,
    Easy = 1,
    Symmetric = 2,
}

impl Default for NatType {
    fn default() -> Self {
        Self::Unknown
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclAction {
    Allow = 1,
    Deny = 2,
}

// Safety: #[repr(C)] plain-old-data types for BPF map storage
unsafe impl aya::Pod for PeerEndpoint {}
unsafe impl aya::Pod for VipBackend {}
unsafe impl aya::Pod for VipInfo {}
unsafe impl aya::Pod for TunnelCfg {}
unsafe impl aya::Pod for AclRule {}
