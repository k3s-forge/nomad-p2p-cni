pub mod bpf;
pub mod metrics;
pub mod protocol;
pub mod relay;
pub mod seed;
pub mod stun;
pub mod vip;

use std::time::Instant;

use nomad_p2p_common::Config;
use tokio::sync::RwLock;

pub struct AgentState {
    pub cfg: Config,
    pub start_time: Instant,
    pub nat_type: RwLock<nomad_p2p_common::NatType>,
    pub public_ip: RwLock<std::net::Ipv4Addr>,
    pub public_port: RwLock<u16>,
}

impl AgentState {
    pub fn new(cfg: Config) -> Self {
        Self {
            start_time: Instant::now(),
            nat_type: RwLock::new(nomad_p2p_common::NatType::Unknown),
            public_ip: RwLock::new(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            public_port: RwLock::new(cfg.listen_port),
            cfg,
        }
    }
}
