pub mod api;
pub mod bpf;
pub mod ipsec;
pub mod kademlia;
pub mod metrics;
pub mod protocol;
pub mod relay;
pub mod reload;
pub mod route;
pub mod seed;
pub mod stun;
pub mod vip;

use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedAddr {
    pub addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VipBackendCfg {
    pub vip: String,
    pub backends: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRule {
    pub source_ip: String,
    pub port: u16,
    pub protocol: String,
    pub allow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub node_overlay_ip: String,
    pub node_subnet: String,
    pub seeds: Vec<SeedAddr>,
    pub tunnel_vni: u32,
    pub tunnel_device: String,
    pub psk: String,
    pub stun_servers: Vec<String>,
    pub listen_port: u16,
    pub stun_refresh_interval: u64,
    pub lazy_discovery: bool,
    pub route_miss_max_pending: usize,
    pub ipsec_enabled: bool,
    pub ipsec_spi: u32,
    pub ipsec_key: String,
    pub cni_bin_path: String,
    pub mtu: u16,
    pub vip_enabled: bool,
    pub vip_watch_list: Vec<String>,
    pub vip_backends: Vec<VipBackendCfg>,
    pub firewall_enabled: bool,
    pub default_policy: String,
    pub allowed_sources: Vec<String>,
    pub allowed_ports: Vec<PortRule>,
    pub metrics_port: u16,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            node_overlay_ip: "10.244.0.1".into(),
            node_subnet: "10.244.1.0/24".into(),
            seeds: vec![],
            tunnel_vni: 100,
            tunnel_device: "gnv0".into(),
            psk: "".into(),
            stun_servers: vec!["stun.l.google.com:19302".into()],
            listen_port: 9527,
            stun_refresh_interval: 120,
            lazy_discovery: true,
            route_miss_max_pending: 256,
            ipsec_enabled: false,
            ipsec_spi: 4096,
            ipsec_key: "".into(),
            cni_bin_path: "/opt/cni/bin/nomad-p2p-cni".into(),
            mtu: 1420,
            vip_enabled: false,
            vip_watch_list: vec![],
            vip_backends: vec![],
            firewall_enabled: false,
            default_policy: "allow".into(),
            allowed_sources: vec![],
            allowed_ports: vec![],
            metrics_port: 9090,
        }
    }
}

pub struct AgentState {
    pub cfg: AgentConfig,
    pub start_time: Instant,
    pub nat_type: RwLock<nomad_p2p_common::NatType>,
    pub public_ip: RwLock<std::net::Ipv4Addr>,
    pub public_port: RwLock<u16>,
}

impl AgentState {
    pub fn new(cfg: AgentConfig) -> Self {
        Self {
            start_time: Instant::now(),
            nat_type: RwLock::new(nomad_p2p_common::NatType::Unknown),
            public_ip: RwLock::new(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            public_port: RwLock::new(cfg.listen_port),
            cfg,
        }
    }
}
