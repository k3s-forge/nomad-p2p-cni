#![allow(unused_imports, unused_variables, unused_mut, dead_code)]

pub mod api;
pub mod bpf;
pub mod ipsec;
// pub mod kademlia;  // unstable: libp2p API mismatch, re-enable when deps stabilize
pub mod metrics;
pub mod protocol;
pub mod relay;
pub mod reload;
pub mod route;
pub mod seed;
pub mod stun;
pub mod vip;

use std::sync::Arc;
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
    /// UDP port for peer communication + seed registration
    pub listen_port: u16,
    /// TCP port for libp2p Kademlia/GossipSub (0 = disabled)
    pub p2p_port: u16,
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
            p2p_port: 0,
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
    pub cfg: RwLock<AgentConfig>,
    pub start_time: Instant,
    pub nat_type: RwLock<nomad_p2p_common::NatType>,
    pub public_ip: RwLock<std::net::Ipv4Addr>,
    pub public_port: RwLock<u16>,
}

impl AgentState {
    pub fn new(cfg: AgentConfig) -> Self {
        let listen_port = cfg.listen_port;
        Self {
            start_time: Instant::now(),
            nat_type: RwLock::new(nomad_p2p_common::NatType::Unknown),
            public_ip: RwLock::new(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            public_port: RwLock::new(listen_port),
            cfg: RwLock::new(cfg),
        }
    }
}

/// Bundled runtime state for task spawning (replaces long parameter lists)
pub struct AppContext {
    pub state: Arc<AgentState>,
    pub bpf: Arc<std::sync::Mutex<bpf::BpfManager>>,
    pub proto: Arc<tokio::sync::Mutex<protocol::UdpProtocol>>,
    pub seed_client: Arc<tokio::sync::Mutex<seed::SeedClient>>,
    pub route_mgr: Arc<route::RouteManager>,
    pub container_mgr: api::ContainerManager,
    pub ipsec_mgr: Option<Arc<std::sync::Mutex<ipsec::IpsecManager>>>,
    // pub p2p: Option<kademlia::P2pNetwork>,
    pub kad_tx: tokio::sync::mpsc::UnboundedSender<u32>,
    pub kad_rx: tokio::sync::mpsc::UnboundedReceiver<u32>,
    pub stop: Arc<std::sync::atomic::AtomicBool>,
}

impl AppContext {
    pub async fn spawn_all(self) {
        let stop = self.stop.clone();
        let state = self.state.clone();
        let bpf = self.bpf.clone();
        let proto = self.proto.clone();
        let route_mgr = self.route_mgr.clone();

        if state.cfg.read().await.metrics_port > 0 {
            tokio::spawn(metrics::serve(
                state.clone(),
                state.cfg.read().await.metrics_port,
                stop.clone(),
            ));
        }

        tokio::spawn(api::api_server(
            self.container_mgr,
            bpf.clone(),
            9091,
            stop.clone(),
        ));

        tokio::spawn(protocol::recv_loop(proto.clone(), bpf.clone(), stop.clone()));

        tokio::spawn(seed::health_loop(
            state.clone(),
            self.seed_client,
            proto.clone(),
            stop.clone(),
        ));

        tokio::spawn(stun::refresh_loop(
            state.clone(),
            state.cfg.read().await.stun_refresh_interval,
            stop.clone(),
        ));

        tokio::spawn(route::ringbuf_consumer(route_mgr.clone(), bpf.clone(), stop.clone()));

        tokio::spawn(route::discovery_loop(
            state.clone(),
            route_mgr.clone(),
            bpf.clone(),
            Some(self.kad_tx),
            stop.clone(),
        ));

        if let Some(ipsec) = self.ipsec_mgr {
            tokio::spawn(ipsec::ipsec_loop(state.clone(), ipsec, stop.clone()));
        }

        // Unstable P2P Kademlia — re-enable when libp2p 0.54 API stabilized
        // if let Some(p2p) = self.p2p {
        //     tokio::spawn(kademlia::kademlia_loop(state.clone(), p2p, self.kad_rx, stop.clone()));
        // }

        if state.cfg.read().await.vip_enabled {
            let monitor = Arc::new(vip::VipMonitor::new());
            tokio::spawn(vip::probe_loop(state, monitor, bpf, stop));
        }
    }
}
