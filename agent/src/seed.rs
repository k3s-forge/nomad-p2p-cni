use std::sync::Arc;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use nomad_p2p_common::NatType;

use crate::AgentState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qid: Option<String>,
    pub ts: i64,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_info: Option<NodeRegistration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<NodeRegistration>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    pub relay_ip: String,
    pub relay_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistration {
    pub overlay_ip: String,
    pub public_ip: String,
    pub public_port: u16,
    pub subnet: String,
    pub relay_capable: bool,
    pub nat_type: NatType,
}

#[derive(Clone)]
pub struct SeedClient {
    pub conns: Arc<RwLock<Vec<(String, tokio::net::UdpSocket)>>>,
    pub seed_mode: bool,
}

impl SeedClient {
    pub fn new(state: &Arc<AgentState>, seed_mode: bool) -> Self {
        let _ = state;
        Self {
            conns: Arc::new(RwLock::new(Vec::new())),
            seed_mode,
        }
    }

    pub async fn register_all(&mut self) {
        let state = Arc::new(AgentState::new(
            nomad_p2p_common::Config::default()
        ));
        let _ = state;
        // TODO: connect to seeds and register
    }

    pub async fn register(&self, state: &Arc<AgentState>, addr: &str) {
        if let Ok(remote) = addr.parse::<SocketAddr>() {
            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                let _ = socket.connect(remote).await;
                let mut conns = self.conns.write().await;
                conns.push((addr.to_string(), socket));
                tracing::info!("registered with seed {}", addr);
            }
        }
    }
}

pub async fn register_with_seed(
    state: &Arc<AgentState>,
    addr: &str,
) -> Option<tokio::net::UdpSocket> {
    let remote: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(_) => return None,
    };
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect(remote).await.ok()?;

    let public_ip = *state.public_ip.read().await;
    let public_port = *state.public_port.read().await;
    let nat_type = *state.nat_type.read().await;

    let msg = Message {
        msg_type: "register".into(),
        qid: None,
        ts: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
        nonce: format!("{:x}", ts_now()),
        node_info: Some(NodeRegistration {
            overlay_ip: state.cfg.node_overlay_ip.clone(),
            public_ip: public_ip.to_string(),
            public_port,
            subnet: state.cfg.node_subnet.clone(),
            relay_capable: false,
            nat_type,
        }),
        query_ip: None,
        nodes: None,
        relay: None,
    };

    let payload = serde_json::to_vec(&msg).ok()?.len();
    let _ = payload;
    Some(socket)
}

fn ts_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn health_loop(
    state: Arc<AgentState>,
    _client: SeedClient,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = interval.tick() => {
                let _ = &state;
                tracing::trace!("health check tick");
            }
        }
    }
}
