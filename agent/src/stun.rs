use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use nomad_p2p_common::NatType;

use crate::AgentState;
use crate::protocol::UdpProtocol;

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
    pub conns: Arc<RwLock<Vec<(String, SocketAddr)>>>,
    pub seed_mode: bool,
    proto: Arc<tokio::sync::Mutex<UdpProtocol>>,
}

impl SeedClient {
    pub fn new(seed_mode: bool, proto: Arc<tokio::sync::Mutex<UdpProtocol>>) -> Self {
        Self {
            conns: Arc::new(RwLock::new(Vec::new())),
            seed_mode,
            proto,
        }
    }

    pub async fn register_all(&self, state: &Arc<AgentState>) {
        for seed in &state.cfg.read().await.seeds {
            if let Ok(addr) = seed.addr.parse::<SocketAddr>() {
                if let Err(e) = self.register(state, addr).await {
                    tracing::warn!("failed to register with seed {}: {}", seed.addr, e);
                }
            }
        }
    }

    pub async fn register(&self, state: &Arc<AgentState>, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let public_ip = *state.public_ip.read().await;
        let public_port = *state.public_port.read().await;
        let nat_type = *state.nat_type.read().await;

        let msg = Message {
            msg_type: "register".into(),
            qid: Some(format!("{:016x}", rand::random::<u64>())),
            ts: now_ts(),
            nonce: format!("{:016x}", rand::random::<u64>()),
            node_info: Some(NodeRegistration {
                overlay_ip: state.cfg.read().await.node_overlay_ip.clone(),
                public_ip: public_ip.to_string(),
                public_port,
                subnet: state.cfg.read().await.node_subnet.clone(),
                relay_capable: false,
                nat_type,
            }),
            query_ip: None,
            nodes: None,
            relay: None,
        };

        let mut proto = self.proto.lock().await;
        proto.send_to(&msg, &addr).await?;
        tracing::info!("registered with seed {}", addr);

        let mut conns = self.conns.write().await;
        conns.push((addr.to_string(), addr));

        Ok(())
    }

    pub async fn query_peer(&self, overlay_ip: &str, addr: SocketAddr) -> Option<Vec<NodeRegistration>> {
        let msg = Message {
            msg_type: "query".into(),
            qid: Some(format!("{:016x}", rand::random::<u64>())),
            ts: now_ts(),
            nonce: format!("{:016x}", rand::random::<u64>()),
            node_info: None,
            query_ip: Some(overlay_ip.to_string()),
            nodes: None,
            relay: None,
        };

        let mut proto = self.proto.lock().await;
        if proto.send_to(&msg, &addr).await.is_err() {
            tracing::warn!("failed to query seed {} for {}", addr, overlay_ip);
            return None;
        }
        drop(proto);

        tracing::info!("queried seed {} for peer {}", addr, overlay_ip);
        None
    }
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub async fn health_loop(
    state: Arc<AgentState>,
    client: Arc<tokio::sync::Mutex<SeedClient>>,
    proto: Arc<tokio::sync::Mutex<UdpProtocol>>,
    stop: Arc<AtomicBool>,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
    loop {
        if stop.load(Ordering::SeqCst) { return; }
        interval.tick().await;
        if stop.load(Ordering::SeqCst) { return; }

        let client = client.lock().await;
        client.register_all(&state).await;
    }
}