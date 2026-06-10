use std::sync::Arc;
use std::time::Duration;

use nomad_p2p_common::{NatType, PeerEndpoint};
use tokio::net::UdpSocket;

use crate::AgentState;
use crate::protocol::UdpProtocol;
use crate::seed::Message;

pub async fn try_relay(
    state: &Arc<AgentState>,
    target_ip: &str,
    proto: &Arc<tokio::sync::Mutex<UdpProtocol>>,
) -> Option<PeerEndpoint> {
    let seeds = state.cfg.read().await.seeds.clone();
    if seeds.is_empty() {
        return None;
    }

    for seed in seeds {
        if let Ok(addr) = seed.addr.parse::<std::net::SocketAddr>() {
            if let Some(relay) = query_seed_for_relay(proto, addr, target_ip).await {
                return Some(relay);
            }
        }
    }
    None
}

async fn query_seed_for_relay(
    proto: &Arc<tokio::sync::Mutex<UdpProtocol>>,
    seed_addr: std::net::SocketAddr,
    target_ip: &str,
) -> Option<PeerEndpoint> {
    let msg = Message {
        msg_type: "relay_query".into(),
        qid: Some(format!("{:016x}", rand::random::<u64>())),
        ts: now_ts(),
        nonce: format!("{:016x}", rand::random::<u64>()),
        node_info: None,
        query_ip: Some(target_ip.to_string()),
        nodes: None,
        relay: None,
    };

    let proto = proto.lock().await;
    if proto.send_to(&msg, &seed_addr).await.is_err() {
        return None;
    }
    drop(proto);

    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let mut buf = vec![0u8; 2048];
    let _ = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf)).await.ok()?;

    if let Ok(response) = serde_json::from_slice::<Message>(&buf) {
        if let Some(relay) = response.relay {
            if let Ok(ip) = relay.relay_ip.parse::<std::net::Ipv4Addr>() {
                return Some(PeerEndpoint {
                    public_ip: u32::from(ip),
                    port: relay.relay_port,
                    nat_type: NatType::Unknown as u8,
                    _pad: 0,
                });
            }
        }
    }
    None
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}