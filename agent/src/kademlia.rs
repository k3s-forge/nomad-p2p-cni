use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    core::{upgrade, Transport},
    identify, identity, kad,
    gossipsub, noise, ping,
    swarm::{self, NetworkBehaviour, SwarmEvent},
    tcp, yamux,
    Multiaddr, PeerId,
};
use tokio::sync::RwLock;

use crate::AgentState;

const GOSSIP_TOPIC: &str = "nomad-p2p/config";

pub struct P2pNetwork {
    pub swarm: swarm::Swarm<P2pBehaviour>,
}

#[derive(NetworkBehaviour)]
pub struct P2pBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

pub async fn build_p2p(
    state: &Arc<AgentState>,
    seed_addrs: &[String],
) -> Result<P2pNetwork> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    let tcp_trans = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let noise_keys = noise::Config::new(&local_key).map_err(|e| anyhow::anyhow!("noise: {}", e))?;
    let transport = tcp_trans
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise_keys)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .boxed();

    let store = kad::store::MemoryStore::new(local_peer_id);
    let mut kad_cfg = kad::Config::default();
    kad_cfg.set_query_timeout(Duration::from_secs(10));
    let kademlia = kad::Behaviour::new(local_peer_id, store, kad_cfg);

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .mesh_n(6)
        .mesh_n_low(4)
        .mesh_n_high(12)
        .history_length(5)
        .history_gossip(3)
        .build()
        .map_err(|e| anyhow::anyhow!("gossipsub: {}", e))?;
    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    ).map_err(|e| anyhow::anyhow!("gossipsub: {}", e))?;
    gossipsub.subscribe(&gossipsub::IdentTopic::new(GOSSIP_TOPIC)).map_err(|e| anyhow::anyhow!("subscribe: {}", e))?;

    let identify = identify::Behaviour::new(
        identify::Config::new("/nomad-p2p/identify/1.0.0".to_string(), local_key.public())
            .with_push_listen_addr_updates(true)
            .with_interval(Duration::from_secs(60)),
    );

    let ping = ping::Behaviour::new(ping::Config::new()
        .with_interval(Duration::from_secs(30)));

    let behaviour = P2pBehaviour {
        kademlia,
        gossipsub,
        identify,
        ping,
    };

    let mut swarm = swarm::Swarm::new(transport, behaviour, local_peer_id, swarm::Config::with_tokio_executor());

    let listen_port = state.cfg.read().await.p2p_port;
    if listen_port > 0 {
        swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", listen_port).parse()?)?;
    }

    for seed in seed_addrs {
        if let Ok(addr) = seed.parse::<Multiaddr>() {
            let _ = swarm.dial(addr);
        }
    }

    Ok(P2pNetwork { swarm })
}

pub async fn kademlia_loop(
    state: Arc<AgentState>,
    mut p2p: P2pNetwork,
    mut kad_rx: tokio::sync::mpsc::UnboundedReceiver<u32>,
    stop: Arc<AtomicBool>,
) {
    let mut bootstrap_interval = tokio::time::interval(Duration::from_secs(60));
    bootstrap_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = bootstrap_interval.tick() => {
                if stop.load(Ordering::SeqCst) { return; }
                let _ = p2p.swarm.behaviour_mut().kademlia.bootstrap();

                let public_ip = *state.public_ip.read().await;
                let public_port = *state.public_port.read().await;

                let record = kad::Record {
                    key: kad::RecordKey::new(&state.cfg.read().await.node_overlay_ip),
                    value: serde_json::json!({
                        "public_ip": public_ip.to_string(),
                        "public_port": public_port,
                        "overlay_ip": state.cfg.read().await.node_overlay_ip,
                        "subnet": state.cfg.read().await.node_subnet,
                    }).to_string().into_bytes(),
                    publisher: None,
                    expires: None,
                };
                p2p.swarm.behaviour_mut().kademlia.put_record(record, kad::Quorum::One).ok();
            }
            overlay_ip = kad_rx.recv() => {
                if let Some(ip) = overlay_ip {
                    let key = kad::RecordKey::new(&ip.to_be_bytes());
                    let _ = p2p.swarm.behaviour_mut().kademlia.get_record(key);
                }
            }
            event = p2p.swarm.next() => {
                match event {
                    Some(SwarmEvent::Behaviour(P2pBehaviourEvent::Kademlia(
                        kad::Event::OutboundQueryCompleted { result, .. }
                    ))) => {
                        match result {
                            kad::QueryResult::GetRecord(Ok(ok)) => {
                                for record in &ok.records {
                                    if let Ok(value) = String::from_utf8(record.record.value.clone()) {
                                        tracing::info!("Kad GET: {}", value);
                                    }
                                }
                            }
                            kad::QueryResult::PutRecord(Ok(_)) => {
                                tracing::debug!("Kad PUT succeeded");
                            }
                            _ => {}
                        }
                    }
                    Some(SwarmEvent::Behaviour(P2pBehaviourEvent::Identify(
                        identify::Event::Received { info, .. }
                    ))) => {
                        tracing::info!("identified peer: {:?}", info.public_key);
                    }
                    Some(SwarmEvent::Behaviour(P2pBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. }
                    ))) => {
                        if let Ok(text) = String::from_utf8(message.data) {
                            tracing::info!("gossip: {}", text);
                        }
                    }
                    Some(SwarmEvent::NewListenAddr { address, .. }) => {
                        tracing::info!("listening on {}", address);
                    }
                    Some(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                        tracing::info!("connected to {}", peer_id);
                    }
                    Some(SwarmEvent::ConnectionClosed { peer_id, .. }) => {
                        tracing::info!("disconnected from {}", peer_id);
                    }
                    _ => {}
                }
            }
        }
        if stop.load(Ordering::SeqCst) { return; }
    }
}