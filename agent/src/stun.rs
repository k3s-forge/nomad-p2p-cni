use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use tokio::net::UdpSocket;

use nomad_p2p_common::NatType;

use crate::AgentState;

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

pub struct StunResult {
    pub public_ip: std::net::Ipv4Addr,
    pub public_port: u16,
}

pub async fn query(server: &str, timeout: std::time::Duration) -> Result<StunResult> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let remote: std::net::SocketAddr = server.parse()?;
    socket.connect(remote).await?;

    let mut req = vec![0u8; 20];
    let binding_type = 0x0001u16; // Binding Request
    req[..2].copy_from_slice(&binding_type.to_be_bytes());
    req[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    // transaction ID (12 bytes)
    for i in 0..12 {
        req[8 + i] = (i + 1) as u8;
    }

    tokio::time::timeout(timeout, async {
        socket.send(&req).await?;
        let mut buf = vec![0u8; 1024];
        let n = socket.recv(&mut buf).await?;
        parse_stun_response(&buf[..n])
    })
    .await?
}

pub async fn query_from_conn(
    conn: &UdpSocket,
    server: &str,
    timeout: std::time::Duration,
) -> Result<StunResult> {
    let remote: std::net::SocketAddr = server.parse()?;

    let mut req = vec![0u8; 20];
    let binding_type = 0x0001u16;
    req[..2].copy_from_slice(&binding_type.to_be_bytes());
    req[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    for i in 0..12 {
        req[8 + i] = (i + 2) as u8;
    }

    tokio::time::timeout(timeout, async {
        conn.send_to(&req, remote).await?;
        let mut buf = vec![0u8; 1024];
        let (n, _) = conn.recv_from(&mut buf).await?;
        parse_stun_response(&buf[..n])
    })
    .await?
}

fn parse_stun_response(data: &[u8]) -> Result<StunResult> {
    if data.len() < 20 {
        anyhow::bail!("too short");
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != 0x0101 {
        anyhow::bail!("not binding response");
    }

    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let mut off = 20;
    while off + 4 <= 20 + len {
        let attr_type = u16::from_be_bytes([data[off], data[off + 1]]);
        let attr_len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
        if (attr_type == 0x0001 || attr_type == 0x0020) && attr_len >= 8 {
            let port = u16::from_be_bytes([data[off + 4], data[off + 5]]);
            let ip = std::net::Ipv4Addr::new(
                data[off + 6], data[off + 7], data[off + 8], data[off + 9],
            );
            if attr_type == 0x0020 {
                // RFC 5389 S15.2: byte-wise XOR with magic cookie 0x2112A442
                // XOR port: high 16 bits of magic cookie = 0x2112
                let port = port ^ 0x2112u16;
                let ip = std::net::Ipv4Addr::new(
                    data[off + 6] ^ 0x21,
                    data[off + 7] ^ 0x12,
                    data[off + 8] ^ 0xA4,
                    data[off + 9] ^ 0x42,
                );
                return Ok(StunResult { public_ip: ip, public_port: port });
            }
            return Ok(StunResult { public_ip: ip, public_port: port });
        }
        off += 4 + attr_len;
        if attr_len % 4 != 0 {
            off += 4 - (attr_len % 4);
        }
    }
    anyhow::bail!("no mapped address")
}

pub async fn detect_nat_type(servers: &[String], timeout: std::time::Duration) -> NatType {
    if servers.len() < 2 {
        return NatType::Unknown;
    }

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return NatType::Unknown,
    };

    let first = query_from_conn(&socket, &servers[0], timeout).await;
    let second = query_from_conn(&socket, &servers[1], timeout).await;

    match (&first, &second) {
        (Ok(a), Ok(b)) => {
            if a.public_port != b.public_port {
                tracing::info!("symmetric NAT detected: port {} vs {}", a.public_port, b.public_port);
                NatType::Symmetric
            } else {
                tracing::info!("easy NAT: port {}", a.public_port);
                NatType::Easy
            }
        }
        _ => {
            let fallback = first.as_ref().ok().or(second.as_ref().ok());
            if let Some(r) = fallback {
                tracing::info!("single STUN result: {}:{}", r.public_ip, r.public_port);
            }
            NatType::Unknown
        }
    }
}

pub async fn discover(state: &Arc<AgentState>) -> Result<()> {
    let servers = &state.cfg.read().await.stun_servers;
    if servers.is_empty() {
        tracing::info!("no STUN servers configured, using overlay IP");
        *state.public_ip.write().await = state.cfg.read().await.node_overlay_ip.parse()?;
        return Ok(());
    }

    let timeout = std::time::Duration::from_secs(3);
    match query(&servers[0], timeout).await {
        Ok(result) => {
            *state.public_ip.write().await = result.public_ip;
            *state.public_port.write().await = result.public_port;
            tracing::info!("STUN discovered: {}:{}", result.public_ip, result.public_port);
        }
        Err(e) => {
            tracing::warn!("STUN failed: {}, using overlay IP", e);
            *state.public_ip.write().await = state.cfg.read().await.node_overlay_ip.parse()?;
        }
    }

    let nat = detect_nat_type(servers, timeout).await;
    *state.nat_type.write().await = nat;

    Ok(())
}

pub async fn refresh_loop(
    state: Arc<AgentState>,
    interval_secs: u64,
    stop: Arc<AtomicBool>,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    loop {
        if stop.load(Ordering::SeqCst) { return; }
        tokio::select! {
            _ = interval.tick() => {
                if stop.load(Ordering::SeqCst) { return; }
                let old_ip = *state.public_ip.read().await;
                let old_port = *state.public_port.read().await;
                discover(&state).await.ok();
                let new_ip = *state.public_ip.read().await;
                let new_port = *state.public_port.read().await;
                if old_ip != new_ip || old_port != new_port {
                    tracing::info!("public endpoint changed: {}:{} -> {}:{}",
                        old_ip, old_port, new_ip, new_port);
                }
            }
        }
    }
}
