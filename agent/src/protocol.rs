use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use serde::Serialize;
use tokio::net::UdpSocket;

use nomad_p2p_common::{HEADER_SIZE, HMAC_SIZE, MIN_MESSAGE_SIZE, REPLAY_WINDOW_SECS};

use crate::bpf;

type HmacSha256 = Hmac<Sha256>;

pub struct UdpProtocol {
    pub socket: UdpSocket,
    psk: Vec<u8>,
    nonces: Vec<(String, u64)>,
}

impl UdpProtocol {
    pub async fn bind(port: u16, psk: &str) -> Result<Self> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).await?;
        tracing::info!("UDP protocol bound to port {}", port);
        Ok(Self {
            socket,
            psk: psk.as_bytes().to_vec(),
            nonces: Vec::with_capacity(4096),
        })
    }

    pub fn marshal(&self, msg: &impl Serialize) -> Vec<u8> {
        let payload = serde_json::to_vec(msg).unwrap_or_default();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut header = [0u8; HEADER_SIZE];
        header[..8].copy_from_slice(&now.to_be_bytes());

        let mut nonce_bytes = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        header[8..].copy_from_slice(&nonce_bytes);

        let signed = [&header[..], &payload[..]].concat();
        let sig = self.sign(&signed);

        [&signed[..], &sig[..]].concat()
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.psk).expect("HMAC key");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.psk).expect("HMAC key");
        mac.update(data);
        mac.verify_slice(sig).is_ok()
    }

    fn check_nonce(&mut self, header: &[u8; HEADER_SIZE]) -> bool {
        let ts = u64::from_be_bytes(header[..8].try_into().unwrap_or([0u8; 8]));
        let nonce = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            header[8], header[9], header[10], header[11],
            header[12], header[13], header[14], header[15]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if ts.abs_diff(now) > REPLAY_WINDOW_SECS {
            return false;
        }

        let cutoff = now.saturating_sub(REPLAY_WINDOW_SECS);
        self.nonces.retain(|(_, t)| *t > cutoff);
        if self.nonces.iter().any(|(n, _)| *n == nonce) {
            return false;
        }
        self.nonces.push((nonce, now));
        true
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr)> {
        const MAX_RECV_ATTEMPTS: u32 = 16;
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            if attempts > MAX_RECV_ATTEMPTS {
                tokio::task::yield_now().await;
                attempts = 0;
            }
            let (n, addr) = self.socket.recv_from(buf).await?;
            if n < MIN_MESSAGE_SIZE {
                continue;
            }

            let header_raw = &buf[..HEADER_SIZE];
            let header: &[u8; HEADER_SIZE] = header_raw.try_into().unwrap_or(&[0u8; HEADER_SIZE]);
            let payload = &buf[HEADER_SIZE..n - HMAC_SIZE];
            let sig = &buf[n - HMAC_SIZE..n];

            if !self.verify(&[header_raw, payload].concat(), sig) {
                tracing::debug!("HMAC verify failed from {}", addr);
                continue;
            }

            if !self.check_nonce(header) {
                tracing::debug!("replay rejected from {}", addr);
                continue;
            }

            return Ok((n, addr));
        }
    }

    pub async fn send_to(&self, msg: &impl Serialize, addr: &std::net::SocketAddr) -> Result<()> {
        let data = self.marshal(msg);
        self.socket.send_to(&data, addr).await?;
        Ok(())
    }
}

pub async fn recv_loop(
    proto: Arc<tokio::sync::Mutex<UdpProtocol>>,
    bpf: Arc<std::sync::Mutex<bpf::BpfManager>>,
    stop: Arc<AtomicBool>,
) {
    let mut buf = vec![0u8; 65535];
    tracing::info!("UDP recv loop started");

    loop {
        if stop.load(Ordering::SeqCst) { return; }

        let result = {
            let mut proto = proto.lock().await;
            tokio::select! {
                result = proto.recv(&mut buf) => result,
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                    continue;
                }
            }
        };

        match result {
            Ok((n, addr)) => {
                tracing::debug!("received {} bytes from {}", n, addr);
                // Process incoming peer messages - route updates, peer announcements, etc.
                // The payload is between HEADER_SIZE and (n - HMAC_SIZE)
                let payload = &buf[HEADER_SIZE..n.saturating_sub(HMAC_SIZE)];
                if let Ok(msg) = serde_json::from_slice::<serde_json::Value>(payload) {
                    if let Some(msg_type) = msg.get("type").and_then(|v| v.as_str()) {
                        match msg_type {
                            "register" => {
                                tracing::info!("peer registration from {}", addr);
                                // TODO: update BPF route map with peer info
                            }
                            "query" => {
                                tracing::debug!("peer query from {}", addr);
                                // Respond with known peer information
                            }
                            "announce" => {
                                tracing::debug!("peer announcement from {}", addr);
                                // Update route table
                            }
                            _ => {
                                tracing::trace!("unknown message type: {}", msg_type);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("UDP recv error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}