use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::net::UdpSocket;

use nomad_p2p_common::{Message, HEADER_SIZE, HMAC_SIZE, MIN_MESSAGE_SIZE, REPLAY_WINDOW_SECS};

type HmacSha256 = Hmac<Sha256>;

pub struct UdpProtocol {
    pub socket: UdpSocket,
    psk: Vec<u8>,
    nonces: Vec<(String, u64)>,
}

impl UdpProtocol {
    pub async fn bind(port: u16, psk: &str) -> Result<Self> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).await?;
        Ok(Self {
            socket,
            psk: psk.as_bytes().to_vec(),
            nonces: Vec::with_capacity(1024),
        })
    }

    pub fn marshal(&self, msg: &Message) -> Vec<u8> {
        let payload = serde_json::to_vec(msg).unwrap_or_default();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut header = [0u8; HEADER_SIZE];
        header[..8].copy_from_slice(&now.to_be_bytes());

        // random nonce
        for i in 0..8 {
            header[8 + i] = (now.wrapping_mul(i as u64 + 1) ^ 0xA5) as u8;
        }

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
        if header.len() < 16 {
            return false;
        }
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
        loop {
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

    pub async fn send_to(&self, msg: &Message, addr: &std::net::SocketAddr) -> Result<()> {
        let data = self.marshal(msg);
        self.socket.send_to(&data, addr).await?;
        Ok(())
    }
}
