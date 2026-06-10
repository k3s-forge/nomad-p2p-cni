use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use tokio::process::Command;

use crate::AgentState;

pub struct IpsecManager {
    pub spi: u32,
    pub key: Vec<u8>,
    pub peers: Vec<(String, String)>,
}

impl IpsecManager {
    pub fn new(spi: u32, key: &str) -> Self {
        let key_bytes = if key.is_empty() {
            Self::generate_key()
        } else if let Ok(decoded) = hex::decode(key) {
            decoded
        } else {
            key.as_bytes().to_vec()
        };
        Self {
            spi,
            key: key_bytes,
            peers: Vec::new(),
        }
    }

    fn generate_key() -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..32).map(|_| rng.gen::<u8>()).collect()
    }

    pub async fn add_state(&self, src: &str, dst: &str) -> Result<()> {
        let key_hex = hex::encode(&self.key);

        // Add inbound state
        let status = Command::new("ip")
            .args([
                "xfrm", "state", "add",
                "src", src,
                "dst", dst,
                "proto", "esp",
                "spi", &format!("{:08x}", self.spi),
                "reqid", &format!("{}", self.spi),
                "mode", "tunnel",
                "auth", "sha256", &key_hex,
                "enc", "aes", &key_hex,
            ])
            .status()
            .await?;
        if !status.success() {
            anyhow::bail!("ip xfrm state add (in) failed for {} -> {}", src, dst);
        }

        // Add outbound state
        let status = Command::new("ip")
            .args([
                "xfrm", "state", "add",
                "src", dst,
                "dst", src,
                "proto", "esp",
                "spi", &format!("{:08x}", self.spi),
                "reqid", &format!("{}", self.spi),
                "mode", "tunnel",
                "auth", "sha256", &key_hex,
                "enc", "aes", &key_hex,
            ])
            .status()
            .await?;
        if !status.success() {
            anyhow::bail!("ip xfrm state add (out) failed for {} -> {}", src, dst);
        }

        tracing::info!("IPsec state added: {} <-> {}", src, dst);
        Ok(())
    }

    pub async fn add_policy(&self, src_subnet: &str, dst_subnet: &str, tunnel_src: &str, tunnel_dst: &str) -> Result<()> {
        let status = Command::new("ip")
            .args([
                "xfrm", "policy", "add",
                "src", src_subnet,
                "dst", dst_subnet,
                "dir", "out",
                "tmpl", "src", tunnel_src,
                "dst", tunnel_dst,
                "proto", "esp",
                "mode", "tunnel",
                "reqid", &format!("{}", self.spi),
            ])
            .status()
            .await?;
        if !status.success() {
            anyhow::bail!("ip xfrm policy add (out) failed for {} -> {}", src_subnet, dst_subnet);
        }

        let status = Command::new("ip")
            .args([
                "xfrm", "policy", "add",
                "src", dst_subnet,
                "dst", src_subnet,
                "dir", "in",
                "tmpl", "src", tunnel_dst,
                "dst", tunnel_src,
                "proto", "esp",
                "mode", "tunnel",
                "reqid", &format!("{}", self.spi),
            ])
            .status()
            .await?;
        if !status.success() {
            anyhow::bail!("ip xfrm policy add (in) failed for {} -> {}", dst_subnet, src_subnet);
        }

        tracing::info!("IPsec policy added: {} <-> {}", src_subnet, dst_subnet);
        Ok(())
    }

    pub async fn delete_state(&self, src: &str, dst: &str) -> Result<()> {
        let _ = Command::new("ip")
            .args(["xfrm", "state", "del", "src", src, "dst", dst, "spi", &format!("{:08x}", self.spi), "proto", "esp"])
            .status().await;
        let _ = Command::new("ip")
            .args(["xfrm", "state", "del", "src", dst, "dst", src, "spi", &format!("{:08x}", self.spi), "proto", "esp"])
            .status().await;
        Ok(())
    }

    pub async fn delete_policy(&self, src_subnet: &str, dst_subnet: &str, dir: &str) -> Result<()> {
        let _ = Command::new("ip")
            .args(["xfrm", "policy", "del", "src", src_subnet, "dst", dst_subnet, "dir", dir])
            .status().await;
        Ok(())
    }

    pub async fn rotate_key(&mut self) -> Result<()> {
        let old_spi = self.spi;
        self.spi = self.spi.wrapping_add(1);
        self.key = Self::generate_key();

        tracing::info!("IPsec key rotation: old spi={:08x} new spi={:08x}", old_spi, self.spi);

        for (src, dst) in &self.peers {
            if let Err(e) = self.add_state(src, dst).await {
                tracing::warn!("failed to re-apply XFRM state for {} <-> {}: {}", src, dst, e);
            }
        }

        Ok(())
    }

    pub fn add_peer(&mut self, src: String, dst: String) {
        if !self.peers.contains(&(src.clone(), dst.clone())) {
            self.peers.push((src, dst));
        }
    }
}

pub async fn ipsec_loop(
    state: Arc<AgentState>,
    ipsec: Arc<std::sync::Mutex<IpsecManager>>,
    stop: Arc<AtomicBool>,
) {
    if !state.cfg.read().await.ipsec_enabled {
        return;
    }

    let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Rotate every hour
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if stop.load(Ordering::SeqCst) { return; }
        interval.tick().await;
        if stop.load(Ordering::SeqCst) { return; }

        {
            let mut guard = ipsec.lock().unwrap();
            guard.spi = guard.spi.wrapping_add(1);
            guard.key = IpsecManager::generate_key();
            tracing::info!("IPsec key rotation: spi={:08x}", guard.spi);
        }
    }
}
