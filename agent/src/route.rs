use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::RwLock;

use crate::AgentState;

const BATCH_INTERVAL_MS: u64 = 100;
const COOLDOWN_SECS: u64 = 5;
const MAX_PENDING: usize = 4096;

pub struct RouteManager {
    pub pending: Arc<RwLock<Vec<u32>>>,
    pub cooldowns: Arc<RwLock<HashMap<u32, Instant>>>,
}

impl RouteManager {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(RwLock::new(Vec::with_capacity(1024))),
            cooldowns: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn submit_miss(&self, overlay_ip: u32) {
        let pending_len = self.pending.read().await.len();
        if pending_len >= MAX_PENDING {
            return;
        }
        let mut pending = self.pending.write().await;
        pending.push(overlay_ip);
    }

    pub async fn drain_batch(&self) -> Vec<u32> {
        let now = Instant::now();
        let mut cooldowns = self.cooldowns.write().await;

        // Clean expired cooldowns
        cooldowns.retain(|_, expires| *expires > now);

        let mut batch = Vec::new();
        let mut pending = self.pending.write().await;
        for ip in pending.drain(..) {
            if cooldowns.contains_key(&ip) {
                continue;
            }
            cooldowns.insert(ip, now + Duration::from_secs(COOLDOWN_SECS));
            batch.push(ip);
        }
        batch
    }
}

pub async fn discovery_loop(
    state: Arc<AgentState>,
    route_mgr: Arc<RouteManager>,
    stop: Arc<AtomicBool>,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(BATCH_INTERVAL_MS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if stop.load(Ordering::SeqCst) { return; }
        interval.tick().await;
        if stop.load(Ordering::SeqCst) { return; }

        let batch = route_mgr.drain_batch().await;
        if batch.is_empty() {
            continue;
        }

        for overlay_ip in &batch {
            tracing::info!("route miss for overlay IP {:08x}", overlay_ip);
            // TODO: query Kademlia DHT for peer endpoint
            let _ = &state;
        }

        if batch.len() > 1 {
            tracing::debug!("batched {} route misses", batch.len());
        }
    }
}

pub async fn ringbuf_consumer(
    route_mgr: Arc<RouteManager>,
    bpf: Arc<std::sync::Mutex<crate::bpf::BpfManager>>,
    stop: Arc<AtomicBool>,
) {
    loop {
        if stop.load(Ordering::SeqCst) { return; }

        let result = tokio::task::spawn_blocking({
            let bpf = bpf.clone();
            move || {
                let bpf = bpf.lock().unwrap();
                if let Some(ref mut ringbuf) = bpf.maps.route_miss_ringbuf.as_mut() {
                    match ringbuf.next() {
                        Some(data) => {
                            if data.len() >= 4 {
                                let ip = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                                return Some(ip);
                            }
                        }
                        None => {}
                    }
                }
                None
            }
        })
        .await;

        match result {
            Ok(Some(overlay_ip)) => {
                route_mgr.submit_miss(overlay_ip).await;
            }
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(e) => {
                tracing::error!("ringbuf task panicked: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
