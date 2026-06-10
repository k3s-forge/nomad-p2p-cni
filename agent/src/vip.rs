use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::bpf;

const PROBE_INTERVAL_SECS: u64 = 2;

#[derive(Clone)]
pub struct BackendHealth {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub alive: bool,
}

pub struct VipMonitor {
    pub backends: Arc<RwLock<HashMap<String, Vec<BackendHealth>>>>,
}

impl VipMonitor {
    pub fn new() -> Self {
        Self {
            backends: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn set_backends(&self, vip: &str, backends: &[(Ipv4Addr, u16)]) {
        let mut map = self.backends.write().await;
        let health: Vec<BackendHealth> = backends.iter().map(|(ip, port)| BackendHealth {
            ip: *ip,
            port: *port,
            alive: true,
            last_check: Instant::now(),
        }).collect();
        map.insert(vip.to_string(), health);
    }

    pub async fn get_alive(&self, vip: &str) -> Vec<Ipv4Addr> {
        let map = self.backends.read().await;
        map.get(vip).map(|backends| {
            backends.iter()
                .filter(|b| b.alive)
                .map(|b| b.ip)
                .collect()
        }).unwrap_or_default()
    }

    async fn probe_backend(ip: Ipv4Addr, port: u16) -> bool {
        let addr = format!("{}:{}", ip, port);
        TcpStream::connect(&addr).await.is_ok()
    }
}

pub async fn probe_loop(
    state: Arc<crate::AgentState>,
    monitor: Arc<VipMonitor>,
    bpf: Arc<std::sync::Mutex<bpf::BpfManager>>,
    stop: Arc<AtomicBool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(PROBE_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Initialize from config
    for vc in &state.cfg.vip_backends {
        let backends: Vec<(Ipv4Addr, u16)> = vc.backends.iter()
            .filter_map(|s| {
                let parts: Vec<&str> = s.split(':').collect();
                let ip = parts[0].parse::<Ipv4Addr>().ok()?;
                let port = parts.get(1).and_then(|p| p.parse::<u16>().ok()).unwrap_or(80);
                Some((ip, port))
            })
            .collect();
        monitor.set_backends(&vc.vip, &backends).await;
    }

    loop {
        if stop.load(Ordering::SeqCst) { return; }
        interval.tick().await;
        if stop.load(Ordering::SeqCst) { return; }

        let vips = {
            let map = monitor.backends.read().await;
            map.keys().cloned().collect::<Vec<_>>()
        };

        for vip in &vips {
            let changed = {
                let map = monitor.backends.read().await;
                let mut changed = false;
                if let Some(backends) = map.get(vip) {
                    for backend in backends {
                        let alive = VipMonitor::probe_backend(backend.ip, backend.port).await;
                        if alive != backend.alive {
                            changed = true;
                            if alive {
                                tracing::info!("VIP {} backend {}:{} alive", vip, backend.ip, backend.port);
                            } else {
                                tracing::warn!("VIP {} backend {}:{} dead", vip, backend.ip, backend.port);
                            }
                        }
                    }
                }
                changed
            };

            if changed {
                // Update BPF VIP_MAP with alive backends
                let alive = monitor.get_alive(vip).await;
                if !alive.is_empty() {
                    if let Ok(vip_ip) = vip.parse::<Ipv4Addr>() {
                        if let Ok(bpf) = bpf.lock() {
                            update_bpf_vip(&*bpf, vip_ip, &alive).ok();
                        }
                    }
                }
            }
        }
    }
}

fn update_bpf_vip(bpf: &bpf::BpfManager, vip_ip: Ipv4Addr, backends: &[Ipv4Addr]) -> Result<()> {
    let mut vip_info = nomad_p2p_common::VipInfo::default();
    for (i, ip) in backends.iter().enumerate().take(16) {
        vip_info.backends[i] = nomad_p2p_common::VipBackend {
            ip: u32::from(*ip),
            port: 0u16.to_be(),
            weight: 1,
            _pad: 0,
        };
    }
    vip_info.count = backends.len().min(16) as u8;
    vip_info.next_idx = 0;

    if let Some(ref map) = bpf.maps.vip_map {
        map.insert(&u32::from(vip_ip), &vip_info, 0)?;
    }
    Ok(())
}
