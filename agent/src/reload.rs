use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use notify::{Event, EventKind, RecursiveMode, Watcher};

use crate::AgentState;

pub async fn watch_loop(
    state: Arc<AgentState>,
    stop: Arc<AtomicBool>,
) {
    let (tx, rx) = std::sync::mpsc::channel();

    let mut watcher = match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            let _ = tx.send(event);
        }
    }) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("file watcher not available: {}", e);
            return;
        }
    };

    let config_path = "/etc/nomad-p2p/config.json";
    if let Err(e) = watcher.watch(
        std::path::Path::new(config_path),
        RecursiveMode::NonRecursive,
    ) {
        tracing::warn!("watch config failed: {}", e);
        return;
    }

    loop {
        if stop.load(Ordering::SeqCst) { return; }

        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(event) => {
                match event.kind {
                    EventKind::Modify(_) | EventKind::Create(_) => {
                        tracing::info!("config file changed, reloading...");
                        match reload_config(&state).await {
                            Ok(()) => tracing::info!("config reloaded successfully"),
                            Err(e) => tracing::warn!("config reload failed: {}", e),
                        }
                    }
                    EventKind::Remove(_) => {
                        tracing::debug!("config file removed");
                    }
                    _ => {}
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if stop.load(Ordering::SeqCst) { return; }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                tracing::warn!("file watcher disconnected");
                return;
            }
        }
    }
}

async fn reload_config(state: &Arc<AgentState>) -> Result<(), String> {
    let data = std::fs::read_to_string("/etc/nomad-p2p/config.json")
        .map_err(|e| format!("read config: {}", e))?;
    let new_cfg: crate::AgentConfig = serde_json::from_str(&data)
        .map_err(|e| format!("parse config: {}", e))?;

    let mut cfg = state.cfg.write().await;

    if cfg.stun_servers != new_cfg.stun_servers {
        tracing::info!("STUN servers updated: {:?}", new_cfg.stun_servers);
        cfg.stun_servers = new_cfg.stun_servers;
    }

    if cfg.vip_enabled != new_cfg.vip_enabled {
        tracing::info!("VIP enabled changed: {} -> {}", cfg.vip_enabled, new_cfg.vip_enabled);
        cfg.vip_enabled = new_cfg.vip_enabled;
    }

    if cfg.ipsec_enabled != new_cfg.ipsec_enabled {
        tracing::info!("IPsec enabled changed: {} -> {}", cfg.ipsec_enabled, new_cfg.ipsec_enabled);
        cfg.ipsec_enabled = new_cfg.ipsec_enabled;
    }

    if cfg.firewall_enabled != new_cfg.firewall_enabled {
        tracing::info!("firewall enabled changed: {} -> {}", cfg.firewall_enabled, new_cfg.firewall_enabled);
        cfg.firewall_enabled = new_cfg.firewall_enabled;
    }

    if cfg.metrics_port != new_cfg.metrics_port {
        tracing::info!("metrics port changed: {} -> {}", cfg.metrics_port, new_cfg.metrics_port);
        cfg.metrics_port = new_cfg.metrics_port;
    }

    Ok(())
}