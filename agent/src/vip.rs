use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::Ipv4Addr;

use crate::AgentState;

pub async fn probe_loop(
    state: Arc<AgentState>,
    stop: Arc<AtomicBool>,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    loop {
        if stop.load(Ordering::SeqCst) { return; }
        interval.tick().await;
        if stop.load(Ordering::SeqCst) { return; }
        let _ = &state;
        // TODO: probe VIP backends and update BPF map
    }
}

pub async fn update_vip_map(
    _vip: Ipv4Addr,
    _backends: &[Ipv4Addr],
) {
    // TODO: update BPF VIP_MAP via aya
}
