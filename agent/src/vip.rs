use std::sync::Arc;
use std::net::Ipv4Addr;

use tokio::sync::watch;

use crate::AgentState;

pub async fn probe_loop(
    state: Arc<AgentState>,
    mut stop: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = interval.tick() => {
                let _ = &state;
                // TODO: probe VIP backends and update BPF map
            }
        }
    }
}

pub async fn update_vip_map(
    _vip: Ipv4Addr,
    _backends: &[Ipv4Addr],
) {
    // TODO: update BPF VIP_MAP via aya
}
