use std::sync::Arc;

use notify::Watcher;
use tokio::sync::watch;

use crate::AgentState;

pub async fn watch_loop(
    state: Arc<AgentState>,
    mut stop: watch::Receiver<bool>,
) {
    let config_path = std::path::Path::new(&state.cfg.seeds[0].addr);
    let _ = config_path;

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let mut watcher = match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        let _ = tx.blocking_send(res.map(|_| ()).map_err(|e| e.to_string()));
    }) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("file watcher not available: {}", e);
            return;
        }
    };

    if let Err(e) = watcher.watch(
        std::path::Path::new("/etc/nomad-p2p/config.json"),
        notify::RecursiveMode::NonRecursive,
    ) {
        tracing::warn!("watch config failed: {}", e);
        return;
    }

    loop {
        tokio::select! {
            _ = stop.changed() => return,
            Some(result) = rx.recv() => {
                match result {
                    Ok(()) => {
                        tracing::info!("config file changed, reloading...");
                        // TODO: reload config and update BPF maps
                    }
                    Err(e) => {
                        tracing::warn!("watch error: {}", e);
                    }
                }
            }
        }
    }
}
