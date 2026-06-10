use std::sync::mpsc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use notify::{DebouncedEvent, RecursiveMode, Watcher};

use crate::AgentState;

pub async fn watch_loop(
    state: Arc<AgentState>,
    stop: Arc<AtomicBool>,
) {
    let (tx, rx) = mpsc::channel();

    let mut watcher = match notify::watcher(tx, Duration::from_secs(2)) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("file watcher not available: {}", e);
            return;
        }
    };

    if let Err(e) = watcher.watch(
        std::path::Path::new("/etc/nomad-p2p/config.json"),
        RecursiveMode::NonRecursive,
    ) {
        tracing::warn!("watch config failed: {}", e);
        return;
    }

    loop {
        if stop.load(Ordering::SeqCst) { return; }

        if let Ok(event) = rx.recv_timeout(Duration::from_millis(200)) {
            match event {
                DebouncedEvent::Write(_) | DebouncedEvent::Create(_) => {
                    tracing::info!("config file changed, reloading...");
                    let _ = &state;
                    // TODO: reload config and update BPF maps
                }
                _ => {}
            }
        }

        if stop.load(Ordering::SeqCst) { return; }
    }
}
