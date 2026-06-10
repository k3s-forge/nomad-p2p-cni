use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::SocketAddr;

use tokio::io::AsyncWriteExt;

use crate::AgentState;

pub async fn serve(
    state: Arc<AgentState>,
    port: u16,
    stop: Arc<AtomicBool>,
) {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("metrics server bind failed: {}", e);
            return;
        }
    };
    tracing::info!("metrics server on {}", port);

    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }

        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                if stop.load(Ordering::SeqCst) { return; }
            }
            result = listener.accept() => {
                if let Ok((mut stream, _)) = result {
                    tokio::spawn(async move {
                        let response = concat!(
                            "HTTP/1.1 200 OK\r\n",
                            "Content-Type: text/plain; version=0.0.4\r\n\r\n",
                            "# HELP nomad_p2p_uptime_seconds Agent uptime\n",
                            "# TYPE nomad_p2p_uptime_seconds gauge\n",
                            "nomad_p2p_uptime_seconds 0\n",
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
            }
        }
    }
}
