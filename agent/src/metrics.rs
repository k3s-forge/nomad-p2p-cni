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
        tokio::select! {
            result = listener.accept() => {
                if stop.load(Ordering::SeqCst) { return; }
                if let Ok((mut stream, _)) = result {
                    let state = state.clone();
                    tokio::spawn(async move {
                        let uptime = state.start_time.elapsed().as_secs();
                        let nat_type = *state.nat_type.read().await as u8;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n\r\n\
                             # HELP nomad_p2p_uptime_seconds Agent uptime\n\
                             # TYPE nomad_p2p_uptime_seconds gauge\n\
                             nomad_p2p_uptime_seconds {}\n\
                             # HELP nomad_p2p_nat_type NAT type (0=unknown 1=easy 2=symmetric)\n\
                             # TYPE nomad_p2p_nat_type gauge\n\
                             nomad_p2p_nat_type {}\n",
                            uptime, nat_type
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
            }
            _ = tokio::signal::ctrl_c() => { return; }
        }
    }
}