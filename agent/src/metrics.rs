use std::sync::Arc;
use std::net::SocketAddr;

use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

use crate::AgentState;

pub async fn serve(
    state: Arc<AgentState>,
    port: u16,
    mut stop: watch::Receiver<bool>,
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
            _ = stop.changed() => {
                tracing::info!("metrics server stopped");
                return;
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
