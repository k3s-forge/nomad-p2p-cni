use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::bpf;

#[derive(Clone)]
pub struct ContainerManager {
    pub containers: Arc<RwLock<HashMap<String, ContainerInfo>>>,
}

#[derive(Clone)]
pub struct ContainerInfo {
    pub container_id: String,
    pub ip: String,
    pub host_iface: String,
}

impl ContainerManager {
    pub fn new() -> Self {
        Self {
            containers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add(&self, container_id: &str, ip: &str, iface: &str) {
        let mut map = self.containers.write().await;
        map.insert(container_id.to_string(), ContainerInfo {
            container_id: container_id.to_string(),
            ip: ip.to_string(),
            host_iface: iface.to_string(),
        });
        tracing::info!("container added: {} ip={} iface={}", container_id, ip, iface);
    }

    pub async fn remove(&self, container_id: &str) {
        let mut map = self.containers.write().await;
        map.remove(container_id);
        tracing::info!("container removed: {}", container_id);
    }
}

pub async fn api_server(
    cm: ContainerManager,
    bpf: Arc<std::sync::Mutex<bpf::BpfManager>>,
    port: u16,
    stop: Arc<AtomicBool>,
) {
    let addr = format!("127.0.0.1:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("API server bind failed: {}", e);
            return;
        }
    };
    tracing::info!("API server on {}", addr);

    loop {
        if stop.load(Ordering::SeqCst) { return; }

        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let cm = cm.clone();
                        let bpf = bpf.clone();
                        tokio::spawn(handle_api_connection(stream, cm, bpf));
                    }
                    Err(e) => {
                        tracing::error!("API accept error: {}", e);
                    }
                }
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(200)) => {}
        }
    }
}

async fn handle_api_connection(
    stream: tokio::net::TcpStream,
    cm: ContainerManager,
    bpf: Arc<std::sync::Mutex<bpf::BpfManager>>,
) {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        send_response(reader.into_inner(), "400 Bad Request", "invalid request").await;
        return;
    }

    let method = parts[0];
    let path = parts[1];

    // Read headers to find Content-Length
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).await.ok() != Some(true) || header.trim().is_empty() {
            break;
        }
        if header.to_lowercase().starts_with("content-length:") {
            if let Ok(len) = header.trim_start_matches("Content-Length:").trim().parse::<usize>() {
                content_length = len;
            }
        }
    }

    // Read body
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        use tokio::io::AsyncReadExt;
        if reader.read_exact(&mut body).await.is_err() {
            return;
        }
    }

    let response = match (method, path) {
        ("POST", "/api/v1/container") => {
            handle_container_cmd(&cm, &bpf, &body).await
        }
        ("GET", "/api/v1/health") => {
            "200 OK\r\n\r\n{\"status\":\"ok\"}".to_string()
        }
        _ => {
            format!("404 Not Found\r\n\r\n{{\"error\":\"not found\"}}")
        }
    };

    send_raw(reader.into_inner(), &response).await;
}

async fn handle_container_cmd(
    cm: &ContainerManager,
    bpf: &Arc<std::sync::Mutex<bpf::BpfManager>>,
    body: &[u8],
) -> String {
    let parsed: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return format!("400 Bad Request\r\n\r\n{{\"error\":\"json: {}\"}}", e);
        }
    };

    let action = parsed["action"].as_str().unwrap_or("");
    let container_id = parsed["container_id"].as_str().unwrap_or("");
    let ip = parsed["ip"].as_str().unwrap_or("0.0.0.0");
    let iface = parsed["iface"].as_str().unwrap_or("");

    match action {
        "add" => {
            cm.add(container_id, ip, iface).await;
            // Add to BPF container route map
            if let Ok(ip_addr) = ip.parse::<std::net::Ipv4Addr>() {
                if let Ok(bpf) = bpf.lock() {
                    let _ = bpf.update_container_route(u32::from(ip_addr), 1);
                }
            }
            format!("200 OK\r\n\r\n{{\"status\":\"added\"}}")
        }
        "del" => {
            cm.remove(container_id).await;
            if let Ok(ip_addr) = ip.parse::<std::net::Ipv4Addr>() {
                if let Ok(bpf) = bpf.lock() {
                    let _ = bpf.remove_container_route(u32::from(ip_addr));
                }
            }
            format!("200 OK\r\n\r\n{{\"status\":\"removed\"}}")
        }
        _ => {
            format!("400 Bad Request\r\n\r\n{{\"error\":\"unknown action\"}}")
        }
    }
}

async fn send_response(stream: tokio::net::TcpStream, status: &str, body: &str) {
    let response = format!("HTTP/1.1 {}\r\nContent-Length: {}\r\n\r\n{}", status, body.len(), body);
    send_raw(stream, &response).await;
}

async fn send_raw(mut stream: tokio::net::TcpStream, response: &str) {
    let _ = stream.write_all(response.as_bytes()).await;
}
