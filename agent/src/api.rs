use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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

    /// Recover container state from pinned BPF map after agent restart
    pub async fn recover_from_bpf(&self, bpf: &Arc<std::sync::Mutex<bpf::BpfManager>>) {
        let ips = {
            let bpf = bpf.lock().unwrap();
            bpf.list_container_ips()
        };
        let mut map = self.containers.write().await;
        for ip in ips {
            let addr = std::net::Ipv4Addr::from(ip);
            let cid = format!("recovered-{}", addr);
            map.insert(cid.clone(), ContainerInfo {
                container_id: cid.clone(),
                ip: addr.to_string(),
                host_iface: format!("veth-{}", &cid[..cid.len().min(8)]),
            });
        }
        if map.len() > 0 {
            tracing::info!("recovered {} container IPs from BPF", map.len());
        }
    }

    /// Allocate IP via BPF map (avoids collisions on restart)
    pub fn allocate_from_bpf(bpf: &Arc<std::sync::Mutex<bpf::BpfManager>>, container_id: &str) -> String {
        let bpf = bpf.lock().unwrap();
        let hash = container_id.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
        for offset in 0..253u8 {
            let host = (2u8 + ((hash as u8).wrapping_add(offset))) % 254;
            if host < 2 { continue; }
            let ip = u32::from(std::net::Ipv4Addr::new(10, 244, 0, host));
            if !bpf.is_ip_allocated(ip) {
                let _ = bpf.update_container_route(ip, 1);
                return std::net::Ipv4Addr::from(ip).to_string();
            }
        }
        let ip = u32::from(std::net::Ipv4Addr::new(10, 244, 0, 2u8 + (hash % 253) as u8));
        std::net::Ipv4Addr::from(ip).to_string()
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
        tokio::select! {
            result = listener.accept() => {
                if stop.load(Ordering::SeqCst) { return; }
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
            _ = tokio::signal::ctrl_c() => {
                return;
            }
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
        let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 15\r\n\r\ninvalid request";
        send_raw(reader.into_inner(), response).await;
        return;
    }

    let method = parts[0];
    let path = parts[1];

    // Read headers to find Content-Length
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header).await.unwrap_or(0);
        if n == 0 || header.trim().is_empty() {
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
        "allocate" => {
            let ip = ContainerManager::allocate_from_bpf(bpf, container_id);
            format!("200 OK\r\n\r\n{{\"ip\":\"{}\"}}", ip)
        }
        "add" => {
            cm.add(container_id, ip, iface).await;
            if let Ok(ip_addr) = ip.parse::<std::net::Ipv4Addr>() {
                if let Ok(bpf) = bpf.lock() {
                    if let Err(e) = bpf.update_container_route(u32::from(ip_addr), 1) {
                        tracing::warn!("BPF container route add failed: {}", e);
                    }
                }
            }
            format!("200 OK\r\n\r\n{{\"status\":\"added\"}}")
        }
        "del" => {
            cm.remove(container_id).await;
            if let Ok(ip_addr) = ip.parse::<std::net::Ipv4Addr>() {
                if let Ok(bpf) = bpf.lock() {
                    if let Err(e) = bpf.remove_container_route(u32::from(ip_addr)) {
                        tracing::warn!("BPF container route del failed: {}", e);
                    }
                }
            }
            format!("200 OK\r\n\r\n{{\"status\":\"removed\"}}")
        }
        _ => {
            format!("400 Bad Request\r\n\r\n{{\"error\":\"unknown action\"}}")
        }
    }
}

async fn send_raw(mut stream: tokio::net::TcpStream, response: &str) {
    let _ = stream.write_all(response.as_bytes()).await;
}
