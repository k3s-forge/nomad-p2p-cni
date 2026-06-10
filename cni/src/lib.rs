use std::io::Read;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CniCmd {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub command: Option<String>,
    #[serde(rename = "containerId")]
    pub container_id: Option<String>,
    #[serde(rename = "netns")]
    pub netns: Option<String>,
    #[serde(rename = "ifName")]
    pub if_name: Option<String>,
    pub args: Option<String>,
    pub name: Option<String>,
    pub r#type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CniResult {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub ips: Vec<CniIp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<CniDns>,
}

#[derive(Debug, Serialize)]
pub struct CniIp {
    pub version: String,
    pub address: String,
    pub gateway: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CniDns {
    pub nameservers: Vec<String>,
}

const GATEWAY: &str = "10.244.0.1";
const AGENT_API: &str = "http://127.0.0.1:9091";

pub fn run() -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let cmd: CniCmd = serde_json::from_str(&input)?;

    let cni_version = cmd.cni_version.clone();

    match cmd.command.as_deref() {
        Some("ADD") | None => cmd_add(&cmd, &cni_version),
        Some("DEL") => cmd_del(&cmd, &cni_version),
        Some(other) => anyhow::bail!("unknown CNI command: {}", other),
    }
}

fn cmd_add(cmd: &CniCmd, cni_version: &str) -> anyhow::Result<()> {
    let container_id = cmd.container_id.as_deref().unwrap_or("unknown");
    let netns = cmd.netns.as_deref().unwrap_or("/proc/1/ns/net");
    let if_name = cmd.if_name.as_deref().unwrap_or("eth0");
    let host_iface = format!("veth-{}", &container_id[..8.min(container_id.len())]);

    // Create veth pair
    let output = Command::new("ip")
        .args(["link", "add", &host_iface, "type", "veth", "peer", "name", if_name])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore if already exists
        if !stderr.contains("File exists") {
            anyhow::bail!("veth create failed: {}", stderr);
        }
    }

    // Move peer to container netns
    let output = Command::new("ip")
        .args(["link", "set", if_name, "netns", netns])
        .output()?;
    if !output.status.success() {
        tracing::warn!("move peer to netns failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    // Assign IP to host side
    let container_ip = allocate_ip(container_id);
    let output = Command::new("ip")
        .args(["addr", "add", &format!("{}/32", container_ip), "dev", &host_iface])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            tracing::warn!("host addr add failed: {}", stderr);
        }
    }

    // Bring up host side
    let output = Command::new("ip")
        .args(["link", "set", &host_iface, "up"])
        .output()?;
    if !output.status.success() {
        tracing::warn!("host link up failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    // Assign IP and bring up inside container
    let ns_target = netns.trim_start_matches("/proc/").trim_end_matches("/ns/net");
    let output = Command::new("nsenter")
        .args(["--target", ns_target, "--net", "--",
            "ip", "addr", "add", &format!("{}/16", container_ip), "dev", if_name])
        .output()?;
    if !output.status.success() {
        tracing::warn!("container addr add failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let output = Command::new("nsenter")
        .args(["--target", ns_target, "--net", "--",
            "ip", "link", "set", if_name, "up"])
        .output()?;
    if !output.status.success() {
        tracing::warn!("container link up failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    // Add default route via gateway inside container
    let output = Command::new("nsenter")
        .args(["--target", ns_target, "--net", "--",
            "ip", "route", "add", "default", "via", GATEWAY, "dev", if_name])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            tracing::warn!("container route add failed: {}", stderr);
        }
    }

    // Notify agent to attach TC and add route
    if let Err(e) = notify_agent("add", container_id, &container_ip.to_string(), &host_iface) {
        tracing::warn!("agent notification failed: {}", e);
    }

    let result = CniResult {
        cni_version: cni_version.to_string(),
        ips: vec![CniIp {
            version: "4".into(),
            address: format!("{}/16", container_ip),
            gateway: Some(GATEWAY.into()),
        }],
        dns: None,
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn cmd_del(cmd: &CniCmd, cni_version: &str) -> anyhow::Result<()> {
    let container_id = cmd.container_id.as_deref().unwrap_or("unknown");
    let host_iface = format!("veth-{}", &container_id[..8.min(container_id.len())]);

    let output = Command::new("ip")
        .args(["link", "delete", &host_iface])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("Cannot find") && !stderr.contains("No such") {
            tracing::warn!("veth delete failed: {}", stderr);
        }
    }

    if let Err(e) = notify_agent("del", container_id, "", &host_iface) {
        tracing::warn!("agent del notification failed: {}", e);
    }

    let result = serde_json::json!({ "cniVersion": cni_version });
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn allocate_ip(container_id: &str) -> Ipv4Addr {
    let body = serde_json::json!({
        "action": "allocate",
        "container_id": container_id,
    });
    let payload = serde_json::to_string(&body).unwrap_or_default();
    match ureq::post(&format!("{}/api/v1/container", AGENT_API))
        .set("Content-Type", "application/json")
        .send_string(&payload)
    {
        Ok(resp) => {
            if let Ok(json) = resp.into_json::<serde_json::Value>() {
                if let Some(ip_str) = json["ip"].as_str() {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        return ip;
                    }
                }
            }
        }
        Err(_) => {
            // Agent unavailable, use deterministic fallback
        }
    };
    // Fallback: deterministic hash (will be overwritten by agent on restart)
    let hash = container_id.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    Ipv4Addr::new(10, 244, 0, 2 + (hash % 253) as u8)
}

fn notify_agent(action: &str, container_id: &str, ip: &str, iface: &str) -> Result<(), String> {
    let body = serde_json::json!({
        "action": action,
        "container_id": container_id,
        "ip": ip,
        "iface": iface,
    });
    let payload = serde_json::to_string(&body).map_err(|e| format!("json: {}", e))?;
    ureq::post(&format!("{}/api/v1/container", AGENT_API))
        .set("Content-Type", "application/json")
        .send_string(&payload)
        .map_err(|e| format!("agent API error: {}", e))?;
    Ok(())
}
