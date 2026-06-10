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

const VETH_PREFIX: &str = "eth1";
const OVERLAY_SUBNET: &str = "10.244.0.0/16";
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
    let _ = Command::new("ip")
        .args(["link", "set", if_name, "netns", netns])
        .output();

    // Assign IP to host side
    let container_ip = allocate_ip(container_id);
    let _ = Command::new("ip")
        .args(["addr", "add", &format!("{}/32", container_ip), "dev", &host_iface])
        .output();

    // Bring up host side
    let _ = Command::new("ip")
        .args(["link", "set", &host_iface, "up"])
        .output();

    // Assign IP and bring up inside container
    let _ = Command::new("nsenter")
        .args(["--target", &netns.trim_start_matches("/proc/").trim_end_matches("/ns/net"),
            "--net", "--",
            "ip", "addr", "add", &format!("{}/16", container_ip), "dev", if_name])
        .output();

    let _ = Command::new("nsenter")
        .args(["--target", &netns.trim_start_matches("/proc/").trim_end_matches("/ns/net"),
            "--net", "--",
            "ip", "link", "set", if_name, "up"])
        .output();

    // Add default route via gateway inside container
    let _ = Command::new("nsenter")
        .args(["--target", &netns.trim_start_matches("/proc/").trim_end_matches("/ns/net"),
            "--net", "--",
            "ip", "route", "add", "default", "via", GATEWAY, "dev", if_name])
        .output();

    // Notify agent to attach TC and add route
    let _ = notify_agent("add", container_id, &container_ip.to_string(), &host_iface);

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

    // Delete veth pair
    let _ = Command::new("ip")
        .args(["link", "delete", &host_iface])
        .output();

    // Notify agent to remove route
    let _ = notify_agent("del", container_id, "", &host_iface);

    let result = serde_json::json!({ "cniVersion": cni_version });
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn allocate_ip(container_id: &str) -> Ipv4Addr {
    let hash = container_id.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    let host_part = 2 + (hash % 253) as u8;
    Ipv4Addr::new(10, 244, 0, host_part)
}

fn notify_agent(action: &str, container_id: &str, ip: &str, iface: &str) -> Result<(), ureq::Error> {
    let body = serde_json::json!({
        "action": action,
        "container_id": container_id,
        "ip": ip,
        "iface": iface,
    });
    let _ = ureq::post(&format!("{}/api/v1/container", AGENT_API))
        .set("Content-Type", "application/json")
        .send_json(&body);
    Ok(())
}
