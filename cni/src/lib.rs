use std::io::Read;

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

pub fn run() -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let cmd: CniCmd = serde_json::from_str(&input)?;

    let cni_version = cmd.cni_version.clone();

    match cmd.command.as_deref() {
        Some("ADD") | None => {
            let result = CniResult {
                cni_version,
                ips: vec![CniIp {
                    version: "4".into(),
                    address: "10.244.0.0/24".into(),
                    gateway: Some("10.244.0.1".into()),
                }],
                dns: None,
            };
            let output = serde_json::to_string(&result)?;
            println!("{}", output);
        }
        Some("DEL") => {
            let result = serde_json::json!({ "cniVersion": cni_version });
            println!("{}", serde_json::to_string(&result)?);
        }
        Some(other) => {
            anyhow::bail!("unknown CNI command: {}", other);
        }
    }

    Ok(())
}
