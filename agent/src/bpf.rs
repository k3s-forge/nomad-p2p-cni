use anyhow::{Context, Result};
use aya::{
    programs::{CgroupAttachMode, CgroupSkbAttachType, Link, TcAttachType, Xdp, XdpFlags},
    Ebpf, EbpfLoader, MapData, maps::HashMap,
};
use nomad_p2p_common::{AclRule, PeerEndpoint, TunnelCfg, VipInfo};
use std::{
    net::Ipv4Addr,
    os::fd::AsFd,
    path::Path,
    sync::Arc,
};
use tokio::sync::RwLock;

pub struct BpfMaps {
    pub container_route: Option<HashMap<MapData, u32, u32>>,
    pub node_dynamic: Option<HashMap<MapData, u32, PeerEndpoint>>,
    pub route_miss_ringbuf: Option<aya::maps::RingBuf<MapData>>,
    pub geneve_ifindex: Option<HashMap<MapData, u32, u32>>,
    pub tunnel_cfg: Option<HashMap<MapData, u32, TunnelCfg>>,
    pub vip_map: Option<HashMap<MapData, u32, VipInfo>>,
    pub acl_map: Option<HashMap<MapData, u32, AclRule>>,
    pub default_policy: Option<HashMap<MapData, u32, u8>>,
}

pub struct BpfManager {
    pub mesh: Ebpf,
    pub fw: Option<Ebpf>,
    pub vip: Option<Ebpf>,
    pub maps: BpfMaps,
    pub links: Vec<Box<dyn Link>>,
    pub pinned: bool,
}

impl BpfManager {
    pub fn load() -> Result<Self> {
        let mut mesh = EbpfLoader::new()
            .load_file(Path::new("bin/mesh.bpf.o"))
            .context("load mesh BPF")?;
        aya_log::EbpfLogger::init(&mut mesh).ok();

        let maps = BpfMaps {
            container_route: mesh.take_map("CONTAINER_ROUTE_MAP").ok().map(|d| HashMap::new(d, 0).ok()).flatten(),
            node_dynamic: mesh.take_map("NODE_DYNAMIC_MAP").ok().map(|d| HashMap::new(d, 0).ok()).flatten(),
            route_miss_ringbuf: mesh.take_map("ROUTE_MISS_RINGBUF").ok().map(|d| aya::maps::RingBuf::new(d).ok()).flatten(),
            geneve_ifindex: mesh.take_map("GENEVE_IFINDEX_MAP").ok().map(|d| HashMap::new(d, 0).ok()).flatten(),
            tunnel_cfg: mesh.take_map("TUNNEL_CFG_MAP").ok().map(|d| HashMap::new(d, 0).ok()).flatten(),
            vip_map: None,
            acl_map: None,
            default_policy: None,
        };

        let fw = match EbpfLoader::new().load_file(Path::new("bin/firewall.bpf.o")) {
            Ok(mut fw) => {
                aya_log::EbpfLogger::init(&mut fw).ok();
                Some(fw)
            }
            Err(e) => {
                tracing::warn!("firewall BPF not loaded: {}", e);
                None
            }
        };

        let vip = match EbpfLoader::new().load_file(Path::new("bin/vip_balancer.bpf.o")) {
            Ok(mut vip) => {
                aya_log::EbpfLogger::init(&mut vip).ok();
                Some(vip)
            }
            Err(e) => {
                tracing::warn!("VIP BPF not loaded: {}", e);
                None
            }
        };

        Ok(Self {
            mesh,
            fw,
            vip,
            maps,
            links: vec![],
            pinned: false,
        })
    }

    pub fn set_tunnel_cfg(&self, tunnel_id: u32) -> Result<()> {
        if let Some(ref map) = self.maps.tunnel_cfg {
            map.insert(&0u32, &TunnelCfg { tunnel_id }, 0)?;
        }
        Ok(())
    }

    pub fn set_geneve_ifindex(&self, ifindex: u32) -> Result<()> {
        if let Some(ref map) = self.maps.geneve_ifindex {
            map.insert(&0u32, &ifindex, 0)?;
        }
        Ok(())
    }

    pub fn update_peer(&self, overlay_ip: u32, ep: &PeerEndpoint) -> Result<()> {
        if let Some(ref map) = self.maps.node_dynamic {
            map.insert(&overlay_ip, ep, 0)?;
        }
        Ok(())
    }

    pub fn remove_peer(&self, overlay_ip: u32) -> Result<()> {
        if let Some(ref map) = self.maps.node_dynamic {
            map.remove(&overlay_ip)?;
        }
        Ok(())
    }

    pub fn attach_all(&mut self, ifindex: u32) -> Result<()> {
        let _ = self.attach_xdp(ifindex);
        let _ = self.attach_tc(ifindex, "egress");
        let _ = self.attach_fw_tc(ifindex);
        let _ = self.attach_cgroup_vip();
        Ok(())
    }

    fn attach_xdp(&mut self, ifindex: u32) -> Result<()> {
        let prog = self.mesh.program_mut("xdp_pass").context("xdp_pass not found")?;
        let xdp: &mut Xdp = prog.try_into()?;
        let link = xdp.attach()?;
        self.links.push(Box::new(link));
        Ok(())
    }

    fn attach_tc(&mut self, ifindex: u32, _direction: &str) -> Result<()> {
        let _ = aya::programs::tc::TcError;
        let prog = self.mesh.program_mut("egress_p2p_mesh").context("egress_p2p_mesh not found")?;
        let tc: &mut aya::programs::SchedClassifier = prog.try_into()?;
        tc.attach(aya::programs::TcAttachType::Egress)?;
        Ok(())
    }

    fn attach_fw_tc(&mut self, ifindex: u32) -> Result<()> {
        if let Some(ref mut fw) = self.fw {
            if let Some(prog) = fw.program_mut("tc_ingress_firewall") {
                let tc: &mut aya::programs::SchedClassifier = prog.try_into()?;
                tc.attach(aya::programs::TcAttachType::Ingress)?;
            }
        }
        Ok(())
    }

    fn attach_cgroup_vip(&mut self) -> Result<()> {
        if let Some(ref mut vip) = self.vip {
            if let Some(prog) = vip.program_mut("vip_load_balance") {
                let cg: &mut aya::programs::CgroupSkb = prog.try_into()?;
                cg.attach(CgroupAttachMode::Single)?;
            }
        }
        Ok(())
    }
}

pub async fn find_default_ifindex() -> Result<u32> {
    let out = tokio::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .await
        .context("ip route failed")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "dev" && i + 1 < parts.len() {
                let name = parts[i + 1];
                if let Ok(iface) = tokio::net::TcpStream::connect("127.0.0.1:1").await {
                    drop(iface);
                }
                let out = tokio::process::Command::new("ip")
                    .args(["link", "show", name])
                    .output()
                    .await?;
                let stdout = String::from_utf8_lossy(&out.stdout);
                if let Some(line) = stdout.lines().next() {
                    if let Some(idx_str) = line.split(':').next() {
                        if let Ok(idx) = idx_str.trim().parse::<u32>() {
                            return Ok(idx);
                        }
                    }
                }
            }
        }
    }
    Ok(1)
}

pub async fn find_geneve_ifindex(dev: &str) -> Result<u32> {
    let out = tokio::process::Command::new("ip")
        .args(["link", "show", dev])
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if let Some(line) = stdout.lines().next() {
        if let Some(idx_str) = line.split(':').next() {
            if let Ok(idx) = idx_str.trim().parse::<u32>() {
                return Ok(idx);
            }
        }
    }
    Err(anyhow::anyhow!("Geneve device {} not found", dev))
}
