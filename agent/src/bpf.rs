use anyhow::{Context, Result};
use aya::{Ebpf, EbpfLoader, maps::HashMap, programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags, CgroupAttachMode}};
use nomad_p2p_common::{PeerEndpoint, TunnelCfg};
use std::path::Path;
use std::sync::Arc;

pub struct BpfMaps {
    pub container_route: Option<HashMap<u32, u32>>,
    pub node_dynamic: Option<HashMap<u32, PeerEndpoint>>,
    pub geneve_ifindex: Option<HashMap<u32, u32>>,
    pub tunnel_cfg: Option<HashMap<u32, TunnelCfg>>,
    pub vip_map: Option<HashMap<u32, nomad_p2p_common::VipInfo>>,
    pub acl_map: Option<HashMap<u32, nomad_p2p_common::AclRule>>,
    pub default_policy: Option<HashMap<u32, u8>>,
}

pub struct BpfManager {
    pub mesh: Ebpf,
    pub fw: Option<Ebpf>,
    pub vip: Option<Ebpf>,
    pub maps: BpfMaps,
    pub pinned: bool,
    pub ringbuf: Arc<std::sync::Mutex<Option<aya::maps::RingBuf>>>,
}

impl BpfManager {
    pub fn load() -> Result<Self> {
        let mut mesh = EbpfLoader::new()
            .load_file(Path::new("bin/mesh.bpf.o"))
            .context("load mesh BPF")?;

        let ringbuf = match mesh.map_mut("ROUTE_MISS_RINGBUF") {
            Some(m) => aya::maps::RingBuf::try_from(m).ok(),
            None => None,
        };

        let fw = EbpfLoader::new().load_file(Path::new("bin/firewall.bpf.o")).ok();
        let vip = EbpfLoader::new().load_file(Path::new("bin/vip_balancer.bpf.o")).ok();

        let maps = BpfMaps {
            container_route: mesh.take_map("CONTAINER_ROUTE_MAP").ok().and_then(|m| HashMap::try_from(m).ok()),
            node_dynamic: mesh.take_map("NODE_DYNAMIC_MAP").ok().and_then(|m| HashMap::try_from(m).ok()),
            geneve_ifindex: mesh.take_map("GENEVE_IFINDEX_MAP").ok().and_then(|m| HashMap::try_from(m).ok()),
            tunnel_cfg: mesh.take_map("TUNNEL_CFG_MAP").ok().and_then(|m| HashMap::try_from(m).ok()),
            vip_map: None,
            acl_map: None,
            default_policy: None,
        };

        Ok(Self { mesh, fw, vip, maps, pinned: false, ringbuf: Arc::new(std::sync::Mutex::new(ringbuf)), links: vec![] })
    }

    pub fn set_tunnel_cfg(&mut self, tunnel_id: u32) -> Result<()> {
        if let Some(ref map) = self.maps.tunnel_cfg { map.insert(0u32, TunnelCfg { tunnel_id }, 0)?; }
        Ok(())
    }

    pub fn set_geneve_ifindex(&mut self, ifindex: u32) -> Result<()> {
        if let Some(ref map) = self.maps.geneve_ifindex { map.insert(0u32, ifindex, 0)?; }
        Ok(())
    }

    pub fn update_peer(&self, overlay_ip: u32, ep: PeerEndpoint) -> Result<()> {
        if let Some(ref map) = self.maps.node_dynamic { map.insert(overlay_ip, ep, 0)?; }
        Ok(())
    }

    pub fn remove_peer(&self, overlay_ip: u32) -> Result<()> {
        if let Some(ref map) = self.maps.node_dynamic { map.remove(&overlay_ip)?; }
        Ok(())
    }

    pub fn update_container_route(&self, container_ip: u32, route_vni: u32) -> Result<()> {
        if let Some(ref map) = self.maps.container_route { map.insert(container_ip, route_vni, 0)?; }
        Ok(())
    }

    pub fn remove_container_route(&self, container_ip: u32) -> Result<()> {
        if let Some(ref map) = self.maps.container_route { map.remove(&container_ip)?; }
        Ok(())
    }

    pub fn list_container_ips(&self) -> Vec<u32> {
        Vec::new()
    }

    pub fn is_ip_allocated(&self, _ip: u32) -> bool {
        false
    }

    pub fn attach_all(&mut self, ifindex: u32) -> Result<()> {
        self.attach_xdp(ifindex)?;
        self.attach_tc(ifindex)?;
        Ok(())
    }

    fn attach_xdp(&mut self, ifindex: u32) -> Result<()> {
        if let Some(prog) = self.mesh.program_mut("xdp_pass") {
            let xdp: &mut Xdp = prog.try_into()?;
            xdp.attach(ifindex, XdpFlags::default())?;
        }
        Ok(())
    }

    fn attach_tc(&mut self, ifindex: u32) -> Result<()> {
        if let Some(prog) = self.mesh.program_mut("egress_p2p_mesh") {
            let tc: &mut SchedClassifier = prog.try_into()?;
            tc.attach(ifindex, TcAttachType::Egress)?;
        }
        Ok(())
    }
}

pub async fn find_default_ifindex() -> Result<u32> {
    let out = tokio::process::Command::new("ip").args(["route", "show", "default"]).output().await.context("ip route")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = parts.iter().position(|&p| p == "dev") {
            if let Some(name) = parts.get(pos + 1) {
                let out = tokio::process::Command::new("ip").args(["link", "show", name]).output().await?;
                let stdout = String::from_utf8_lossy(&out.stdout);
                if let Some(line) = stdout.lines().next() {
                    if let Some(idx) = line.split(':').next().and_then(|s| s.trim().parse::<u32>().ok()) {
                        return Ok(idx);
                    }
                }
            }
        }
    }
    Ok(1)
}