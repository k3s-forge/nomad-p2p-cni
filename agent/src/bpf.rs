use anyhow::{Context, Result};
use aya::{
    Ebpf, EbpfLoader,
    maps::{HashMap, MapData, RingBuf},
    programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags},
};
use nomad_p2p_common::{PeerEndpoint, TunnelCfg, VipInfo, AclRule};
use std::path::Path;
use std::sync::Arc;

// Safety: these are #[repr(C)] POD types safe for BPF map storage
unsafe impl aya::Pod for PeerEndpoint {}
unsafe impl aya::Pod for TunnelCfg {}
unsafe impl aya::Pod for VipInfo {}
unsafe impl aya::Pod for AclRule {}

pub struct BpfMaps {
    pub container_route: Option<HashMap<MapData, u32, u32>>,
    pub node_dynamic: Option<HashMap<MapData, u32, PeerEndpoint>>,
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
    pub pinned: bool,
    pub ringbuf: Arc<std::sync::Mutex<Option<RingBuf<MapData>>>>,
}

fn into_map<K: aya::Pod, V: aya::Pod>(m: Option<MapData>) -> Option<HashMap<MapData, K, V>> {
    m.and_then(|d| HashMap::try_from(d).ok())
}

impl BpfManager {
    pub fn load() -> Result<Self> {
        let mut mesh = EbpfLoader::new()
            .load_file(Path::new("bin/mesh.bpf.o"))
            .context("load mesh BPF")?;

        let ringbuf = mesh.map_mut("ROUTE_MISS_RINGBUF")
            .and_then(|m| RingBuf::try_from(m).ok());

        let fw = EbpfLoader::new().load_file(Path::new("bin/firewall.bpf.o")).ok();
        let vip = EbpfLoader::new().load_file(Path::new("bin/vip_balancer.bpf.o")).ok();

        let maps = BpfMaps {
            container_route: into_map::<u32, u32>(mesh.take_map("CONTAINER_ROUTE_MAP").ok()),
            node_dynamic: into_map::<u32, PeerEndpoint>(mesh.take_map("NODE_DYNAMIC_MAP").ok()),
            geneve_ifindex: into_map::<u32, u32>(mesh.take_map("GENEVE_IFINDEX_MAP").ok()),
            tunnel_cfg: into_map::<u32, TunnelCfg>(mesh.take_map("TUNNEL_CFG_MAP").ok()),
            vip_map: None,
            acl_map: None,
            default_policy: None,
        };

        Ok(Self { mesh, fw, vip, maps, pinned: false, ringbuf: Arc::new(std::sync::Mutex::new(ringbuf)) })
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

    pub fn update_container_route(&self, container_ip: u32, route_vni: u32) -> Result<()> {
        if let Some(ref map) = self.maps.container_route {
            map.insert(&container_ip, &route_vni, 0)?;
        }
        Ok(())
    }

    pub fn remove_container_route(&self, container_ip: u32) -> Result<()> {
        if let Some(ref map) = self.maps.container_route {
            map.remove(&container_ip)?;
        }
        Ok(())
    }

    pub fn list_container_ips(&self) -> Vec<u32> { Vec::new() }
    pub fn is_ip_allocated(&self, _ip: u32) -> bool { false }

    pub fn attach_all(&mut self, ifindex: u32) -> Result<()> {
        if let Some(prog) = self.mesh.program_mut("xdp_pass") {
            let xdp: &mut Xdp = prog.try_into()?;
            xdp.attach(ifindex, XdpFlags::default())?;
        }
        if let Some(prog) = self.mesh.program_mut("egress_p2p_mesh") {
            let tc: &mut SchedClassifier = prog.try_into()?;
            tc.attach(ifindex, TcAttachType::Egress)?;
        }
        Ok(())
    }
}

pub async fn find_default_ifindex() -> Result<u32> {
    let out = tokio::process::Command::new("ip")
        .args(["route","show","default"]).output().await.context("ip route")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = p.iter().position(|&x| x == "dev") {
            if let Some(name) = p.get(pos + 1) {
                let out = tokio::process::Command::new("ip")
                    .args(["link","show",name]).output().await?;
                let s = String::from_utf8_lossy(&out.stdout);
                if let Some(l) = s.lines().next() {
                    if let Some(idx) = l.split(':').next().and_then(|i| i.trim().parse::<u32>().ok()) {
                        return Ok(idx);
                    }
                }
            }
        }
    }
    Ok(1)
}