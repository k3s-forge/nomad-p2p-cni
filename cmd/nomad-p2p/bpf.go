package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type BPFMaps struct {
	ContainerRouteMap *ebpf.Map
	NodeDynamicMap    *ebpf.Map
	RouteMissRingbuf  *ebpf.Map
	GeneveIfindexMap  *ebpf.Map
	TunnelCfgMap      *ebpf.Map
	VIPMap            *ebpf.Map
	VIPStatsMap       *ebpf.Map
	ACLMap            *ebpf.Map
	PortACLMap        *ebpf.Map
	DefaultPolicy     *ebpf.Map
}

type NodeEndpoint struct {
	PublicIP   uint32
	PublicPort uint16
	Pad        uint16
}

type VIPInfo struct {
	Backends [16]uint32
	Count    uint8
	Pad      [3]byte
	NextIdx  uint32
}

type TunnelCfg struct {
	TunnelID uint32
}

func (a *Agent) loadBPF() error {
	spec, err := ebpf.LoadCollectionSpec("bin/mesh.bpf.o")
	if err != nil {
		return fmt.Errorf("load mesh spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load mesh collection: %w", err)
	}
	a.maps = &BPFMaps{
		ContainerRouteMap: coll.Maps["CONTAINER_ROUTE_MAP"],
		NodeDynamicMap:    coll.Maps["NODE_DYNAMIC_MAP"],
		RouteMissRingbuf:  coll.Maps["ROUTE_MISS_RINGBUF"],
		GeneveIfindexMap:  coll.Maps["GENEVE_IFINDEX_MAP"],
		TunnelCfgMap:      coll.Maps["TUNNEL_CFG_MAP"],
	}
	a.meshColl = coll

	pinDir := "/sys/fs/bpf/nomad-p2p"
	exec.Command("mkdir", "-p", pinDir).Run()
	if a.maps.ContainerRouteMap != nil {
		a.maps.ContainerRouteMap.Pin(pinDir + "/container_route")
	}
	if a.maps.NodeDynamicMap != nil {
		a.maps.NodeDynamicMap.Pin(pinDir + "/node_dynamic")
	}
	if prog, ok := a.meshColl.Programs["egress_p2p_mesh"]; ok {
		prog.Pin(pinDir + "/mesh_prog")
		log.Printf("[agent] pinned egress_p2p_mesh program")
	}
	log.Printf("[agent] mesh BPF maps pinned to %s", pinDir)

	if a.maps.TunnelCfgMap != nil {
		key := uint32(0)
		cfg := TunnelCfg{TunnelID: uint32(a.cfg.TunnelVNI)}
		a.maps.TunnelCfgMap.Update(key, cfg, 0)
	}

	if a.cfg.VIPEnabled {
		vipSpec, err := ebpf.LoadCollectionSpec("bin/vip_balancer.bpf.o")
		if err != nil {
			log.Printf("[agent] VIP balancer BPF not found: %v", err)
		} else {
			vipColl, err := ebpf.NewCollection(vipSpec)
			if err != nil {
				log.Printf("[agent] VIP balancer load failed: %v", err)
			} else {
				a.maps.VIPMap = vipColl.Maps["VIP_MAP"]
				a.maps.VIPStatsMap = vipColl.Maps["VIP_STATS_MAP"]
				a.vipColl = vipColl
				log.Printf("[agent] VIP balancer BPF loaded")
			}
		}
	}

	fwSpec, err := ebpf.LoadCollectionSpec("bin/firewall.bpf.o")
	if err != nil {
		log.Printf("[agent] firewall BPF not found: %v", err)
	} else {
		fwColl, err := ebpf.NewCollection(fwSpec)
		if err != nil {
			log.Printf("[agent] firewall load failed: %v", err)
		} else {
			a.maps.ACLMap = fwColl.Maps["ACL_MAP"]
			a.maps.PortACLMap = fwColl.Maps["PORT_ACL_MAP"]
			a.maps.DefaultPolicy = fwColl.Maps["DEFAULT_POLICY"]
			a.fwColl = fwColl
			a.loadACLsFromConfig()
		}
	}

	return nil
}

func (a *Agent) attachBPF() error {
	iface, err := findDefaultInterface()
	if err != nil {
		log.Printf("[agent] no network interface found for BPF attachment: %v", err)
		return nil
	}
	ifIndex := uint32(iface.Index)
	log.Printf("[agent] attaching BPF to interface %s (index %d)", iface.Name, iface.Index)

	if a.meshColl != nil {
		if xdpProg, ok := a.meshColl.Programs["xdp_pass"]; ok {
			l, err := link.AttachXDP(link.XDPOptions{
				Interface: iface.Index,
				Program:   xdpProg,
			})
			if err != nil {
				log.Printf("[agent] XDP attach failed: %v", err)
			} else {
				a.bpfLinks = append(a.bpfLinks, l)
				log.Printf("[agent] XDP attached to %s", iface.Name)
			}
		}

		if tcProg, ok := a.meshColl.Programs["egress_p2p_mesh"]; ok {
			if err := a.attachTC(ifIndex, tcProg, "egress"); err != nil {
				log.Printf("[agent] TC egress attach failed: %v", err)
			} else {
				log.Printf("[agent] TC egress attached to %s", iface.Name)
			}
		}
	}

	if a.fwColl != nil {
		if fwProg, ok := a.fwColl.Programs["tc_ingress_firewall"]; ok {
			if err := a.attachTC(ifIndex, fwProg, "ingress"); err != nil {
				log.Printf("[agent] TC ingress attach failed: %v", err)
			} else {
				log.Printf("[agent] TC ingress firewall attached to %s", iface.Name)
			}
		}
	}

	if a.vipColl != nil {
		if vipProg, ok := a.vipColl.Programs["vip_load_balance"]; ok {
			if err := a.attachCgroup(vipProg); err != nil {
				log.Printf("[agent] cgroup attach failed: %v", err)
			} else {
				log.Printf("[agent] VIP cgroup program attached")
			}
		}
	}

	return nil
}

func (a *Agent) attachTC(ifIndex uint32, prog *ebpf.Program, direction string) error {
	iface, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil {
		return fmt.Errorf("get interface: %w", err)
	}

	cmd := exec.Command("tc", "qdisc", "add", "dev", iface.Name, "clsact")
	cmd.Run()

	pinPath := fmt.Sprintf("/sys/fs/bpf/tc/%s_%d", direction, ifIndex)
	exec.Command("rm", "-f", pinPath).Run()
	if err := exec.Command("bpftool", "prog", "pin", "id",
		fmt.Sprintf("%d", prog.FD()), pinPath).Run(); err != nil {
		return fmt.Errorf("pin prog: %w", err)
	}

	cmd = exec.Command("tc", "filter", "add", "dev", iface.Name, direction,
		"pref", "1", "handle", "1", "bpf", "direct-action", "pinned", pinPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tc filter add: %w: %s", err, out)
	}

	return nil
}

func (a *Agent) attachCgroup(prog *ebpf.Program) error {
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Program: prog,
		Attach:  ebpf.AttachCGroupInet4Connect,
	})
	if err != nil {
		return fmt.Errorf("attach cgroup: %w", err)
	}
	a.bpfLinks = append(a.bpfLinks, l)
	return nil
}

func findDefaultInterface() (*net.Interface, error) {
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err == nil {
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) {
				return net.InterfaceByName(fields[i+1])
			}
		}
	}

	for _, name := range []string{"eth0", "ens3", "wlan0", "enp0s3"} {
		iface, err := net.InterfaceByName(name)
		if err == nil {
			return iface, nil
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("no suitable network interface found")
}

func (a *Agent) updateGeneveIfindex() {
	if a.maps.GeneveIfindexMap == nil {
		return
	}
	iface, err := net.InterfaceByName(a.cfg.TunnelDevice)
	if err != nil {
		log.Printf("[agent] geneve device %s not found for ifindex update", a.cfg.TunnelDevice)
		return
	}
	key := uint32(0)
	val := uint32(iface.Index)
	a.maps.GeneveIfindexMap.Update(key, val, 0)
	log.Printf("[agent] geneve ifindex %d stored in BPF map", iface.Index)
}
