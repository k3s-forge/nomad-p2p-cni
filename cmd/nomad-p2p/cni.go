package main

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
)

type NetConf struct {
	CniVersion string `json:"cniVersion"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Subnet     string `json:"subnet"`
	MTU        int    `json:"mtu"`
}

const (
	bpfMapPath = "/sys/fs/bpf/nomad-p2p"
	stateDir   = "/var/run/nomad-p2p"
)

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func handleCNI(command, containerID, netns string, stdinData []byte) error {
	switch command {
	case "ADD":
		return cniAddFromArgs(containerID, netns, stdinData)
	case "DEL":
		return cniDelFromArgs(containerID, netns, stdinData)
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

func cniAddSk(args *skel.CmdArgs) error {
	conf := &NetConf{}
	if err := json.Unmarshal(args.StdinData, conf); err != nil {
		return err
	}
	if conf.MTU == 0 {
		conf.MTU = 1420
	}

	podIP, gateway, err := allocateIP(conf.Subnet, args.ContainerID)
	if err != nil {
		return fmt.Errorf("allocate IP: %w", err)
	}

	if args.Netns != "" {
		if err := configureContainer(args.Netns, podIP, gateway, conf.MTU); err != nil {
			return fmt.Errorf("configure container: %w", err)
		}

		peerIfIndex, err := findVethPeerIndex(args.Netns)
		if err != nil {
			log.Printf("[cni] find veth peer: %v (non-fatal)", err)
		} else {
			if err := registerRouteWithIfindex(podIP, peerIfIndex); err != nil {
				log.Printf("[cni] BPF route register: %v (non-fatal)", err)
			}
			if err := attachTCToVethPeer(peerIfIndex); err != nil {
				log.Printf("[cni] TC attach: %v (non-fatal)", err)
			} else {
				log.Printf("[cni] TC egress attached to veth peer %d", peerIfIndex)
			}
		}
	}

	saveContainerState(args.ContainerID, podIP)
	log.Printf("[cni] ADD %s -> %s", shortID(args.ContainerID), podIP)

	result := &current.Result{
		CNIVersion: conf.CniVersion,
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{IP: podIP, Mask: net.CIDRMask(32, 32)},
				Gateway: gateway,
			},
		},
	}
	return types.PrintResult(result, conf.CniVersion)
}

func cniDelSk(args *skel.CmdArgs) error {
	log.Printf("[cni] DEL %s", shortID(args.ContainerID))
	unregisterRouteByContainerID(args.ContainerID)
	cleanupTCFilters()
	if args.Netns != "" {
		exec.Command("ip", "netns", "del", args.Netns).Run()
	}
	removeContainerState(args.ContainerID)
	return nil
}

func cniAddFromArgs(containerID, netns string, stdinData []byte) error {
	conf := &NetConf{}
	if err := json.Unmarshal(stdinData, conf); err != nil {
		return err
	}
	if conf.MTU == 0 {
		conf.MTU = 1420
	}
	podIP, gateway, err := allocateIP(conf.Subnet, containerID)
	if err != nil {
		return err
	}
	if netns != "" {
		if err := configureContainer(netns, podIP, gateway, conf.MTU); err != nil {
			return err
		}
		peerIfIndex, err := findVethPeerIndex(netns)
		if err != nil {
			log.Printf("[cni] find veth peer: %v (non-fatal)", err)
		} else {
			if err := registerRouteWithIfindex(podIP, peerIfIndex); err != nil {
				log.Printf("[cni] BPF route register: %v (non-fatal)", err)
			}
			if err := attachTCToVethPeer(peerIfIndex); err != nil {
				log.Printf("[cni] TC attach: %v (non-fatal)", err)
			} else {
				log.Printf("[cni] TC egress attached to veth peer %d", peerIfIndex)
			}
		}
	}

	saveContainerState(containerID, podIP)
	log.Printf("[cni] ADD %s -> %s", shortID(containerID), podIP)
	result := &current.Result{
		CNIVersion: conf.CniVersion,
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{IP: podIP, Mask: net.CIDRMask(32, 32)},
				Gateway: gateway,
			},
		},
	}
	return types.PrintResult(result, conf.CniVersion)
}

func cniDelFromArgs(containerID, netns string, stdinData []byte) error {
	log.Printf("[cni] DEL %s", shortID(containerID))
	unregisterRouteByContainerID(containerID)
	cleanupTCFilters()
	if netns != "" {
		exec.Command("ip", "netns", "del", netns).Run()
	}
	removeContainerState(containerID)
	return nil
}

func allocateIP(subnet, containerID string) (net.IP, net.IP, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, nil, err
	}
	h := fnv.New32a()
	h.Write([]byte(containerID))
	hash := h.Sum32()

	ip := make(net.IP, 4)
	copy(ip, ipNet.IP.To4())
	ip[3] = byte(10 + (hash % 240))

	gw := make(net.IP, 4)
	copy(gw, ipNet.IP.To4())
	gw[3] = 1

	return ip, gw, nil
}

func configureContainer(netns string, podIP net.IP, gateway net.IP, mtu int) error {
	ifName := "eth0"
	ns := "--net=/var/run/netns/" + netns

	cmd := exec.Command("nsenter", ns, "--", "ip", "addr", "replace", podIP.String()+"/32", "dev", ifName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set IP: %w: %s", err, out)
	}

	cmd = exec.Command("nsenter", ns, "--", "ip", "link", "set", ifName, "mtu", fmt.Sprintf("%d", mtu), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set MTU: %w: %s", err, out)
	}

	cmd = exec.Command("nsenter", ns, "--", "ip", "route", "replace", "default", "via", gateway.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set route: %w: %s", err, out)
	}
	return nil
}

func findVethPeerIndex(netns string) (uint32, error) {
	ns := "--net=/var/run/netns/" + netns
	out, err := exec.Command("nsenter", ns, "--", "ip", "link", "show", "eth0").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("show eth0 in ns: %w: %s", err, out)
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) == 0 {
		return 0, fmt.Errorf("no output from ip link show eth0")
	}

	var containerIfIndex int
	fmt.Sscanf(lines[0], "%d:", &containerIfIndex)
	if containerIfIndex == 0 {
		return 0, fmt.Errorf("could not parse ifindex from: %s", lines[0])
	}

	out, err = exec.Command("bash", "-c",
		fmt.Sprintf("for f in /sys/class/net/veth*/iflink; do [ -f \"$f\" ] && peer=$(cat \"$f\") && [ \"$peer\" = \"%d\" ] && basename $(dirname $(dirname $f)); done",
			containerIfIndex)).CombinedOutput()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		vethName := strings.TrimSpace(string(out))
		out2, err := exec.Command("ip", "link", "show", vethName).CombinedOutput()
		if err == nil {
			var ifIndex int
			fmt.Sscanf(strings.Split(string(out2), "\n")[0], "%d:", &ifIndex)
			if ifIndex > 0 {
				return uint32(ifIndex), nil
			}
		}
	}

	out, err = exec.Command("bash", "-c",
		fmt.Sprintf("for d in /sys/class/net/veth*; do iflink=$(cat $d/iflink 2>/dev/null); [ \"$iflink\" = \"%d\" ] && basename $d && break; done",
			containerIfIndex)).CombinedOutput()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		vethName := strings.TrimSpace(string(out))
		out2, _ := exec.Command("ip", "link", "show", vethName).CombinedOutput()
		var ifIndex int
		fmt.Sscanf(strings.Split(string(out2), "\n")[0], "%d:", &ifIndex)
		if ifIndex > 0 {
			return uint32(ifIndex), nil
		}
	}

	return 0, fmt.Errorf("veth peer not found for container ifindex %d", containerIfIndex)
}

func registerRouteWithIfindex(podIP net.IP, ifindex uint32) error {
	mapPath := bpfMapPath + "/container_route"
	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("load pinned map: %w", err)
	}
	defer m.Close()

	ip4 := podIP.To4()
	if ip4 == nil {
		return fmt.Errorf("not an IPv4 address")
	}
	key := *(*uint32)(unsafe.Pointer(&ip4[0]))

	if err := m.Update(key, ifindex, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update map: %w", err)
	}
	log.Printf("[cni] registered route %s -> ifindex %d", podIP, ifindex)
	return nil
}

func unregisterRouteByContainerID(containerID string) {
	ip := loadContainerState(containerID)
	if ip == nil {
		return
	}

	mapPath := bpfMapPath + "/container_route"
	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Printf("[cni] load pinned map for delete: %v", err)
		return
	}
	defer m.Close()

	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	key := *(*uint32)(unsafe.Pointer(&ip4[0]))
	if err := m.Delete(key); err != nil {
		log.Printf("[cni] delete route from BPF map: %v", err)
	} else {
		log.Printf("[cni] unregistered route %s", ip)
	}
}

func attachTCToVethPeer(ifindex uint32) error {
	out, err := exec.Command("bash", "-c",
		fmt.Sprintf("for d in /sys/class/net/*; do cat $d/ifindex 2>/dev/null | grep -q %d && basename $d && break; done", ifindex)).CombinedOutput()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return fmt.Errorf("interface not found for ifindex %d", ifindex)
	}
	ifName := strings.TrimSpace(string(out))

	exec.Command("tc", "qdisc", "add", "dev", ifName, "clsact").Run()

	progPath := bpfMapPath + "/mesh_prog"
	if _, err := os.Stat(progPath); os.IsNotExist(err) {
		return fmt.Errorf("BPF program not pinned at %s", progPath)
	}

	cmd := exec.Command("tc", "filter", "add", "dev", ifName, "egress",
		"pref", "1", "handle", "1", "bpf", "direct-action", "pinned", progPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tc filter add: %w: %s", err, out)
	}

	log.Printf("[cni] TC egress attached to %s (ifindex %d)", ifName, ifindex)
	return nil
}

func cleanupTCFilters() {
	out, _ := exec.Command("bash", "-c", "ip link show type veth 2>/dev/null | grep -o 'veth[^:]*'").CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		ifName := strings.TrimSpace(line)
		if ifName == "" {
			continue
		}
		exec.Command("tc", "filter", "del", "dev", ifName, "egress", "pref", "1").Run()
	}
}

func saveContainerState(containerID string, ip net.IP) {
	os.MkdirAll(stateDir, 0755)
	path := filepath.Join(stateDir, containerID)
	os.WriteFile(path, []byte(ip.String()), 0644)
}

func loadContainerState(containerID string) net.IP {
	path := filepath.Join(stateDir, containerID)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return net.ParseIP(strings.TrimSpace(string(data)))
}

func removeContainerState(containerID string) {
	path := filepath.Join(stateDir, containerID)
	os.Remove(path)
}

func pluginMain() {
	skel.PluginMain(cniAddSk, nil, cniDelSk, version.All, "nomad-p2p v0.3.0")
}
