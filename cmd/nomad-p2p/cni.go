package main

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os"
	"os/exec"
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

const bpfMapPath = "/sys/fs/bpf/nomad-p2p"

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

		// Find the veth peer ifindex on the host side
		peerIfIndex, err := findVethPeerIndex(args.Netns)
		if err != nil {
			log.Printf("[cni] find veth peer: %v (non-fatal)", err)
		} else {
			// Register route with actual peer ifindex
			if err := registerRouteWithIfindex(podIP, peerIfIndex); err != nil {
				log.Printf("[cni] BPF route register: %v (non-fatal)", err)
			}

			// Attach TC egress program to the veth peer
			if err := attachTCToVethPeer(peerIfIndex); err != nil {
				log.Printf("[cni] TC attach to veth peer: %v (non-fatal)", err)
			} else {
				log.Printf("[cni] TC egress attached to veth peer %d", peerIfIndex)
			}
		}
	}

	log.Printf("[cni] ADD %s -> %s", args.ContainerID[:12], podIP)

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
	log.Printf("[cni] DEL %s", args.ContainerID[:12])

	// Try to remove TC filter from any veth we can find
	cleanupTCFilters()

	if args.Netns != "" {
		cmd := exec.Command("ip", "netns", "del", args.Netns)
		_ = cmd.Run()
	}
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

	log.Printf("[cni] ADD %s -> %s", containerID[:12], podIP)
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
	log.Printf("[cni] DEL %s", containerID[:12])
	cleanupTCFilters()
	if netns != "" {
		cmd := exec.Command("ip", "netns", "del", netns)
		_ = cmd.Run()
	}
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

// --- Veth peer discovery ---

// findVethPeerIndex finds the host-side veth peer index for a container
func findVethPeerIndex(netns string) (uint32, error) {
	// Find the ifindex of eth0 inside the container
	ns := "--net=/var/run/netns/" + netns
	out, err := exec.Command("nsenter", ns, "--", "ip", "link", "show", "eth0").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("show eth0 in ns: %w: %s", err, out)
	}

	// Parse: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1420 ... link/ether ... brd ..."
	lines := strings.Split(string(out), "\n")
	if len(lines) == 0 {
		return 0, fmt.Errorf("no output from ip link show eth0")
	}

	var containerIfIndex int
	fmt.Sscanf(lines[0], "%d:", &containerIfIndex)
	if containerIfIndex == 0 {
		return 0, fmt.Errorf("could not parse ifindex from: %s", lines[0])
	}

	// Find the veth peer on the host by looking for the peer link
	// Use ethtool or check /sys/class/net/*/iflink
	out, err = exec.Command("bash", "-c",
		fmt.Sprintf("for f in /sys/class/net/veth*/iflink; do [ -f \"$f\" ] && peer=$(cat \"$f\") && [ \"$peer\" = \"%d\" ] && basename $(dirname $(dirname $f)); done",
			containerIfIndex)).CombinedOutput()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		// Found the veth on host, get its ifindex
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

	// Fallback: find via /sys/class/net
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

// --- BPF Map integration ---

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

// --- TC program attachment to veth peers ---

func attachTCToVethPeer(ifindex uint32) error {
	// Find interface name from ifindex
	out, err := exec.Command("bash", "-c",
		fmt.Sprintf("for d in /sys/class/net/*; do cat $d/ifindex 2>/dev/null | grep -q %d && basename $d && break; done", ifindex)).CombinedOutput()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return fmt.Errorf("interface not found for ifindex %d", ifindex)
	}
	ifName := strings.TrimSpace(string(out))

	// Ensure clsact qdisc
	exec.Command("tc", "qdisc", "add", "dev", ifName, "clsact").Run()

	// Pin the TC program
	pinPath := fmt.Sprintf("/sys/fs/bpf/tc/egress_%d", ifindex)
	progPath := bpfMapPath + "/mesh_prog"

	// Try to find the pinned program
	if _, err := os.Stat(progPath); os.IsNotExist(err) {
		// No pinned program available, skip TC attach
		return fmt.Errorf("BPF program not pinned at %s", progPath)
	}

	// Attach TC filter
	cmd := exec.Command("tc", "filter", "add", "dev", ifName, "egress",
		"pref", "1", "handle", "1", "bpf", "direct-action", "pinned", progPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tc filter add: %w: %s", err, out)
	}

	log.Printf("[cni] TC egress attached to %s (ifindex %d)", ifName, ifindex)
	return nil
}

func cleanupTCFilters() {
	// Best effort cleanup of TC filters on all veth interfaces
	out, _ := exec.Command("bash", "-c", "ip link show type veth 2>/dev/null | grep -o 'veth[^:]*'").CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		ifName := strings.TrimSpace(line)
		if ifName == "" {
			continue
		}
		exec.Command("tc", "filter", "del", "dev", ifName, "egress", "pref", "1").Run()
	}
}

func pluginMain() {
	skel.PluginMain(cniAddSk, nil, cniDelSk, version.All, "nomad-p2p v0.3.0")
}
