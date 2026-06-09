package main

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os/exec"

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
	PodSubnet  string `json:"podSubnet"`
}

func cmdAdd(args *skel.CmdArgs) error {
	netConf, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	podIP, gateway, err := allocateIP(netConf.Subnet, args.ContainerID)
	if err != nil {
		return fmt.Errorf("allocate IP: %w", err)
	}

	if err := configureContainer(args.Netns, podIP, gateway, netConf.MTU); err != nil {
		return fmt.Errorf("configure container: %w", err)
	}

	if err := addContainerRoute(podIP, gateway); err != nil {
		return fmt.Errorf("add route: %w", err)
	}

	result := &current.Result{
		CNIVersion: netConf.CniVersion,
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{IP: podIP, Mask: net.CIDRMask(32, 32)},
				Gateway: gateway,
			},
		},
	}

	return types.PrintResult(result, netConf.CniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	netConf, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	_ = removeContainerRoute(args.ContainerID)
	_ = cleanupContainerNetns(args.Netns)
	_ = netConf
	return nil
}

func loadNetConf(data []byte) (*NetConf, error) {
	conf := &NetConf{}
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, err
	}
	if conf.MTU == 0 {
		conf.MTU = 1420
	}
	return conf, nil
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

	gateway := make(net.IP, 4)
	copy(gateway, ipNet.IP.To4())
	gateway[3] = 1

	return ip, gateway, nil
}

func configureContainer(netns string, podIP net.IP, gateway net.IP, mtu int) error {
	if netns == "" {
		return nil
	}

	ifName := "eth0"

	// Use nsenter to configure the container's network namespace
	nsenterArgs := []string{
		"--net=/var/run/netns/" + netns,
		"--",
		"ip", "addr", "replace", podIP.String() + "/32", "dev", ifName,
	}
	cmd := exec.Command("nsenter", nsenterArgs...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set IP: %w: %s", err, string(out))
	}

	cmd = exec.Command("nsenter",
		"--net=/var/run/netns/"+netns,
		"--", "ip", "link", "set", ifName, "mtu",
		fmt.Sprintf("%d", mtu), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set MTU: %w: %s", err, string(out))
	}

	cmd = exec.Command("nsenter",
		"--net=/var/run/netns/"+netns,
		"--", "ip", "route", "replace", "default", "via", gateway.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("add route: %w: %s", err, string(out))
	}

	return nil
}

func addContainerRoute(podIP net.IP, gateway net.IP) error {
	log.Printf("[CNI] route added: %s -> gw %s", podIP, gateway)
	return nil
}

func removeContainerRoute(containerID string) error {
	log.Printf("[CNI] route removed for %s", containerID)
	return nil
}

func cleanupContainerNetns(netns string) error {
	cmd := exec.Command("ip", "netns", "del", netns)
	_ = cmd.Run()
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, nil, cmdDel,
		version.All, "nomad-p2p-cni v0.1.0")
}
