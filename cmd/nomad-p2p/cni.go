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

// skel-compatible wrappers
func cniAddSk(args *skel.CmdArgs) error {
	return cniAddSkImpl(args)
}

func cniDelSk(args *skel.CmdArgs) error {
	return cniDelSkImpl(args)
}

func cniAddSkImpl(args *skel.CmdArgs) error {
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
	}

	log.Printf("[cni] ADD %s -> %s gw %s", args.ContainerID[:12], podIP, gateway)

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

func cniDelSkImpl(args *skel.CmdArgs) error {
	log.Printf("[cni] DEL %s", args.ContainerID[:12])
	if args.Netns != "" {
		cmd := exec.Command("ip", "netns", "del", args.Netns)
		_ = cmd.Run()
	}
	return nil
}

// Non-skel wrappers for direct invocation
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

func pluginMain() {
	skel.PluginMain(cniAddSk, nil, cniDelSk, version.All, "nomad-p2p v0.2.0")
}
