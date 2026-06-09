package main

import (
	"fmt"
	"log"
	"os/exec"
)

func (a *Agent) setupGeneveDevice() error {
	cmd := exec.Command("ip", "link", "show", a.cfg.TunnelDevice)
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("ip", "link", "add", a.cfg.TunnelDevice,
			"type", "geneve", "id", fmt.Sprintf("%d", a.cfg.TunnelVNI),
			"remote", "0.0.0.0", "port", "6081")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("create: %w: %s", err, out)
		}
	}
	cmd = exec.Command("ip", "link", "set", a.cfg.TunnelDevice,
		"mtu", fmt.Sprintf("%d", a.cfg.MTU), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("up: %w: %s", err, out)
	}
	cmd = exec.Command("ip", "addr", "replace", a.cfg.NodeOverlayIP+"/16", "dev", a.cfg.TunnelDevice)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("addr: %w: %s", err, out)
	}

	log.Printf("[agent] geneve %s = %s", a.cfg.TunnelDevice, a.cfg.NodeOverlayIP)
	return nil
}
