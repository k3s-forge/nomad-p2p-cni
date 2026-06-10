package main

import (
	"log"
	"os"
	"time"

	"github.com/nomad-p2p-cni/config"
)

func (a *Agent) configHotReload() {
	if a.configPath == "" {
		return
	}

	var lastModTime time.Time
	if info, err := os.Stat(a.configPath); err == nil {
		lastModTime = info.ModTime()
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			info, err := os.Stat(a.configPath)
			if err != nil {
				continue
			}
			if info.ModTime().After(lastModTime) {
				lastModTime = info.ModTime()
				a.reloadConfig()
			}
		}
	}
}

func (a *Agent) reloadConfig() {
	newCfg, err := config.Load(a.configPath)
	if err != nil {
		log.Printf("[agent] config reload failed: %v", err)
		return
	}

	log.Printf("[agent] config reloaded")

	if a.cfg.FirewallEnabled != newCfg.FirewallEnabled ||
		a.cfg.DefaultPolicy != newCfg.DefaultPolicy {
		a.cfg.FirewallEnabled = newCfg.FirewallEnabled
		a.cfg.DefaultPolicy = newCfg.DefaultPolicy
		a.reloadFirewallACLs(newCfg)
	}

	if stringSliceChanged(a.cfg.AllowedSources, newCfg.AllowedSources) {
		a.cfg.AllowedSources = newCfg.AllowedSources
		a.reloadFirewallACLs(newCfg)
	}

	if portRulesChanged(a.cfg.AllowedPorts, newCfg.AllowedPorts) {
		a.cfg.AllowedPorts = newCfg.AllowedPorts
		a.reloadFirewallACLs(newCfg)
	}

	if stringSliceChanged(a.cfg.VIPWatchList, newCfg.VIPWatchList) {
		a.cfg.VIPWatchList = newCfg.VIPWatchList
		log.Printf("[agent] VIP watch list updated: %v", newCfg.VIPWatchList)
	}

	if stringSliceChanged(a.cfg.StunServers, newCfg.StunServers) {
		a.cfg.StunServers = newCfg.StunServers
		log.Printf("[agent] STUN servers updated: %v", newCfg.StunServers)
	}

	if vipBackendsChanged(a.cfg.VIPBackends, newCfg.VIPBackends) {
		a.cfg.VIPBackends = newCfg.VIPBackends
		if a.cfg.VIPEnabled {
			a.updateVIPsFromConfig()
			log.Printf("[agent] VIP backends reloaded")
		}
	}
}

func stringSliceChanged(a, b []string) bool {
	if len(a) != len(b) {
		return true
	}
	m := make(map[string]bool, len(a))
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if !m[s] {
			return true
		}
	}
	return false
}

func portRulesChanged(a, b []config.PortRule) bool {
	if len(a) != len(b) {
		return true
	}
	for i := range a {
		if a[i].SourceIP != b[i].SourceIP ||
			a[i].Port != b[i].Port ||
			a[i].Protocol != b[i].Protocol ||
			a[i].Allow != b[i].Allow {
			return true
		}
	}
	return false
}

func vipBackendsChanged(a, b []config.VIPBackend) bool {
	if len(a) != len(b) {
		return true
	}
	for i := range a {
		if a[i].VIP != b[i].VIP {
			return true
		}
		if stringSliceChanged(a[i].Backends, b[i].Backends) {
			return true
		}
	}
	return false
}
