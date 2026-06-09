package main

import (
	"log"
	"net"
	"unsafe"

	"github.com/nomad-p2p-cni/config"
)

func (a *Agent) loadACLsFromConfig() {
	if !a.cfg.FirewallEnabled || a.maps.ACLMap == nil {
		return
	}

	if a.maps.DefaultPolicy != nil {
		key := uint32(0)
		val := uint8(0)
		if a.cfg.DefaultPolicy == "allow" {
			val = 1
		}
		a.maps.DefaultPolicy.Update(key, val, 0)
		log.Printf("[agent] firewall default policy: %s", a.cfg.DefaultPolicy)
	}

	for _, srcIP := range a.cfg.AllowedSources {
		ip := net.ParseIP(srcIP).To4()
		if ip == nil {
			continue
		}
		ipU := *(*uint32)(unsafe.Pointer(&ip[0]))
		allow := uint8(1)
		a.maps.ACLMap.Update(ipU, allow, 0)
		log.Printf("[agent] ACL: allow %s", srcIP)
	}

	for _, rule := range a.cfg.AllowedPorts {
		srcIP := net.ParseIP(rule.SourceIP).To4()
		if srcIP == nil {
			continue
		}
		srcU := *(*uint32)(unsafe.Pointer(&srcIP[0]))
		portKey := (uint64(srcU) << 32) | uint64(rule.Port)
		var allow uint8
		if rule.Allow {
			allow = 1
		}
		a.maps.PortACLMap.Update(portKey, allow, 0)
		log.Printf("[agent] port ACL: %s %s/%d -> %v",
			rule.Protocol, rule.SourceIP, rule.Port, rule.Allow)
	}

	log.Printf("[agent] loaded %d IP rules, %d port rules",
		len(a.cfg.AllowedSources), len(a.cfg.AllowedPorts))
}

func (a *Agent) reloadFirewallACLs(newCfg *config.Config) {
	if a.maps.ACLMap == nil {
		return
	}

	if a.maps.DefaultPolicy != nil {
		key := uint32(0)
		val := uint8(0)
		if newCfg.DefaultPolicy == "allow" {
			val = 1
		}
		a.maps.DefaultPolicy.Update(key, val, 0)
	}

	var key uint32
	var val uint8
	iter := a.maps.ACLMap.Iterate()
	for iter.Next(&key, &val) {
		a.maps.ACLMap.Delete(key)
	}

	if a.maps.PortACLMap != nil {
		var portKey uint64
		var portVal uint8
		portIter := a.maps.PortACLMap.Iterate()
		for portIter.Next(&portKey, &portVal) {
			a.maps.PortACLMap.Delete(portKey)
		}
	}

	a.cfg.AllowedSources = newCfg.AllowedSources
	a.cfg.AllowedPorts = newCfg.AllowedPorts
	a.loadACLsFromConfig()
	log.Printf("[agent] firewall ACLs reloaded")
}
