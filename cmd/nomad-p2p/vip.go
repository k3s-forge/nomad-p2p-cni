package main

import (
	"log"
	"net"
	"time"
	"unsafe"
)

func (a *Agent) watchVIPs() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.updateVIPsFromConfig()
		}
	}
}

func (a *Agent) updateVIPsFromConfig() {
	if a.maps.VIPMap == nil {
		return
	}
	for _, vipStr := range a.cfg.VIPWatchList {
		vip := net.ParseIP(vipStr).To4()
		if vip == nil {
			continue
		}
		vipU := *(*uint32)(unsafe.Pointer(&vip[0]))

		backends := a.getStaticVIPBackends(vipStr)
		if len(backends) == 0 {
			continue
		}

		info := VIPInfo{
			Count:   uint8(len(backends)),
			NextIdx: 0,
		}
		for i, backend := range backends {
			if i >= 16 {
				break
			}
			info.Backends[i] = *(*uint32)(unsafe.Pointer(&backend[0]))
		}
		a.maps.VIPMap.Update(vipU, info, 0)
	}
}

func (a *Agent) getStaticVIPBackends(vipStr string) []net.IP {
	for _, vb := range a.cfg.VIPBackends {
		if vb.VIP == vipStr {
			var ips []net.IP
			for _, addr := range vb.Backends {
				if ip := net.ParseIP(addr); ip != nil {
					ips = append(ips, ip)
				}
			}
			return ips
		}
	}
	return nil
}

func (a *Agent) updateVIPMap(vipStr string, backends []net.IP) {
	if a.maps.VIPMap == nil || len(backends) == 0 {
		return
	}
	vip := net.ParseIP(vipStr).To4()
	if vip == nil {
		return
	}
	vipU := *(*uint32)(unsafe.Pointer(&vip[0]))

	info := VIPInfo{
		Count:   uint8(len(backends)),
		NextIdx: 0,
	}
	for i, backend := range backends {
		if i >= 16 {
			break
		}
		info.Backends[i] = *(*uint32)(unsafe.Pointer(&backend[0]))
	}
	a.maps.VIPMap.Update(vipU, info, 0)
	log.Printf("[agent] VIP %s updated: %d backends", vipStr, len(backends))
}
