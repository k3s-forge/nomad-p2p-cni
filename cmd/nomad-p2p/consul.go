package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
	"unsafe"
)

// ConsulService represents a Consul service instance
type ConsulService struct {
	ID      string   `json:"ID"`
	Service string   `json:"Service"`
	Address string   `json:"Address"`
	Port    int      `json:"Port"`
	Tags    []string `json:"Tags"`
	Meta    map[string]string `json:"Meta"`
}

// consulClient wraps HTTP calls to Consul API
type consulClient struct {
	addr    string
	token   string
	client  *http.Client
}

func newConsulClient(addr, token string) *consulClient {
	return &consulClient{
		addr:  addr,
		token: token,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// queryService returns all instances of a service
func (c *consulClient) queryService(service string) ([]ConsulService, error) {
	url := fmt.Sprintf("http://%s/v1/health/service/%s?passing=true", c.addr, service)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("X-Consul-Token", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("consul returned %d", resp.StatusCode)
	}

	var entries []struct {
		Service ConsulService `json:"Service"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	var services []ConsulService
	for _, e := range entries {
		services = append(services, e.Service)
	}
	return services, nil
}

// queryVIPBackends returns all healthy backend IPs for a VIP from Consul
func (c *consulClient) queryVIPBackends(vip string) ([]net.IP, error) {
	// List all services
	url := fmt.Sprintf("http://%s/v1/catalog/services", c.addr)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("X-Consul-Token", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var serviceNames map[string]map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&serviceNames); err != nil {
		return nil, err
	}

	// For each service, query healthy instances and collect backends matching the VIP
	var allBackends []net.IP
	for name := range serviceNames {
		instances, err := c.queryService(name)
		if err != nil {
			continue
		}
		for _, inst := range instances {
			// Match VIP by service address or meta["vip"] field
			if inst.Address == vip || inst.Meta["vip"] == vip {
				ip := net.ParseIP(inst.Address).To4()
				if ip != nil {
					allBackends = append(allBackends, ip)
				}
			}
		}
	}

	if len(allBackends) == 0 {
		return nil, fmt.Errorf("no healthy backends found for VIP %s", vip)
	}
	return allBackends, nil
}

// watchVIPsFromConsul polls Consul and updates BPF VIP_MAP
func (a *Agent) watchVIPsFromConsul() {
	if a.cfg.ConsulAddr == "" {
		// No Consul configured, use config-only mode
		return
	}

	client := newConsulClient(a.cfg.ConsulAddr, a.cfg.ConsulToken)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	log.Printf("[agent] watching VIPs from Consul at %s", a.cfg.ConsulAddr)

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.updateVIPsFromConsul(client)
		}
	}
}

func (a *Agent) updateVIPsFromConsul(client *consulClient) {
	if a.maps.VIPMap == nil {
		return
	}

	for _, vipStr := range a.cfg.VIPWatchList {
		vip := net.ParseIP(vipStr).To4()
		if vip == nil {
			continue
		}
		vipU := *(*uint32)(unsafe.Pointer(&vip[0]))

		// Start with static backends from config
		backends := a.getStaticVIPBackends(vipStr)

		// Merge in Consul-discovered backends
		consulBackends, err := client.queryVIPBackends(vipStr)
		if err != nil {
			log.Printf("[agent] VIP query failed for %s: %v", vipStr, err)
		} else {
			// Deduplicate
			existing := make(map[string]bool)
			for _, ip := range backends {
				existing[ip.String()] = true
			}
			for _, ip := range consulBackends {
				if !existing[ip.String()] {
					backends = append(backends, ip)
				}
			}
		}

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
		log.Printf("[agent] VIP %s updated: %d backends (static + consul)", vipStr, len(backends))
	}
}
