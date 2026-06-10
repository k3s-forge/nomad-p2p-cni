package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

type Config struct {
	NodeOverlayIP string `json:"node_overlay_ip"`
	NodeSubnet    string `json:"node_subnet"`

	Seeds []SeedConfig `json:"seeds"`

	TunnelVNI    int    `json:"tunnel_vni"`
	TunnelDevice string `json:"tunnel_device"`

	PSK string `json:"psk"`

	StunServers         []string `json:"stun_servers"`
	ListenPort          int      `json:"listen_port"`
	StunRefreshInterval int      `json:"stun_refresh_interval"`

	LazyDiscovery       bool `json:"lazy_discovery"`
	RouteMissMaxPending int  `json:"route_miss_max_pending"`

	IPsecEnabled bool   `json:"ipsec_enabled"`
	IPsecSPI     uint32 `json:"ipsec_spi"`
	IPsecKey     string `json:"ipsec_key"`

	CNIBinPath string `json:"cni_bin_path"`
	MTU        int    `json:"mtu"`

	VIPEnabled   bool         `json:"vip_enabled"`
	VIPWatchList []string     `json:"vip_watch_list"`
	VIPBackends  []VIPBackend `json:"vip_backends"`

	FirewallEnabled bool       `json:"firewall_enabled"`
	DefaultPolicy   string     `json:"default_policy"`
	AllowedSources  []string   `json:"allowed_sources"`
	AllowedPorts    []PortRule `json:"allowed_ports"`

	MetricsPort int `json:"metrics_port"`
}

type SeedConfig struct {
	Addr string `json:"addr"`
}

type PortRule struct {
	SourceIP string `json:"source_ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Allow    bool   `json:"allow"`
}

type VIPBackend struct {
	VIP      string   `json:"vip"`
	Backends []string `json:"backends"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.NodeOverlayIP == "" {
		return fmt.Errorf("node_overlay_ip is required")
	}
	if net.ParseIP(c.NodeOverlayIP) == nil {
		return fmt.Errorf("invalid node_overlay_ip: %s", c.NodeOverlayIP)
	}
	if c.PSK == "" {
		return fmt.Errorf("psk is required")
	}
	if c.ListenPort == 0 {
		c.ListenPort = 9527
	}
	if c.TunnelVNI == 0 {
		c.TunnelVNI = 100
	}
	if c.TunnelDevice == "" {
		c.TunnelDevice = "gnv0"
	}
	if c.MTU == 0 {
		c.MTU = 1420
	}
	if len(c.Seeds) == 0 {
		return fmt.Errorf("at least one seed node is required")
	}
	if len(c.StunServers) == 0 {
		c.StunServers = []string{"stun.l.google.com:19302"}
	}
	if c.StunRefreshInterval == 0 {
		c.StunRefreshInterval = 120
	}
	if c.DefaultPolicy == "" {
		c.DefaultPolicy = "allow"
	}
	if c.RouteMissMaxPending == 0 {
		c.RouteMissMaxPending = 256
	}
	if c.MetricsPort == 0 {
		c.MetricsPort = 9090
	}
	return nil
}

func (c *Config) NodeOverlayIPBytes() net.IP {
	ip := net.ParseIP(c.NodeOverlayIP)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}
