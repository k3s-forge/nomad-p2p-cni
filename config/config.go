package config

import (
	"encoding/json"
	"fmt"
	"os"
	"net"
)

type Config struct {
	// Node identity
	NodeOverlayIP string `json:"node_overlay_ip"` // e.g. "10.244.0.1"
	NodeSubnet    string `json:"node_subnet"`      // e.g. "10.244.1.0/24"

	// Seed nodes for bootstrap
	Seeds []SeedConfig `json:"seeds"`

	// Tunnel settings
	TunnelVNI    int    `json:"tunnel_vni"`
	TunnelDevice string `json:"tunnel_device"` // e.g. "gnv0"

	// Authentication
	PSK string `json:"psk"` // Pre-shared key for HMAC

	// NAT traversal
	StunServers []string `json:"stun_servers"`
	ListenPort  int      `json:"listen_port"` // UDP listen port for P2P

	// IPsec (optional)
	IPsecEnabled  bool   `json:"ipsec_enabled"`
	IPsecSPI      uint32 `json:"ipsec_spi"`
	IPsecKey      string `json:"ipsec_key"` // hex-encoded AES key

	// CNI settings
	CNIBinPath  string `json:"cni_bin_path"`
	MTU         int    `json:"mtu"`

	// VIP settings
	VIPEnabled   bool     `json:"vip_enabled"`
	VIPWatchList []string `json:"vip_watch_list"` // VIPs to watch
}

type SeedConfig struct {
	Addr string `json:"addr"` // IP:port or hostname
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
	return nil
}

func (c *Config) NodeOverlayIPBytes() net.IP {
	ip := net.ParseIP(c.NodeOverlayIP)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}
