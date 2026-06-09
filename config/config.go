package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
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

	// STUN refresh interval (seconds, default 120)
	StunRefreshInterval int `json:"stun_refresh_interval"`

	// IPsec (optional)
	IPsecEnabled  bool   `json:"ipsec_enabled"`
	IPsecSPI      uint32 `json:"ipsec_spi"`
	IPsecKey      string `json:"ipsec_key"` // hex-encoded AES key

	// CNI settings
	CNIBinPath string `json:"cni_bin_path"`
	MTU        int    `json:"mtu"`

	// VIP settings
	VIPEnabled   bool     `json:"vip_enabled"`
	VIPWatchList []string `json:"vip_watch_list"` // VIPs to watch

	// Consul integration
	ConsulAddr  string `json:"consul_addr"`  // Consul HTTP address (e.g. "127.0.0.1:8500")
	ConsulToken string `json:"consul_token"` // Consul ACL token (optional)

	// Firewall ACL settings
	FirewallEnabled bool          `json:"firewall_enabled"`
	DefaultPolicy   string        `json:"default_policy"` // "allow" or "deny"
	AllowedSources  []string      `json:"allowed_sources"` // IPs allowed to reach this node
	AllowedPorts    []PortRule    `json:"allowed_ports"`   // port-level rules
}

type SeedConfig struct {
	Addr string `json:"addr"` // IP:port or hostname
}

type PortRule struct {
	SourceIP string `json:"source_ip"` // source IP
	Port     int    `json:"port"`      // destination port
	Protocol string `json:"protocol"`  // "tcp" or "udp"
	Allow    bool   `json:"allow"`     // true=allow, false=deny
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
	return nil
}

func (c *Config) NodeOverlayIPBytes() net.IP {
	ip := net.ParseIP(c.NodeOverlayIP)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}
