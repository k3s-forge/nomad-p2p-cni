package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

type IPSecManager struct {
	spi      uint32
	key      []byte
	localIP  net.IP
	remoteIP net.IP
}

func NewIPSecManager(spi uint32, keyHex string, localIP, remoteIP net.IP) (*IPSecManager, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid IPsec key: %w", err)
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("IPsec key must be 16 or 32 bytes, got %d", len(key))
	}
	return &IPSecManager{
		spi:      spi,
		key:      key,
		localIP:  localIP,
		remoteIP: remoteIP,
	}, nil
}

func (m *IPSecManager) AddSA() error {
_spi := fmt.Sprintf("0x%08x", m.spi)
_spiHex := hex.EncodeToString(m.key)

	// Use AES-GCM for encryption
	cmd := exec.Command("ip", "xfrm", "state", "add",
		"src", m.localIP.String(), "dst", m.remoteIP.String(),
		"proto", "esp",
		"spi", _spi,
		"enc", "aes-gcm", _spiHex,
		"mode", "tunnel",
		"replay-window", "128",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("add SA: %w: %s", err, string(out))
	}

	// Add policy
	cmd = exec.Command("ip", "xfrm", "policy", "add",
		"src", m.localIP.String()+"/32",
		"dst", m.remoteIP.String()+"/32",
		"dir", "out",
		"tmpl",
		"src", m.localIP.String(),
		"dst", m.remoteIP.String(),
		"proto", "esp",
		"spi", _spi,
		"mode", "tunnel",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("add policy: %w: %s", err, string(out))
	}

	log.Printf("[IPsec] added SA: %s <-> %s (SPI: 0x%08x)", m.localIP, m.remoteIP, m.spi)
	return nil
}

func (m *IPSecManager) DelSA() error {
	_spi := fmt.Sprintf("0x%08x", m.spi)

	cmd := exec.Command("ip", "xfrm", "state", "del",
		"src", m.localIP.String(), "dst", m.remoteIP.String(),
		"proto", "esp",
		"spi", _spi,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("del SA: %w: %s", err, string(out))
	}

	cmd = exec.Command("ip", "xfrm", "policy", "del",
		"src", m.localIP.String()+"/32",
		"dst", m.remoteIP.String()+"/32",
		"dir", "out",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("del policy: %w: %s", err, string(out))
	}

	log.Printf("[IPsec] removed SA: %s <-> %s", m.localIP, m.remoteIP)
	return nil
}

func (m *IPSecManager) RotateKey(newKeyHex string) error {
	newKey, err := hex.DecodeString(newKeyHex)
	if err != nil {
		return fmt.Errorf("invalid new key: %w", err)
	}

	// Delete old SA
	_ = m.DelSA()

	// Update key
	m.key = newKey
	m.spi++

	// Add new SA
	return m.AddSA()
}

func (m *IPSecManager) DumpStates() (string, error) {
	cmd := exec.Command("ip", "xfrm", "state", "list")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("dump states: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
