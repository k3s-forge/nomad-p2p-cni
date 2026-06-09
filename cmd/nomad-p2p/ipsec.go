package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
)

type ipSecManager struct {
	spi      uint32
	key      []byte
	localIP  net.IP
	remoteIP net.IP
	mu       sync.Mutex
	peers    map[string]bool // track which peers have SAs
}

func newIPSecManager(spi uint32, keyHex string, localIP, remoteIP net.IP) (*ipSecManager, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("key must be 16 or 32 bytes, got %d", len(key))
	}
	return &ipSecManager{
		spi:     spi,
		key:     key,
		localIP: localIP,
		peers:   make(map[string]bool),
	}, nil
}

func (m *ipSecManager) addSA() {
	m.mu.Lock()
	defer m.mu.Unlock()

	spi := fmt.Sprintf("0x%08x", m.spi)
	key := hex.EncodeToString(m.key)

	cmd := exec.Command("ip", "xfrm", "state", "add",
		"src", m.localIP.String(), "dst", m.remoteIP.String(),
		"proto", "esp", "spi", spi, "enc", "aes-gcm", key,
		"mode", "tunnel", "replay-window", "128")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[ipsec] state add: %v: %s", err, out)
		return
	}

	cmd = exec.Command("ip", "xfrm", "policy", "add",
		"src", m.localIP.String()+"/32", "dst", m.remoteIP.String()+"/32",
		"dir", "out", "tmpl",
		"src", m.localIP.String(), "dst", m.remoteIP.String(),
		"proto", "esp", "spi", spi, "mode", "tunnel")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[ipsec] policy add: %v: %s", err, out)
		return
	}
	m.peers[m.remoteIP.String()] = true
	log.Printf("[ipsec] SA added: %s <-> %s (SPI: %s)", m.localIP, m.remoteIP, spi)
}

func (m *ipSecManager) addSAForPeer(peerIP net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()

	peerStr := peerIP.String()
	if m.peers[peerStr] {
		return // already have SA for this peer
	}

	spi := fmt.Sprintf("0x%08x", m.spi)
	key := hex.EncodeToString(m.key)

	cmd := exec.Command("ip", "xfrm", "state", "add",
		"src", m.localIP.String(), "dst", peerStr,
		"proto", "esp", "spi", spi, "enc", "aes-gcm", key,
		"mode", "tunnel", "replay-window", "128")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[ipsec] state add for %s: %v: %s", peerStr, err, out)
		return
	}

	cmd = exec.Command("ip", "xfrm", "policy", "add",
		"src", m.localIP.String()+"/32", "dst", peerStr+"/32",
		"dir", "out", "tmpl",
		"src", m.localIP.String(), "dst", peerStr,
		"proto", "esp", "spi", spi, "mode", "tunnel")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[ipsec] policy add for %s: %v: %s", peerStr, err, out)
		return
	}

	// Also add inbound SA (reverse direction)
	cmd = exec.Command("ip", "xfrm", "state", "add",
		"src", peerStr, "dst", m.localIP.String(),
		"proto", "esp", "spi", spi, "enc", "aes-gcm", key,
		"mode", "tunnel", "replay-window", "128")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[ipsec] inbound state add for %s: %v: %s", peerStr, err, out)
	}

	cmd = exec.Command("ip", "xfrm", "policy", "add",
		"src", peerStr+"/32", "dst", m.localIP.String()+"/32",
		"dir", "in", "tmpl",
		"src", peerStr, "dst", m.localIP.String(),
		"proto", "esp", "spi", spi, "mode", "tunnel")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[ipsec] inbound policy add for %s: %v: %s", peerStr, err, out)
	}

	m.peers[peerStr] = true
	log.Printf("[ipsec] SA added for peer %s (SPI: %s)", peerStr, spi)
}

func (m *ipSecManager) delSA() {
	m.mu.Lock()
	defer m.mu.Unlock()

	spi := fmt.Sprintf("0x%08x", m.spi)

	// Delete outbound SA
	exec.Command("ip", "xfrm", "state", "del",
		"src", m.localIP.String(), "dst", m.remoteIP.String(),
		"proto", "esp", "spi", spi).Run()
	exec.Command("ip", "xfrm", "policy", "del",
		"src", m.localIP.String()+"/32", "dst", m.remoteIP.String()+"/32",
		"dir", "out").Run()

	// Delete inbound SA
	exec.Command("ip", "xfrm", "state", "del",
		"src", m.remoteIP.String(), "dst", m.localIP.String(),
		"proto", "esp", "spi", spi).Run()
	exec.Command("ip", "xfrm", "policy", "del",
		"src", m.remoteIP.String()+"/32", "dst", m.localIP.String()+"/32",
		"dir", "in").Run()

	// Delete all peer SAs
	for peerStr := range m.peers {
		exec.Command("ip", "xfrm", "state", "del",
			"src", m.localIP.String(), "dst", peerStr,
			"proto", "esp", "spi", spi).Run()
		exec.Command("ip", "xfrm", "state", "del",
			"src", peerStr, "dst", m.localIP.String(),
			"proto", "esp", "spi", spi).Run()
	}
	m.peers = make(map[string]bool)
}
