package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os/exec"
)

type ipSecManager struct {
	spi      uint32
	key      []byte
	localIP  net.IP
	remoteIP net.IP
}

func newIPSecManager(spi uint32, keyHex string, localIP, remoteIP net.IP) (*ipSecManager, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("key must be 16 or 32 bytes, got %d", len(key))
	}
	return &ipSecManager{spi: spi, key: key, localIP: localIP, remoteIP: remoteIP}, nil
}

func (m *ipSecManager) addSA() {
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
	log.Printf("[ipsec] SA added: %s <-> %s (SPI: %s)", m.localIP, m.remoteIP, spi)
}

func (m *ipSecManager) delSA() {
	spi := fmt.Sprintf("0x%08x", m.spi)
	exec.Command("ip", "xfrm", "state", "del",
		"src", m.localIP.String(), "dst", m.remoteIP.String(),
		"proto", "esp", "spi", spi).Run()
	exec.Command("ip", "xfrm", "policy", "del",
		"src", m.localIP.String()+"/32", "dst", m.remoteIP.String()+"/32",
		"dir", "out").Run()
}
