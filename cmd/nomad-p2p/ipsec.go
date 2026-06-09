package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"
)

type ipSecManager struct {
	spi     uint32
	key     []byte
	localIP net.IP
	mu      sync.Mutex
	peers   map[string]bool
}

func newIPSecManager(spi uint32, keyHex string, localIP net.IP) (*ipSecManager, error) {
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

func (m *ipSecManager) addSAForPeer(peerIP net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()

	peerStr := peerIP.String()
	if m.peers[peerStr] {
		return
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
		log.Printf("[ipsec] outbound policy add for %s: %v: %s", peerStr, err, out)
		return
	}

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

	for peerStr := range m.peers {
		exec.Command("ip", "xfrm", "state", "del",
			"src", m.localIP.String(), "dst", peerStr,
			"proto", "esp", "spi", spi).Run()
		exec.Command("ip", "xfrm", "policy", "del",
			"src", m.localIP.String()+"/32", "dst", peerStr+"/32",
			"dir", "out").Run()
		exec.Command("ip", "xfrm", "state", "del",
			"src", peerStr, "dst", m.localIP.String(),
			"proto", "esp", "spi", spi).Run()
		exec.Command("ip", "xfrm", "policy", "del",
			"src", peerStr+"/32", "dst", m.localIP.String()+"/32",
			"dir", "in").Run()
	}
	m.peers = make(map[string]bool)
}

func (a *Agent) setupIPsec() {
	localIP := net.ParseIP(a.cfg.NodeOverlayIP).To4()
	if localIP == nil {
		return
	}
	mgr, err := newIPSecManager(a.cfg.IPsecSPI, a.cfg.IPsecKey, localIP)
	if err != nil {
		log.Printf("[agent] ipsec: %v", err)
		return
	}
	a.ipSecMgr = mgr
	log.Printf("[agent] IPsec enabled (SPI: 0x%08x)", a.cfg.IPsecSPI)
}

func (a *Agent) ipsecRotationLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			if a.ipSecMgr == nil {
				continue
			}
			newSPI := make([]byte, 4)
			rand.Read(newSPI)
			oldSPI := a.ipSecMgr.spi
			a.ipSecMgr.spi = binary.BigEndian.Uint32(newSPI)

			oldPeers := make([]string, 0, len(a.ipSecMgr.peers))
			for p := range a.ipSecMgr.peers {
				oldPeers = append(oldPeers, p)
			}

			for _, peerStr := range oldPeers {
				peerIP := net.ParseIP(peerStr)
				if peerIP != nil {
					a.ipSecMgr.addSAForPeer(peerIP)
				}
			}

			a.ipSecMgr.mu.Lock()
			spi := fmt.Sprintf("0x%08x", oldSPI)
			for _, peerStr := range oldPeers {
				exec.Command("ip", "xfrm", "state", "del",
					"src", a.ipSecMgr.localIP.String(), "dst", peerStr,
					"proto", "esp", "spi", spi).Run()
				exec.Command("ip", "xfrm", "state", "del",
					"src", peerStr, "dst", a.ipSecMgr.localIP.String(),
					"proto", "esp", "spi", spi).Run()
			}
			a.ipSecMgr.mu.Unlock()

			log.Printf("[agent] IPsec SA rotated (new SPI: 0x%08x)", a.ipSecMgr.spi)
		}
	}
}
