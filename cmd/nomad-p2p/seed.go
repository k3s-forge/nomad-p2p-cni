package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
	"unsafe"
)

const (
	seedEntryTTL = 5 * time.Minute
)

type seedRegistry struct {
	table    map[string]*seedEntry
	mu       sync.RWMutex
	nonces   map[string]time.Time
	nonceMu  sync.Mutex

	// Relay tracking: queryID -> original requester addr
	relayPending map[string]*net.UDPAddr
	relayMu      sync.Mutex
}

type seedEntry struct {
	node      *NodeRegistration
	updatedAt time.Time
}

type NodeRegistration struct {
	OverlayIP    string `json:"overlay_ip"`
	PublicIP     string `json:"public_ip"`
	PublicPort   int    `json:"public_port"`
	Subnet       string `json:"subnet"`
	RelayCapable bool   `json:"relay_capable"`
	NATType      string `json:"nat_type"`
}

func newSeedRegistry() *seedRegistry {
	return &seedRegistry{
		table:       make(map[string]*seedEntry),
		nonces:      make(map[string]time.Time),
		relayPending: make(map[string]*net.UDPAddr),
	}
}

func (s *seedRegistry) register(node *NodeRegistration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.table[node.OverlayIP] = &seedEntry{node: node, updatedAt: time.Now()}
}

func (s *seedRegistry) lookup(ip string) *NodeRegistration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e, ok := s.table[ip]; ok {
		return e.node
	}
	return nil
}

func (s *seedRegistry) all() []NodeRegistration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []NodeRegistration
	for _, e := range s.table {
		out = append(out, *e.node)
	}
	return out
}

func (s *seedRegistry) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for ip, e := range s.table {
		if now.Sub(e.updatedAt) > seedEntryTTL {
			delete(s.table, ip)
		}
	}
}

func (s *seedRegistry) checkNonce(nonce string) bool {
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()

	now := time.Now()
	if _, seen := s.nonces[nonce]; seen {
		return false
	}

	for n, t := range s.nonces {
		if now.Sub(t) > replayWindow {
			delete(s.nonces, n)
		}
	}

	s.nonces[nonce] = now
	return true
}

func (a *Agent) handleRegister(msg Message) {
	if msg.NodeInfo == nil {
		return
	}
	a.registry.register(msg.NodeInfo)
	a.metrics.inc("seed_registrations")
	log.Printf("[seed] registered %s -> %s:%d (relay=%v, nat=%s)",
		msg.NodeInfo.OverlayIP, msg.NodeInfo.PublicIP,
		msg.NodeInfo.PublicPort, msg.NodeInfo.RelayCapable, msg.NodeInfo.NATType)
}

func (a *Agent) handleQuery(msg Message, remote net.Addr) {
	var nodes []NodeRegistration
	if msg.QueryIP == "" {
		nodes = a.registry.all()
	} else {
		if n := a.registry.lookup(msg.QueryIP); n != nil {
			nodes = []NodeRegistration{*n}
		}
	}
	a.sendMessage(Message{Type: "query_resp", Nodes: nodes}, remote)
}

func (a *Agent) handleQueryResponse(msg Message) {
	if msg.QueryID != "" {
		a.registry.relayMu.Lock()
		origAddr, ok := a.registry.relayPending[msg.QueryID]
		if ok {
			delete(a.registry.relayPending, msg.QueryID)
		}
		a.registry.relayMu.Unlock()
		if ok {
			log.Printf("[seed] relaying response for qid=%s to %s", msg.QueryID, origAddr)
			a.sendMessage(Message{Type: "query_resp", Nodes: msg.Nodes, QueryID: msg.QueryID}, origAddr)
			return
		}
	}

	for _, node := range msg.Nodes {
		overlayIP := net.ParseIP(node.OverlayIP).To4()
		publicIP := net.ParseIP(node.PublicIP).To4()
		if overlayIP == nil || publicIP == nil {
			continue
		}
		overlayU := *(*uint32)(unsafe.Pointer(&overlayIP[0]))
		publicU := *(*uint32)(unsafe.Pointer(&publicIP[0]))

		ep := NodeEndpoint{PublicIP: publicU, PublicPort: uint16(node.PublicPort)}
		a.maps.NodeDynamicMap.Update(overlayU, ep, 0)

		a.routeMissMu.Lock()
		delete(a.routeMissPending, node.OverlayIP)
		a.routeMissMu.Unlock()

		a.mu.Lock()
		a.peerBook[overlayU] = &PeerInfo{
			Addr:         &net.UDPAddr{IP: publicIP, Port: node.PublicPort},
			RelayCapable: node.RelayCapable,
			NATType:      NATType(node.NATType),
		}
		a.mu.Unlock()
		a.metrics.setGauge("peers_total", float64(len(a.peerBook)))
		log.Printf("[agent] node %s -> %s:%d (nat=%s, relay=%v)",
			node.OverlayIP, node.PublicIP, node.PublicPort, node.NATType, node.RelayCapable)

		if a.cfg.IPsecEnabled && a.ipSecMgr != nil {
			remoteIP := net.ParseIP(node.PublicIP).To4()
			if remoteIP != nil {
				a.ipSecMgr.addSAForPeer(remoteIP)
			}
		}
	}
}

func (a *Agent) handleRelayRequest(msg Message, remote net.Addr) {
	if !a.seedMode || msg.Relay == nil || msg.QueryID == "" {
		return
	}
	log.Printf("[seed] relay request for %s via %s:%d (qid=%s)",
		msg.QueryIP, msg.Relay.RelayIP, msg.Relay.RelayPort, msg.QueryID)

	a.registry.relayMu.Lock()
	a.registry.relayPending[msg.QueryID] = remote.(*net.UDPAddr)
	a.registry.relayMu.Unlock()

	relayAddr := fmt.Sprintf("%s:%d", msg.Relay.RelayIP, msg.Relay.RelayPort)
	udpAddr, err := net.ResolveUDPAddr("udp4", relayAddr)
	if err != nil {
		a.registry.relayMu.Lock()
		delete(a.registry.relayPending, msg.QueryID)
		a.registry.relayMu.Unlock()
		return
	}
	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		a.registry.relayMu.Lock()
		delete(a.registry.relayPending, msg.QueryID)
		a.registry.relayMu.Unlock()
		return
	}
	defer conn.Close()
	a.sendToSeed(conn, Message{Type: "query", QueryIP: msg.QueryIP, QueryID: msg.QueryID})
}

func (a *Agent) bootstrapFromSeeds() {
	for _, seed := range a.cfg.Seeds {
		go a.registerWithSeed(seed.Addr)
	}
}

func (a *Agent) registerWithSeed(addr string) {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return
	}
	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		return
	}
	a.mu.Lock()
	a.seedConns[addr] = conn
	a.mu.Unlock()

	reg := NodeRegistration{
		OverlayIP:    a.cfg.NodeOverlayIP,
		PublicIP:     a.publicIP.String(),
		PublicPort:   a.publicPort,
		Subnet:       a.cfg.NodeSubnet,
		RelayCapable: a.seedMode,
		NATType:      string(a.natType),
	}
	a.sendToSeed(conn, Message{Type: "register", NodeInfo: &reg})

	if !a.cfg.LazyDiscovery {
		a.sendToSeed(conn, Message{Type: "query"})
	}
}

func (a *Agent) registerSelf() {
	reg := NodeRegistration{
		OverlayIP:    a.cfg.NodeOverlayIP,
		PublicIP:     a.publicIP.String(),
		PublicPort:   a.publicPort,
		Subnet:       a.cfg.NodeSubnet,
		RelayCapable: true,
		NATType:      string(a.natType),
	}
	a.registry.register(&reg)
	log.Printf("[seed] self-registered %s -> %s:%d (nat=%s)", reg.OverlayIP, reg.PublicIP, reg.PublicPort, reg.NATType)
}

func (a *Agent) heartbeatLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			reg := NodeRegistration{
				OverlayIP:    a.cfg.NodeOverlayIP,
				PublicIP:     a.publicIP.String(),
				PublicPort:   a.publicPort,
				Subnet:       a.cfg.NodeSubnet,
				RelayCapable: a.seedMode,
				NATType:      string(a.natType),
			}
			a.mu.RLock()
			for _, conn := range a.seedConns {
				a.sendToSeed(conn, Message{Type: "heartbeat", NodeInfo: &reg})
			}
			a.mu.RUnlock()
		}
	}
}

func (a *Agent) peerHealthLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.registry.cleanup()

			a.routeMissMu.Lock()
			now := time.Now()
			for ip, t := range a.routeMissPending {
				if now.Sub(t) > time.Minute {
					delete(a.routeMissPending, ip)
				}
			}
			a.routeMissMu.Unlock()

			a.mu.RLock()
			stalePeers := make([]uint32, 0)
			for overlayIP, peer := range a.peerBook {
				var ep NodeEndpoint
				if err := a.maps.NodeDynamicMap.Lookup(overlayIP, &ep); err != nil {
					stalePeers = append(stalePeers, overlayIP)
					continue
				}
				if peer.PingOK && time.Since(peer.PingLastSuccess) > 5*time.Minute {
					stalePeers = append(stalePeers, overlayIP)
				}
			}
			a.mu.RUnlock()

			for _, ip := range stalePeers {
				a.maps.NodeDynamicMap.Delete(ip)
				a.mu.Lock()
				delete(a.peerBook, ip)
				a.mu.Unlock()
				ipBytes := make(net.IP, 4)
				binary.BigEndian.PutUint32(ipBytes, ip)
				log.Printf("[agent] removed stale peer %s", ipBytes)
			}
			a.metrics.setGauge("peers_total", float64(len(a.peerBook)))
		}
	}
}

func (a *Agent) pingPeer(overlayIP uint32, peer *PeerInfo) {
	reg := NodeRegistration{
		OverlayIP:    a.cfg.NodeOverlayIP,
		PublicIP:     a.publicIP.String(),
		PublicPort:   a.publicPort,
		Subnet:       a.cfg.NodeSubnet,
		RelayCapable: a.seedMode,
		NATType:      string(a.natType),
	}
	a.sendMessage(Message{Type: "ping", NodeInfo: &reg}, peer.Addr)
}

func (a *Agent) pingAllPeers() {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for overlayIP, peer := range a.peerBook {
		go a.pingPeer(overlayIP, peer)
	}
}

func (a *Agent) peerPingLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.pingAllPeers()
		}
	}
}
