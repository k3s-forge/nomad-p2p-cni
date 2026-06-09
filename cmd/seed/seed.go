package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type NodeInfo struct {
	OverlayIP  net.IP `json:"overlay_ip"`
	PublicIP   string `json:"public_ip"`
	PublicPort int    `json:"public_port"`
	Subnet     string `json:"subnet"`
	LastSeen   int64  `json:"last_seen"`
}

type SeedServer struct {
	addr       string
	psk        string
	routeTable map[string]*NodeInfo
	mu         sync.RWMutex
}

type Message struct {
	Type     string         `json:"type"`
	NodeInfo *NodeInfo      `json:"node_info,omitempty"`
	QueryIP  string         `json:"query_ip,omitempty"`
	Nodes    []NodeInfo     `json:"nodes,omitempty"`
}

func NewSeedServer(addr, psk string) *SeedServer {
	return &SeedServer{
		addr:       addr,
		psk:        psk,
		routeTable: make(map[string]*NodeInfo),
	}
}

func (s *SeedServer) Run() error {
	conn, err := net.ListenPacket("udp4", s.addr)
	if err != nil {
		return fmt.Errorf("seed listen: %w", err)
	}
	defer conn.Close()

	log.Printf("[Seed] listening on %s", s.addr)

	go s.cleanupLoop()

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("[Seed] read error: %v", err)
			continue
		}
		go s.handlePacket(conn, remoteAddr, buf[:n])
	}
}

func (s *SeedServer) handlePacket(conn net.PacketConn, remoteAddr net.Addr, data []byte) {
	if len(data) < 32 {
		return
	}
	payload := data[:len(data)-32]
	sig := data[len(data)-32:]

	if !hmacVerify(s.psk, payload, sig) {
		log.Printf("[Seed] HMAC failed from %s", remoteAddr)
		return
	}

	var msg Message
	if err := json.Unmarshal(payload, &msg); err != nil {
		log.Printf("[Seed] unmarshal error: %v", err)
		return
	}

	switch msg.Type {
	case "register":
		s.handleRegister(msg, remoteAddr)
	case "query":
		s.handleQuery(conn, msg, remoteAddr)
	case "heartbeat":
		s.handleHeartbeat(msg, remoteAddr)
	default:
		log.Printf("[Seed] unknown type: %s", msg.Type)
	}
}

func (s *SeedServer) handleRegister(msg Message, remoteAddr net.Addr) {
	if msg.NodeInfo == nil {
		return
	}
	node := msg.NodeInfo
	node.LastSeen = time.Now().Unix()

	s.mu.Lock()
	s.routeTable[node.OverlayIP.String()] = node
	s.mu.Unlock()

	log.Printf("[Seed] registered %s -> %s:%d", node.OverlayIP, node.PublicIP, node.PublicPort)
}

func (s *SeedServer) handleQuery(conn net.PacketConn, msg Message, remoteAddr net.Addr) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var nodes []NodeInfo
	if msg.QueryIP == "" {
		for _, n := range s.routeTable {
			nodes = append(nodes, *n)
		}
	} else {
		if n, ok := s.routeTable[msg.QueryIP]; ok {
			nodes = []NodeInfo{*n}
		}
	}

	resp := Message{Type: "query_resp", Nodes: nodes}
	respData, _ := json.Marshal(resp)
	sig := hmacSign(s.psk, respData)
	full := append(respData, sig...)
	conn.WriteTo(full, remoteAddr)
}

func (s *SeedServer) handleHeartbeat(msg Message, remoteAddr net.Addr) {
	if msg.NodeInfo == nil {
		return
	}
	s.mu.Lock()
	if n, ok := s.routeTable[msg.NodeInfo.OverlayIP.String()]; ok {
		n.LastSeen = time.Now().Unix()
	}
	s.mu.Unlock()
}

func (s *SeedServer) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now().Unix()
		for ip, n := range s.routeTable {
			if now-n.LastSeen > 180 {
				delete(s.routeTable, ip)
				log.Printf("[Seed] cleaned stale node %s", ip)
			}
		}
		s.mu.Unlock()
	}
}

func hmacSign(psk string, data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(data)
	return mac.Sum(nil)
}

func hmacVerify(psk string, data, sig []byte) bool {
	expected := hmacSign(psk, data)
	return hmac.Equal(expected, sig)
}
