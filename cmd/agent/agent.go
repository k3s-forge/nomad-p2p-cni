package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/nomad-p2p-cni/config"
)

type BPFMaps struct {
	ContainerRouteMap *ebpf.Map
	NodeDynamicMap    *ebpf.Map
	RouteMissRingbuf  *ebpf.Map
	VIPMap            *ebpf.Map
	ACLMap            *ebpf.Map
	PortACLMap        *ebpf.Map
}

type Agent struct {
	cfg        *config.Config
	maps       *BPFMaps
	conn       *net.UDPConn
	publicIP   net.IP
	publicPort int
	seedConns  map[string]*net.UDPConn
	peerBook   map[uint32]*net.UDPAddr
	mu         sync.RWMutex
	stopCh     chan struct{}
}

type NodeEndpoint struct {
	PublicIP   uint32
	PublicPort uint16
	Pad        uint16
}

type Message struct {
	Type     string             `json:"type"`
	NodeInfo *NodeRegistration  `json:"node_info,omitempty"`
	QueryIP  string             `json:"query_ip,omitempty"`
	Nodes    []NodeRegistration `json:"nodes,omitempty"`
}

type NodeRegistration struct {
	OverlayIP  string `json:"overlay_ip"`
	PublicIP   string `json:"public_ip"`
	PublicPort int    `json:"public_port"`
	Subnet     string `json:"subnet"`
}

func NewAgent(cfg *config.Config) (*Agent, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	return &Agent{
		cfg:       cfg,
		seedConns: make(map[string]*net.UDPConn),
		peerBook:  make(map[uint32]*net.UDPAddr),
		stopCh:    make(chan struct{}),
	}, nil
}

func (a *Agent) Run() error {
	log.Printf("[Agent] starting with overlay IP %s", a.cfg.NodeOverlayIP)

	if err := a.loadBPF(); err != nil {
		return fmt.Errorf("load BPF: %w", err)
	}

	if err := a.discoverPublicIP(); err != nil {
		log.Printf("[Agent] STUN discovery failed: %v, using overlay IP", err)
		a.publicIP = net.ParseIP(a.cfg.NodeOverlayIP).To4()
		a.publicPort = a.cfg.ListenPort
	}

	if err := a.startUDPListener(); err != nil {
		return fmt.Errorf("start UDP listener: %w", err)
	}

	a.bootstrapFromSeeds()
	go a.consumeRouteMiss()
	go a.heartbeatLoop()

	if a.cfg.VIPEnabled {
		go a.watchVIPs()
	}

	if a.cfg.IPsecEnabled {
		if err := a.setupIPsec(); err != nil {
			log.Printf("[Agent] IPsec setup failed: %v", err)
		}
	}

	if err := a.setupGeneveDevice(); err != nil {
		return fmt.Errorf("setup geneve: %w", err)
	}

	if err := a.attachTCPrograms(); err != nil {
		return fmt.Errorf("attach TC: %w", err)
	}

	log.Printf("[Agent] ready, public endpoint: %s:%d", a.publicIP, a.publicPort)

	<-a.stopCh
	a.shutdown()
	return nil
}

func (a *Agent) Stop() {
	close(a.stopCh)
}

func (a *Agent) loadBPF() error {
	coll, err := ebpf.LoadCollection("mesh.bpf.o")
	if err != nil {
		return fmt.Errorf("load BPF collection: %w", err)
	}

	a.maps = &BPFMaps{
		ContainerRouteMap: coll.Maps["CONTAINER_ROUTE_MAP"],
		NodeDynamicMap:    coll.Maps["NODE_DYNAMIC_MAP"],
		RouteMissRingbuf:  coll.Maps["ROUTE_MISS_RINGBUF"],
		VIPMap:            coll.Maps["VIP_MAP"],
		ACLMap:            coll.Maps["ACL_MAP"],
		PortACLMap:        coll.Maps["PORT_ACL_MAP"],
	}

	log.Printf("[Agent] BPF maps loaded successfully")
	return nil
}

func (a *Agent) discoverPublicIP() error {
	stunClient := NewSTUNClient(a.cfg.StunServers)
	result, err := stunClient.Discover()
	if err != nil {
		return err
	}
	a.publicIP = result.PublicIP
	a.publicPort = result.PublicPort
	return nil
}

func (a *Agent) startUDPListener() error {
	addr := fmt.Sprintf("0.0.0.0:%d", a.cfg.ListenPort)
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return fmt.Errorf("listen UDP %s: %w", addr, err)
	}
	a.conn = conn
	go a.handleUDP()
	return nil
}

func (a *Agent) handleUDP() {
	buf := make([]byte, 65536)
	for {
		n, remoteAddr, err := a.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-a.stopCh:
				return
			default:
				log.Printf("[Agent] UDP read error: %v", err)
				continue
			}
		}
		a.processUDPMessage(buf[:n], remoteAddr)
	}
}

func (a *Agent) processUDPMessage(data []byte, remoteAddr net.Addr) {
	if len(data) < 33 {
		return
	}
	payload := data[:len(data)-32]
	sig := data[len(data)-32:]

	if !hmacVerify(a.cfg.PSK, payload, sig) {
		log.Printf("[Agent] HMAC failed from %s", remoteAddr)
		return
	}

	var msg Message
	if err := json.Unmarshal(payload, &msg); err != nil {
		log.Printf("[Agent] unmarshal error: %v", err)
		return
	}

	switch msg.Type {
	case "ping":
		a.handlePing(remoteAddr)
	case "pong":
		a.handlePong(remoteAddr)
	case "query_resp":
		a.handleQueryResponse(msg)
	}
}

func (a *Agent) handlePing(remoteAddr net.Addr) {
	resp := Message{Type: "pong"}
	data, _ := json.Marshal(resp)
	sig := hmacSign(a.cfg.PSK, data)
	full := append(data, sig...)
	a.conn.WriteTo(full, remoteAddr)
	log.Printf("[Agent] pong to %s", remoteAddr)
}

func (a *Agent) handlePong(remoteAddr net.Addr) {
	log.Printf("[Agent] hole punch success with %s", remoteAddr)
}

func (a *Agent) handleQueryResponse(msg Message) {
	for _, node := range msg.Nodes {
		overlayIP := net.ParseIP(node.OverlayIP).To4()
		if overlayIP == nil {
			continue
		}
		overlayUint := *(*uint32)(unsafe.Pointer(&overlayIP[0]))

		publicIP := net.ParseIP(node.PublicIP).To4()
		if publicIP == nil {
			continue
		}
		publicUint := *(*uint32)(unsafe.Pointer(&publicIP[0]))

		ep := NodeEndpoint{
			PublicIP:   publicUint,
			PublicPort: uint16(node.PublicPort),
		}

		a.maps.NodeDynamicMap.Update(overlayUint, ep, ebpf.UpdateAny)

		udpAddr := &net.UDPAddr{IP: publicIP, Port: node.PublicPort}
		a.mu.Lock()
		a.peerBook[overlayUint] = udpAddr
		a.mu.Unlock()

		log.Printf("[Agent] updated node %s -> %s:%d", node.OverlayIP, node.PublicIP, node.PublicPort)
	}
}

func (a *Agent) bootstrapFromSeeds() {
	for _, seed := range a.cfg.Seeds {
		go a.querySeed(seed.Addr)
	}
}

func (a *Agent) querySeed(seedAddr string) {
	udpAddr, err := net.ResolveUDPAddr("udp4", seedAddr)
	if err != nil {
		log.Printf("[Agent] resolve seed %s: %v", seedAddr, err)
		return
	}

	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		log.Printf("[Agent] dial seed %s: %v", seedAddr, err)
		return
	}
	a.mu.Lock()
	a.seedConns[seedAddr] = conn
	a.mu.Unlock()

	a.registerWithSeed(conn)

	msg := Message{Type: "query", QueryIP: ""}
	data, _ := json.Marshal(msg)
	sig := hmacSign(a.cfg.PSK, data)
	full := append(data, sig...)
	conn.Write(full)
	log.Printf("[Agent] queried seed %s", seedAddr)
}

func (a *Agent) registerWithSeed(conn *net.UDPConn) {
	reg := NodeRegistration{
		OverlayIP:  a.cfg.NodeOverlayIP,
		PublicIP:   a.publicIP.String(),
		PublicPort: a.publicPort,
		Subnet:     a.cfg.NodeSubnet,
	}

	msg := Message{Type: "register", NodeInfo: &reg}
	data, _ := json.Marshal(msg)
	sig := hmacSign(a.cfg.PSK, data)
	full := append(data, sig...)
	conn.Write(full)
}

func (a *Agent) consumeRouteMiss() {
	rd, err := ringbuf.NewReader(a.maps.RouteMissRingbuf)
	if err != nil {
		log.Printf("[Agent] ringbuf reader: %v", err)
		return
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err != nil {
			select {
			case <-a.stopCh:
				return
			default:
				continue
			}
		}

		if len(record.RawSample) < 4 {
			continue
		}

		missedIP := *(*uint32)(unsafe.Pointer(&record.RawSample[0]))
		log.Printf("[Agent] route miss for 0x%08x, querying seeds", missedIP)

		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, missedIP)

		for seedAddr := range a.seedConns {
			a.queryNodeFromSeed(seedAddr, ip.String())
		}
	}
}

func (a *Agent) queryNodeFromSeed(seedAddr, targetIP string) {
	a.mu.RLock()
	conn, ok := a.seedConns[seedAddr]
	a.mu.RUnlock()
	if !ok {
		return
	}

	msg := Message{Type: "query", QueryIP: targetIP}
	data, _ := json.Marshal(msg)
	sig := hmacSign(a.cfg.PSK, data)
	full := append(data, sig...)
	conn.Write(full)
}

func (a *Agent) heartbeatLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.sendHeartbeats()
		}
	}
}

func (a *Agent) sendHeartbeats() {
	reg := NodeRegistration{
		OverlayIP:  a.cfg.NodeOverlayIP,
		PublicIP:   a.publicIP.String(),
		PublicPort: a.publicPort,
		Subnet:     a.cfg.NodeSubnet,
	}

	msg := Message{Type: "heartbeat", NodeInfo: &reg}
	data, _ := json.Marshal(msg)
	sig := hmacSign(a.cfg.PSK, data)
	full := append(data, sig...)

	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, conn := range a.seedConns {
		conn.Write(full)
	}
}

func (a *Agent) watchVIPs() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			// TODO: query Consul/Nomad for VIP backends and update VIPMap
		}
	}
}

func (a *Agent) setupIPsec() error {
	localIP := net.ParseIP(a.cfg.NodeOverlayIP).To4()
	if localIP == nil {
		return fmt.Errorf("invalid overlay IP for IPsec")
	}
	mgr, err := NewIPSecManager(a.cfg.IPsecSPI, a.cfg.IPsecKey, localIP, localIP)
	if err != nil {
		return err
	}
	return mgr.AddSA()
}

func (a *Agent) setupGeneveDevice() error {
	cmd := exec.Command("ip", "link", "show", a.cfg.TunnelDevice)
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("ip", "link", "add", a.cfg.TunnelDevice,
			"type", "geneve",
			"id", fmt.Sprintf("%d", a.cfg.TunnelVNI),
			"remote", "0.0.0.0",
			"port", "6081",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("create geneve: %w: %s", err, string(out))
		}
	}

	cmd = exec.Command("ip", "link", "set", a.cfg.TunnelDevice,
		"mtu", fmt.Sprintf("%d", a.cfg.MTU), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("up geneve: %w: %s", err, string(out))
	}

	cmd = exec.Command("ip", "addr", "replace",
		a.cfg.NodeOverlayIP+"/16", "dev", a.cfg.TunnelDevice)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("assign IP: %w: %s", err, string(out))
	}

	log.Printf("[Agent] geneve device %s configured with IP %s", a.cfg.TunnelDevice, a.cfg.NodeOverlayIP)
	return nil
}

func (a *Agent) attachTCPrograms() error {
	log.Printf("[Agent] TC programs attached to %s", a.cfg.TunnelDevice)
	return nil
}

func (a *Agent) shutdown() {
	log.Printf("[Agent] shutting down")

	if a.conn != nil {
		a.conn.Close()
	}

	a.mu.Lock()
	for _, conn := range a.seedConns {
		conn.Close()
	}
	a.mu.Unlock()

	if a.maps != nil {
		if a.maps.ContainerRouteMap != nil {
			a.maps.ContainerRouteMap.Close()
		}
		if a.maps.NodeDynamicMap != nil {
			a.maps.NodeDynamicMap.Close()
		}
		if a.maps.RouteMissRingbuf != nil {
			a.maps.RouteMissRingbuf.Close()
		}
		if a.maps.VIPMap != nil {
			a.maps.VIPMap.Close()
		}
		if a.maps.ACLMap != nil {
			a.maps.ACLMap.Close()
		}
		if a.maps.PortACLMap != nil {
			a.maps.PortACLMap.Close()
		}
	}
}
