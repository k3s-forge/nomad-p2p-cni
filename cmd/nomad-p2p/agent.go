package main

import (
	"crypto/hmac"
	"crypto/sha256"
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

// --- BPF Map types ---

type BPFMaps struct {
	ContainerRouteMap *ebpf.Map
	NodeDynamicMap    *ebpf.Map
	RouteMissRingbuf  *ebpf.Map
	VIPMap            *ebpf.Map
	ACLMap            *ebpf.Map
	PortACLMap        *ebpf.Map
}

// --- Protocol messages ---

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

// --- Seed registry (in-memory) ---

type seedRegistry struct {
	table map[string]*NodeRegistration
	mu    sync.RWMutex
}

func newSeedRegistry() *seedRegistry {
	return &seedRegistry{table: make(map[string]*NodeRegistration)}
}

func (s *seedRegistry) register(node *NodeRegistration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.table[node.OverlayIP] = node
}

func (s *seedRegistry) lookup(ip string) *NodeRegistration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.table[ip]
}

func (s *seedRegistry) all() []NodeRegistration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []NodeRegistration
	for _, n := range s.table {
		out = append(out, *n)
	}
	return out
}

func (s *seedRegistry) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// simple: remove entries older than 3 minutes (checked externally)
}

// --- Agent ---

type Agent struct {
	cfg        *config.Config
	maps       *BPFMaps
	conn       net.PacketConn
	publicIP   net.IP
	publicPort int
	seedConns  map[string]*net.UDPConn
	peerBook   map[uint32]*net.UDPAddr
	mu         sync.RWMutex
	stopCh     chan struct{}
	seedMode   bool
	registry   *seedRegistry
}

func newAgent(cfg *config.Config, seedMode bool) (*Agent, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	return &Agent{
		cfg:       cfg,
		seedConns: make(map[string]*net.UDPConn),
		peerBook:  make(map[uint32]*net.UDPAddr),
		stopCh:    make(chan struct{}),
		seedMode:  seedMode,
		registry:  newSeedRegistry(),
	}, nil
}

func (a *Agent) run() error {
	log.Printf("[agent] starting (overlay IP: %s, seed mode: %v)", a.cfg.NodeOverlayIP, a.seedMode)

	if err := a.loadBPF(); err != nil {
		return fmt.Errorf("load BPF: %w", err)
	}

	if err := a.discoverPublicIP(); err != nil {
		log.Printf("[agent] STUN failed: %v, using overlay IP", err)
		a.publicIP = net.ParseIP(a.cfg.NodeOverlayIP).To4()
		a.publicPort = a.cfg.ListenPort
	}

	if err := a.startUDPListener(); err != nil {
		return fmt.Errorf("start UDP: %w", err)
	}

	if err := a.setupGeneveDevice(); err != nil {
		return fmt.Errorf("setup geneve: %w", err)
	}

	a.bootstrapFromSeeds()
	go a.consumeRouteMiss()
	go a.heartbeatLoop()

	if a.cfg.VIPEnabled {
		go a.watchVIPs()
	}

	if a.cfg.IPsecEnabled {
		a.setupIPsec()
	}

	log.Printf("[agent] ready (public: %s:%d)", a.publicIP, a.publicPort)
	<-a.stopCh
	a.shutdown()
	return nil
}

func (a *Agent) stop() { close(a.stopCh) }

// --- BPF ---

func (a *Agent) loadBPF() error {
	spec, err := ebpf.LoadCollectionSpec("bin/mesh.bpf.o")
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}
	a.maps = &BPFMaps{
		ContainerRouteMap: coll.Maps["CONTAINER_ROUTE_MAP"],
		NodeDynamicMap:    coll.Maps["NODE_DYNAMIC_MAP"],
		RouteMissRingbuf:  coll.Maps["ROUTE_MISS_RINGBUF"],
		VIPMap:            coll.Maps["VIP_MAP"],
		ACLMap:            coll.Maps["ACL_MAP"],
		PortACLMap:        coll.Maps["PORT_ACL_MAP"],
	}
	log.Printf("[agent] BPF maps loaded")
	return nil
}

// --- STUN ---

func (a *Agent) discoverPublicIP() error {
	c := &stunClient{servers: a.cfg.StunServers, timeout: 3 * time.Second}
	r, err := c.discover()
	if err != nil {
		return err
	}
	a.publicIP = r.PublicIP
	a.publicPort = r.PublicPort
	return nil
}

// --- UDP listener (handles both agent + seed traffic) ---

func (a *Agent) startUDPListener() error {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", a.cfg.ListenPort))
	if err != nil {
		return err
	}
	a.conn = conn
	go a.handleUDP()
	return nil
}

func (a *Agent) handleUDP() {
	buf := make([]byte, 65536)
	for {
		n, remote, err := a.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-a.stopCh:
				return
			default:
				continue
			}
		}
		a.processUDP(buf[:n], remote)
	}
}

func (a *Agent) processUDP(data []byte, remote net.Addr) {
	if len(data) < 33 {
		return
	}
	payload, sig := data[:len(data)-32], data[len(data)-32:]
	if !hmacVerify(a.cfg.PSK, payload, sig) {
		return
	}

	var msg Message
	if err := json.Unmarshal(payload, &msg); err != nil {
		return
	}

	switch msg.Type {
	case "register":
		a.handleRegister(msg)
	case "query":
		a.handleQuery(msg, remote)
	case "heartbeat":
		a.handleRegister(msg)
	case "ping":
		a.sendPong(remote)
	case "query_resp":
		a.handleQueryResponse(msg)
	}
}

// --- Seed handlers ---

func (a *Agent) handleRegister(msg Message) {
	if msg.NodeInfo == nil {
		return
	}
	a.registry.register(msg.NodeInfo)
	log.Printf("[seed] registered %s -> %s:%d", msg.NodeInfo.OverlayIP, msg.NodeInfo.PublicIP, msg.NodeInfo.PublicPort)
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
	resp := Message{Type: "query_resp", Nodes: nodes}
	data, _ := json.Marshal(resp)
	sig := hmacSign(a.cfg.PSK, data)
	a.conn.WriteTo(append(data, sig...), remote)
}

// --- Agent handlers ---

func (a *Agent) handleQueryResponse(msg Message) {
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

		a.mu.Lock()
		a.peerBook[overlayU] = &net.UDPAddr{IP: publicIP, Port: node.PublicPort}
		a.mu.Unlock()
		log.Printf("[agent] node %s -> %s:%d", node.OverlayIP, node.PublicIP, node.PublicPort)
	}
}

func (a *Agent) sendPong(remote net.Addr) {
	data, _ := json.Marshal(Message{Type: "pong"})
	sig := hmacSign(a.cfg.PSK, data)
	a.conn.WriteTo(append(data, sig...), remote)
}

// --- Bootstrap & heartbeat ---

func (a *Agent) bootstrapFromSeeds() {
	for _, seed := range a.cfg.Seeds {
		go a.querySeed(seed.Addr)
	}
}

func (a *Agent) querySeed(addr string) {
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

	// Register
	reg := NodeRegistration{
		OverlayIP: a.cfg.NodeOverlayIP, PublicIP: a.publicIP.String(),
		PublicPort: a.publicPort, Subnet: a.cfg.NodeSubnet,
	}
	a.sendToSeed(conn, Message{Type: "register", NodeInfo: &reg})

	// Query all
	a.sendToSeed(conn, Message{Type: "query"})
}

func (a *Agent) sendToSeed(conn *net.UDPConn, msg Message) {
	data, _ := json.Marshal(msg)
	sig := hmacSign(a.cfg.PSK, data)
	conn.Write(append(data, sig...))
}

func (a *Agent) consumeRouteMiss() {
	rd, err := ringbuf.NewReader(a.maps.RouteMissRingbuf)
	if err != nil {
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
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, missedIP)
		for addr := range a.seedConns {
			a.queryNodeFromSeed(addr, ip.String())
		}
	}
}

func (a *Agent) queryNodeFromSeed(addr, targetIP string) {
	a.mu.RLock()
	conn, ok := a.seedConns[addr]
	a.mu.RUnlock()
	if !ok {
		return
	}
	a.sendToSeed(conn, Message{Type: "query", QueryIP: targetIP})
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
				OverlayIP: a.cfg.NodeOverlayIP, PublicIP: a.publicIP.String(),
				PublicPort: a.publicPort, Subnet: a.cfg.NodeSubnet,
			}
			a.mu.RLock()
			for _, conn := range a.seedConns {
				a.sendToSeed(conn, Message{Type: "heartbeat", NodeInfo: &reg})
			}
			a.mu.RUnlock()
		}
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
			// TODO: query Consul/Nomad for VIP backends
		}
	}
}

// --- Geneve & IPsec ---

func (a *Agent) setupGeneveDevice() error {
	cmd := exec.Command("ip", "link", "show", a.cfg.TunnelDevice)
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("ip", "link", "add", a.cfg.TunnelDevice,
			"type", "geneve", "id", fmt.Sprintf("%d", a.cfg.TunnelVNI),
			"remote", "0.0.0.0", "port", "6081")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("create: %w: %s", err, out)
		}
	}
	cmd = exec.Command("ip", "link", "set", a.cfg.TunnelDevice,
		"mtu", fmt.Sprintf("%d", a.cfg.MTU), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("up: %w: %s", err, out)
	}
	cmd = exec.Command("ip", "addr", "replace", a.cfg.NodeOverlayIP+"/16", "dev", a.cfg.TunnelDevice)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("addr: %w: %s", err, out)
	}
	log.Printf("[agent] geneve %s = %s", a.cfg.TunnelDevice, a.cfg.NodeOverlayIP)
	return nil
}

func (a *Agent) setupIPsec() {
	localIP := net.ParseIP(a.cfg.NodeOverlayIP).To4()
	if localIP == nil {
		return
	}
	mgr, err := newIPSecManager(a.cfg.IPsecSPI, a.cfg.IPsecKey, localIP, localIP)
	if err != nil {
		log.Printf("[agent] ipsec: %v", err)
		return
	}
	mgr.addSA()
}

func (a *Agent) shutdown() {
	log.Printf("[agent] shutting down")
	if a.conn != nil {
		a.conn.Close()
	}
	a.mu.Lock()
	for _, c := range a.seedConns {
		c.Close()
	}
	a.mu.Unlock()
}

// --- HMAC auth ---

func hmacSign(psk string, data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(data)
	return mac.Sum(nil)
}

func hmacVerify(psk string, data, sig []byte) bool {
	return hmac.Equal(hmacSign(psk, data), sig)
}
