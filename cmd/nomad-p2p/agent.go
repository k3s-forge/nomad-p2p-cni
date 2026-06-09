package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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
	VIPStatsMap       *ebpf.Map
	ACLMap            *ebpf.Map
	PortACLMap        *ebpf.Map
	DefaultPolicy     *ebpf.Map
}

// --- BPF value types (must match C structs) ---

type NodeEndpoint struct {
	PublicIP   uint32
	PublicPort uint16
	Pad        uint16
}

type VIPInfo struct {
	Backends [16]uint32
	Count    uint8
	Pad      [3]byte
	NextIdx  uint32
}

// --- Protocol messages ---

type Message struct {
	Type     string             `json:"type"`
	NodeInfo *NodeRegistration  `json:"node_info,omitempty"`
	QueryIP  string             `json:"query_ip,omitempty"`
	Nodes    []NodeRegistration `json:"nodes,omitempty"`
	Relay    *RelayInfo         `json:"relay,omitempty"`
}

type NodeRegistration struct {
	OverlayIP  string `json:"overlay_ip"`
	PublicIP   string `json:"public_ip"`
	PublicPort int    `json:"public_port"`
	Subnet     string `json:"subnet"`
	RelayCapable bool `json:"relay_capable"`
}

type RelayInfo struct {
	RelayIP   string `json:"relay_ip"`
	RelayPort int    `json:"relay_port"`
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
}

// --- Agent ---

type Agent struct {
	cfg        *config.Config
	configPath string
	maps       *BPFMaps
	meshColl   *ebpf.Collection
	vipColl    *ebpf.Collection
	fwColl     *ebpf.Collection
	conn       net.PacketConn
	publicIP   net.IP
	publicPort int
	seedConns  map[string]*net.UDPConn
	peerBook   map[uint32]*net.UDPAddr
	mu         sync.RWMutex
	stopCh     chan struct{}
	seedMode   bool
	registry   *seedRegistry
	ipSecMgr   *ipSecManager
	geneveDev  string
	bpfLinks   []link.Link
}

func newAgent(cfg *config.Config, configPath string, seedMode bool) (*Agent, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	return &Agent{
		cfg:        cfg,
		configPath: configPath,
		seedConns:  make(map[string]*net.UDPConn),
		peerBook:  make(map[uint32]*net.UDPAddr),
		stopCh:    make(chan struct{}),
		seedMode:  seedMode,
		registry:  newSeedRegistry(),
		geneveDev: cfg.TunnelDevice,
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

	if err := a.attachBPF(); err != nil {
		log.Printf("[agent] BPF attach warning: %v", err)
	}

	a.bootstrapFromSeeds()
	go a.consumeRouteMiss()
	go a.heartbeatLoop()
	go a.stunRefreshLoop()
	go a.peerHealthLoop()

	if a.cfg.VIPEnabled {
		if a.cfg.ConsulAddr != "" {
			go a.watchVIPsFromConsul()
		} else {
			go a.watchVIPs()
		}
	}

	if a.cfg.IPsecEnabled {
		a.setupIPsec()
		go a.ipsecRotationLoop()
	}

	// Seed mode: register self and serve queries
	if a.seedMode {
		a.registerSelf()
	}

	go a.configHotReload()

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
		return fmt.Errorf("load mesh spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load mesh collection: %w", err)
	}
	a.maps = &BPFMaps{
		ContainerRouteMap: coll.Maps["CONTAINER_ROUTE_MAP"],
		NodeDynamicMap:    coll.Maps["NODE_DYNAMIC_MAP"],
		RouteMissRingbuf:  coll.Maps["ROUTE_MISS_RINGBUF"],
	}
	a.meshColl = coll

	// Pin BPF maps for CNI plugin access
	pinDir := "/sys/fs/bpf/nomad-p2p"
	exec.Command("mkdir", "-p", pinDir).Run()
	if a.maps.ContainerRouteMap != nil {
		a.maps.ContainerRouteMap.Pin(pinDir + "/container_route")
	}
	if a.maps.NodeDynamicMap != nil {
		a.maps.NodeDynamicMap.Pin(pinDir + "/node_dynamic")
	}

	// Pin the TC egress program for CNI to attach to veth peers
	if prog, ok := a.meshColl.Programs["egress_p2p_mesh"]; ok {
		prog.Pin(pinDir + "/mesh_prog")
		log.Printf("[agent] pinned egress_p2p_mesh program")
	}

	log.Printf("[agent] mesh BPF maps and programs pinned to %s", pinDir)

	// Load VIP balancer if enabled
	if a.cfg.VIPEnabled {
		vipSpec, err := ebpf.LoadCollectionSpec("bin/vip_balancer.bpf.o")
		if err != nil {
			log.Printf("[agent] VIP balancer BPF not found: %v", err)
		} else {
			vipColl, err := ebpf.NewCollection(vipSpec)
			if err != nil {
				log.Printf("[agent] VIP balancer load failed: %v", err)
			} else {
				a.maps.VIPMap = vipColl.Maps["VIP_MAP"]
				a.maps.VIPStatsMap = vipColl.Maps["VIP_STATS_MAP"]
				a.vipColl = vipColl
				log.Printf("[agent] VIP balancer BPF loaded")
			}
		}
	}

	// Load firewall BPF
	fwSpec, err := ebpf.LoadCollectionSpec("bin/firewall.bpf.o")
	if err != nil {
		log.Printf("[agent] firewall BPF not found: %v", err)
	} else {
		fwColl, err := ebpf.NewCollection(fwSpec)
		if err != nil {
			log.Printf("[agent] firewall load failed: %v", err)
		} else {
			a.maps.ACLMap = fwColl.Maps["ACL_MAP"]
			a.maps.PortACLMap = fwColl.Maps["PORT_ACL_MAP"]
			a.maps.DefaultPolicy = fwColl.Maps["DEFAULT_POLICY"]
				a.fwColl = fwColl
			// Set default policy to allow-all for overlay traffic
			if a.maps.DefaultPolicy != nil {
				key := uint32(0)
				val := uint8(1)
				a.maps.DefaultPolicy.Update(key, val, 0)
			}
			log.Printf("[agent] firewall BPF loaded")
			a.loadACLsFromConfig()
		}
	}

	return nil
}

func (a *Agent) loadACLsFromConfig() {
	if !a.cfg.FirewallEnabled || a.maps.ACLMap == nil {
		return
	}

	// Set default policy
	if a.maps.DefaultPolicy != nil {
		key := uint32(0)
		val := uint8(0) // deny by default
		if a.cfg.DefaultPolicy == "allow" {
			val = 1
		}
		a.maps.DefaultPolicy.Update(key, val, 0)
		log.Printf("[agent] firewall default policy: %s", a.cfg.DefaultPolicy)
	}

	// Load IP-level ACLs
	for _, srcIP := range a.cfg.AllowedSources {
		ip := net.ParseIP(srcIP).To4()
		if ip == nil {
			continue
		}
		ipU := *(*uint32)(unsafe.Pointer(&ip[0]))
		allow := uint8(1)
		a.maps.ACLMap.Update(ipU, allow, 0)
		log.Printf("[agent] ACL: allow %s", srcIP)
	}

	// Load port-level ACLs
	for _, rule := range a.cfg.AllowedPorts {
		srcIP := net.ParseIP(rule.SourceIP).To4()
		if srcIP == nil {
			continue
		}
		srcU := *(*uint32)(unsafe.Pointer(&srcIP[0]))
		portKey := (uint64(srcU) << 32) | uint64(rule.Port)
		var allow uint8
		if rule.Allow {
			allow = 1
		}
		a.maps.PortACLMap.Update(portKey, allow, 0)
		log.Printf("[agent] port ACL: %s %s/%d -> %v",
			rule.Protocol, rule.SourceIP, rule.Port, rule.Allow)
	}

	log.Printf("[agent] loaded %d IP rules, %d port rules",
		len(a.cfg.AllowedSources), len(a.cfg.AllowedPorts))
}

// --- BPF Program Attachment ---

func (a *Agent) attachBPF() error {
	// Find primary network interface
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		iface, err = net.InterfaceByName("ens3")
		if err != nil {
			iface, err = net.InterfaceByName("wlan0")
			if err != nil {
				log.Printf("[agent] no network interface found for XDP/TC attachment")
				return nil
			}
		}
	}
	ifIndex := uint32(iface.Index)
	log.Printf("[agent] attaching BPF to interface %s (index %d)", iface.Name, iface.Index)

	// Attach mesh XDP program
	if a.meshColl != nil {
		if xdpProg, ok := a.meshColl.Programs["xdp_pass"]; ok {
			l, err := link.AttachXDP(link.XDPOptions{
				Interface: iface.Index,
				Program:   xdpProg,
			})
			if err != nil {
				log.Printf("[agent] XDP attach failed: %v", err)
			} else {
				a.bpfLinks = append(a.bpfLinks, l)
				log.Printf("[agent] XDP attached to %s", iface.Name)
			}
		}

		// Attach TC egress program via iproute2
		if tcProg, ok := a.meshColl.Programs["egress_p2p_mesh"]; ok {
			if err := a.attachTC(ifIndex, tcProg, "egress"); err != nil {
				log.Printf("[agent] TC egress attach failed: %v", err)
			} else {
				log.Printf("[agent] TC egress attached to %s", iface.Name)
			}
		}
	}

	// Attach firewall TC ingress
	if a.fwColl != nil {
		if fwProg, ok := a.fwColl.Programs["tc_ingress_firewall"]; ok {
			if err := a.attachTC(ifIndex, fwProg, "ingress"); err != nil {
				log.Printf("[agent] TC ingress attach failed: %v", err)
			} else {
				log.Printf("[agent] TC ingress firewall attached to %s", iface.Name)
			}
		}
	}

	// Attach VIP cgroup program
	if a.vipColl != nil {
		if vipProg, ok := a.vipColl.Programs["vip_load_balance"]; ok {
			if err := a.attachCgroup(vipProg); err != nil {
				log.Printf("[agent] cgroup attach failed: %v", err)
			} else {
				log.Printf("[agent] VIP cgroup program attached")
			}
		}
	}

	return nil
}

func (a *Agent) attachTC(ifIndex uint32, prog *ebpf.Program, direction string) error {
	// Ensure clsact qdisc exists on the interface
	cmd := exec.Command("tc", "qdisc", "add", "dev", fmt.Sprintf("lo"),
		"clsact")
	cmd.Run() // ignore error if already exists

	// Get the interface name from index
	iface, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil {
		return fmt.Errorf("get interface: %w", err)
	}

	// Add clsact qdisc
	cmd = exec.Command("tc", "qdisc", "add", "dev", iface.Name, "clsact")
	cmd.Run() // ignore "exists" error

	// Pin the program to bpffs so tc can find it
	pinPath := fmt.Sprintf("/sys/fs/bpf/tc/%s_%d", direction, ifIndex)
	exec.Command("rm", "-f", pinPath).Run()
	if err := exec.Command("bpftool", "prog", "pin", "id",
		fmt.Sprintf("%d", prog.FD()), pinPath).Run(); err != nil {
		return fmt.Errorf("pin prog: %w", err)
	}

	// Attach via tc
	cmd = exec.Command("tc", "filter", "add", "dev", iface.Name, direction,
		"pref", "1", "handle", "1", "bpf", "direct-action", "pinned", pinPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tc filter add: %w: %s", err, out)
	}

	return nil
}

func (a *Agent) attachCgroup(prog *ebpf.Program) error {
	// Find or create the cgroup v2 mount
	cgroupPath := "/sys/fs/cgroup"

	// Try to attach to root cgroup
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: prog,
		Attach:  ebpf.AttachCGroupInet4Connect,
	})
	if err != nil {
		return fmt.Errorf("attach cgroup: %w", err)
	}
	a.bpfLinks = append(a.bpfLinks, l)
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

func (a *Agent) stunRefreshLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			oldIP := a.publicIP.String()
			oldPort := a.publicPort
			if err := a.discoverPublicIP(); err != nil {
				log.Printf("[agent] STUN refresh failed: %v", err)
				continue
			}
			if a.publicIP.String() != oldIP || a.publicPort != oldPort {
				log.Printf("[agent] public IP changed: %s:%d -> %s:%d",
					oldIP, oldPort, a.publicIP, a.publicPort)
				// Re-register with all seeds
				a.reRegisterWithSeeds()
			}
		}
	}
}

func (a *Agent) reRegisterWithSeeds() {
	reg := NodeRegistration{
		OverlayIP:    a.cfg.NodeOverlayIP,
		PublicIP:     a.publicIP.String(),
		PublicPort:   a.publicPort,
		Subnet:       a.cfg.NodeSubnet,
		RelayCapable: a.seedMode,
	}
	a.mu.RLock()
	for addr, conn := range a.seedConns {
		a.sendToSeed(conn, Message{Type: "register", NodeInfo: &reg})
		log.Printf("[agent] re-registered with seed %s", addr)
	}
	a.mu.RUnlock()
}

// --- UDP listener ---

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
	case "relay_request":
		a.handleRelayRequest(msg, remote)
	}
}

// --- Seed handlers ---

func (a *Agent) handleRegister(msg Message) {
	if msg.NodeInfo == nil {
		return
	}
	a.registry.register(msg.NodeInfo)
	log.Printf("[seed] registered %s -> %s:%d (relay=%v)",
		msg.NodeInfo.OverlayIP, msg.NodeInfo.PublicIP,
		msg.NodeInfo.PublicPort, msg.NodeInfo.RelayCapable)
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

		// Setup IPsec for this peer if enabled
		if a.cfg.IPsecEnabled && a.ipSecMgr != nil {
			remoteIP := net.ParseIP(node.PublicIP).To4()
			if remoteIP != nil {
				a.ipSecMgr.addSAForPeer(remoteIP)
			}
		}
	}
}

func (a *Agent) handleRelayRequest(msg Message, remote net.Addr) {
	if !a.seedMode || msg.Relay == nil {
		return
	}
	log.Printf("[seed] relay request for %s via %s:%d",
		msg.QueryIP, msg.Relay.RelayIP, msg.Relay.RelayPort)
	// Forward the query through relay
	relayAddr := fmt.Sprintf("%s:%d", msg.Relay.RelayIP, msg.Relay.RelayPort)
	udpAddr, err := net.ResolveUDPAddr("udp4", relayAddr)
	if err != nil {
		return
	}
	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		return
	}
	defer conn.Close()
	a.sendToSeed(conn, Message{Type: "query", QueryIP: msg.QueryIP})
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
		OverlayIP:    a.cfg.NodeOverlayIP,
		PublicIP:     a.publicIP.String(),
		PublicPort:   a.publicPort,
		Subnet:       a.cfg.NodeSubnet,
		RelayCapable: a.seedMode,
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

func (a *Agent) registerSelf() {
	reg := NodeRegistration{
		OverlayIP:    a.cfg.NodeOverlayIP,
		PublicIP:     a.publicIP.String(),
		PublicPort:   a.publicPort,
		Subnet:       a.cfg.NodeSubnet,
		RelayCapable: true,
	}
	a.registry.register(&reg)
	log.Printf("[seed] self-registered %s -> %s:%d", reg.OverlayIP, reg.PublicIP, reg.PublicPort)
}

// --- Route miss consumer ---

func (a *Agent) consumeRouteMiss() {
	rd, err := ringbuf.NewReader(a.maps.RouteMissRingbuf)
	if err != nil {
		log.Printf("[agent] ringbuf reader: %v", err)
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
		log.Printf("[agent] route miss for %s", ip)

		// Query all seeds for this IP
		a.mu.RLock()
		for addr := range a.seedConns {
			a.queryNodeFromSeed(addr, ip.String())
		}
		a.mu.RUnlock()
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

// --- Heartbeat ---

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
			}
			a.mu.RLock()
			for _, conn := range a.seedConns {
				a.sendToSeed(conn, Message{Type: "heartbeat", NodeInfo: &reg})
			}
			a.mu.RUnlock()
		}
	}
}

// --- Peer health ---

func (a *Agent) peerHealthLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.mu.RLock()
			stalePeers := make([]uint32, 0)
			for overlayIP := range a.peerBook {
				// Check if still in BPF map
				var ep NodeEndpoint
				if err := a.maps.NodeDynamicMap.Lookup(overlayIP, &ep); err != nil {
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
				binary.LittleEndian.PutUint32(ipBytes, ip)
				log.Printf("[agent] removed stale peer %s", ipBytes)
			}
		}
	}
}

// --- VIP watching (stub for Consul/Nomad integration) ---

func (a *Agent) watchVIPs() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.updateVIPsFromConfig()
		}
	}
}

func (a *Agent) updateVIPsFromConfig() {
	if a.maps.VIPMap == nil {
		return
	}
	for _, vipStr := range a.cfg.VIPWatchList {
		vip := net.ParseIP(vipStr).To4()
		if vip == nil {
			continue
		}
		vipU := *(*uint32)(unsafe.Pointer(&vip[0]))

		// Check static backends first
		backends := a.getStaticVIPBackends(vipStr)

		if len(backends) == 0 {
			continue
		}

		info := VIPInfo{
			Count:   uint8(len(backends)),
			NextIdx: 0,
		}
		for i, backend := range backends {
			if i >= 16 {
				break
			}
			info.Backends[i] = *(*uint32)(unsafe.Pointer(&backend[0]))
		}
		a.maps.VIPMap.Update(vipU, info, 0)
	}
}

// getStaticVIPBackends returns backend IPs from config's VIPBackends
func (a *Agent) getStaticVIPBackends(vipStr string) []net.IP {
	for _, vb := range a.cfg.VIPBackends {
		if vb.VIP == vipStr {
			var ips []net.IP
			for _, addr := range vb.Backends {
				if ip := net.ParseIP(addr); ip != nil {
					ips = append(ips, ip)
				}
			}
			return ips
		}
	}
	return nil
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

	// Add routes for known peer subnets
	a.mu.RLock()
	for _, ep := range a.peerBook {
		// Route through geneve for overlay traffic
		_ = ep
	}
	a.mu.RUnlock()

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
	a.ipSecMgr = mgr
	mgr.addSA()
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
			// Generate new SPI
			newSPI := make([]byte, 4)
			rand.Read(newSPI)
			a.ipSecMgr.spi = binary.BigEndian.Uint32(newSPI)

			// Delete old SA, add new one
			a.ipSecMgr.delSA()
			a.ipSecMgr.addSA()
			log.Printf("[agent] IPsec SA rotated (new SPI: 0x%08x)", a.ipSecMgr.spi)
		}
	}
}

// --- Config Hot Reload ---

func (a *Agent) configHotReload() {
	if a.configPath == "" {
		return
	}

	var lastModTime time.Time
	if info, err := os.Stat(a.configPath); err == nil {
		lastModTime = info.ModTime()
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			info, err := os.Stat(a.configPath)
			if err != nil {
				continue
			}
			if info.ModTime().After(lastModTime) {
				lastModTime = info.ModTime()
				a.reloadConfig()
			}
		}
	}
}

func (a *Agent) reloadConfig() {
	newCfg, err := config.Load(a.configPath)
	if err != nil {
		log.Printf("[agent] config reload failed: %v", err)
		return
	}

	log.Printf("[agent] config reloaded")

	// Update firewall ACLs
	if a.cfg.FirewallEnabled != newCfg.FirewallEnabled ||
		a.cfg.DefaultPolicy != newCfg.DefaultPolicy {
		a.cfg.FirewallEnabled = newCfg.FirewallEnabled
		a.cfg.DefaultPolicy = newCfg.DefaultPolicy
		a.reloadFirewallACLs(newCfg)
	}

	// Update allowed sources
	if stringSliceChanged(a.cfg.AllowedSources, newCfg.AllowedSources) {
		a.cfg.AllowedSources = newCfg.AllowedSources
		a.reloadFirewallACLs(newCfg)
	}

	// Update allowed ports
	if len(a.cfg.AllowedPorts) != len(newCfg.AllowedPorts) {
		a.cfg.AllowedPorts = newCfg.AllowedPorts
		a.reloadFirewallACLs(newCfg)
	}

	// Update VIP watch list
	if stringSliceChanged(a.cfg.VIPWatchList, newCfg.VIPWatchList) {
		a.cfg.VIPWatchList = newCfg.VIPWatchList
		log.Printf("[agent] VIP watch list updated: %v", newCfg.VIPWatchList)
	}
}

func (a *Agent) reloadFirewallACLs(newCfg *config.Config) {
	if a.maps.ACLMap == nil {
		return
	}

	// Clear existing ACLs by resetting the default policy
	if a.maps.DefaultPolicy != nil {
		key := uint32(0)
		val := uint8(0)
		if newCfg.DefaultPolicy == "allow" {
			val = 1
		}
		a.maps.DefaultPolicy.Update(key, val, 0)
	}

	// Clear old IP ACLs
	if a.maps.ACLMap != nil {
		a.maps.ACLMap.Close()
		a.maps.ACLMap = nil
	}

	// Reload from new config
	a.cfg.AllowedSources = newCfg.AllowedSources
	a.cfg.AllowedPorts = newCfg.AllowedPorts
	a.loadACLsFromConfig()
	log.Printf("[agent] firewall ACLs reloaded")
}

func stringSliceChanged(a, b []string) bool {
	if len(a) != len(b) {
		return true
	}
	m := make(map[string]bool, len(a))
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if !m[s] {
			return true
		}
	}
	return false
}

// --- Shutdown ---

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

	// Cleanup IPsec
	if a.ipSecMgr != nil {
		a.ipSecMgr.delSA()
	}

	// Close BPF links
	for _, l := range a.bpfLinks {
		l.Close()
	}
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
