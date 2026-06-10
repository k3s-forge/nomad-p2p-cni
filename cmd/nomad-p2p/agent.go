package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/nomad-p2p-cni/config"
)

type NATType string

const (
	NATUnknown    NATType = "unknown"
	NATEasy       NATType = "easy"
	NATSymmetric  NATType = "symmetric"
)

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
	natType    NATType
	seedConns map[string]*net.UDPConn
	peerBook   map[uint32]*PeerInfo
	mu         sync.RWMutex
	stopCh     chan struct{}
	seedMode   bool
	registry   *seedRegistry
	ipSecMgr   *ipSecManager
	geneveDev  string
	bpfLinks   []link.Link
	startTime  time.Time
	metrics    *metricsCollector
}

func newAgent(cfg *config.Config, configPath string, seedMode bool) (*Agent, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	return &Agent{
		cfg:        cfg,
		configPath: configPath,
		seedConns: make(map[string]*net.UDPConn),
		peerBook:   make(map[uint32]*PeerInfo),
		stopCh:     make(chan struct{}),
		seedMode:   seedMode,
		registry:   newSeedRegistry(),
		geneveDev:  cfg.TunnelDevice,
		startTime:  time.Now(),
		metrics:    newMetricsCollector(),
		natType:    NATUnknown,
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

	a.updateGeneveIfindex()

	if err := a.attachBPF(); err != nil {
		log.Printf("[agent] BPF attach warning: %v", err)
	}

	a.bootstrapFromSeeds()
	go a.consumeRouteMiss()
	go a.heartbeatLoop()
	go a.stunRefreshLoop()
	go a.peerHealthLoop()
	go a.peerPingLoop()

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

	if a.seedMode {
		a.registerSelf()
	}

	go a.configHotReload()

	if a.cfg.MetricsPort > 0 {
		go a.startMetricsServer()
	}

	log.Printf("[agent] ready (public: %s:%d)", a.publicIP, a.publicPort)
	<-a.stopCh
	a.shutdown()
	return nil
}

func (a *Agent) stop() { close(a.stopCh) }

func (a *Agent) shutdown() {
	log.Printf("[agent] shutting down")

	if a.conn != nil {
		a.conn.Close()
	}

	a.mu.Lock()
	for _, c := range a.seedConns {
		c.Close()
	}
	a.seedConns = make(map[string]*net.UDPConn)
	a.mu.Unlock()

	if a.ipSecMgr != nil {
		a.ipSecMgr.delSA()
	}

	for _, l := range a.bpfLinks {
		l.Close()
	}

	if a.meshColl != nil {
		a.meshColl.Close()
	}
	if a.vipColl != nil {
		a.vipColl.Close()
	}
	if a.fwColl != nil {
		a.fwColl.Close()
	}

	pinDir := "/sys/fs/bpf/nomad-p2p"
	exec.Command("rm", "-f", pinDir+"/container_route").Run()
	exec.Command("rm", "-f", pinDir+"/node_dynamic").Run()
	exec.Command("rm", "-f", pinDir+"/mesh_prog").Run()

	exec.Command("ip", "link", "del", a.cfg.TunnelDevice).Run()

	log.Printf("[agent] shutdown complete")
}

func runAgentMain(args []string) {
	if len(os.Args) < 2 && len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: nomad-p2p agent [flags]")
		os.Exit(1)
	}

	fs := newFlagSet("agent")
	configPath := fs.String("config", "/etc/nomad-p2p/config.json", "config file path")
	seedMode := fs.Bool("seed-mode", false, "also run as Seed route registry")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	agent, err := newAgent(cfg, *configPath, *seedMode)
	if err != nil {
		log.Fatalf("create agent: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		agent.stop()
	}()

	if err := agent.run(); err != nil {
		log.Fatalf("agent error: %v", err)
	}
}
