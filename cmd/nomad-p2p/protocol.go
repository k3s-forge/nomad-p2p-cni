package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/nomad-p2p-cni/internal/netutil"
)

const (
	hmacSize       = 32
	headerSize     = 16
	minMessageSize = headerSize + hmacSize
	replayWindow   = 5 * time.Minute
)

type Message struct {
	Type       string             `json:"type"`
	QueryID    string             `json:"qid,omitempty"`
	Timestamp  int64              `json:"ts"`
	Nonce      string             `json:"nonce"`
	NodeInfo   *NodeRegistration  `json:"node_info,omitempty"`
	QueryIP    string             `json:"query_ip,omitempty"`
	Nodes      []NodeRegistration `json:"nodes,omitempty"`
	Relay      *RelayInfo         `json:"relay,omitempty"`
}

type RelayInfo struct {
	RelayIP   string `json:"relay_ip"`
	RelayPort int    `json:"relay_port"`
}

type PeerInfo struct {
	Addr            *net.UDPAddr
	RelayCapable    bool
	NATType         NATType
	PingOK          bool
	PingLastSuccess time.Time
}

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
	if len(data) < minMessageSize {
		return
	}

	header := data[:headerSize]
	payload := data[headerSize : len(data)-hmacSize]
	sig := data[len(data)-hmacSize:]

	if !netutil.HMACVerify(a.cfg.PSK, append(header, payload...), sig) {
		a.metrics.inc("hmac_failures")
		return
	}

	ts := binary.BigEndian.Uint64(header[:8])
	msgTime := time.Unix(int64(ts), 0)
	if time.Since(msgTime) > replayWindow || time.Until(msgTime) > replayWindow {
		a.metrics.inc("replay_rejected")
		return
	}

	nonce := fmt.Sprintf("%x", header[8:16])
	if !a.registry.checkNonce(nonce) {
		a.metrics.inc("replay_rejected")
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
		a.handlePing(msg, remote)
	case "pong":
		a.handlePong(msg)
	case "query_resp":
		a.handleQueryResponse(msg)
	case "relay_request":
		a.handleRelayRequest(msg, remote)
	}
}

func (a *Agent) handlePing(msg Message, remote net.Addr) {
	if msg.NodeInfo != nil {
		a.handleRegister(msg)
	}
	a.sendMessage(Message{Type: "pong", NodeInfo: &NodeRegistration{
		OverlayIP:    a.cfg.NodeOverlayIP,
		PublicIP:     a.publicIP.String(),
		PublicPort:   a.publicPort,
		NATType:      string(a.natType),
		RelayCapable: a.seedMode,
	}}, remote)
}

func (a *Agent) handlePong(msg Message) {
	if msg.NodeInfo == nil {
		return
	}
	overlayIP := net.ParseIP(msg.NodeInfo.OverlayIP).To4()
	publicIP := net.ParseIP(msg.NodeInfo.PublicIP).To4()
	if overlayIP == nil || publicIP == nil {
		return
	}
	overlayU := *(*uint32)(unsafe.Pointer(&overlayIP[0]))
	publicU := *(*uint32)(unsafe.Pointer(&publicIP[0]))

	ep := NodeEndpoint{PublicIP: publicU, PublicPort: uint16(msg.NodeInfo.PublicPort)}
	a.maps.NodeDynamicMap.Update(overlayU, ep, 0)

	a.mu.Lock()
	defer a.mu.Unlock()
	if peer, ok := a.peerBook[overlayU]; ok {
		peer.PingOK = true
		peer.PingLastSuccess = time.Now()
		peer.NATType = NATType(msg.NodeInfo.NATType)
		peer.Addr = &net.UDPAddr{IP: publicIP, Port: msg.NodeInfo.PublicPort}
	} else {
		a.peerBook[overlayU] = &PeerInfo{
			Addr:            &net.UDPAddr{IP: publicIP, Port: msg.NodeInfo.PublicPort},
			RelayCapable:    msg.NodeInfo.RelayCapable,
			NATType:         NATType(msg.NodeInfo.NATType),
			PingOK:          true,
			PingLastSuccess: time.Now(),
		}
		a.metrics.setGauge("peers_total", float64(len(a.peerBook)))
	}
	log.Printf("[agent] pong from %s (nat=%s)", msg.NodeInfo.OverlayIP, msg.NodeInfo.NATType)
}

func (a *Agent) sendMessage(msg Message, remote net.Addr) {
	data := marshalSigned(a.cfg.PSK, msg)
	a.conn.WriteTo(data, remote)
}

func (a *Agent) sendToSeed(conn *net.UDPConn, msg Message) {
	data := marshalSigned(a.cfg.PSK, msg)
	conn.Write(data)
}

func marshalSigned(psk string, msg Message) []byte {
	payload, _ := json.Marshal(msg)

	header := make([]byte, headerSize)
	binary.BigEndian.PutUint64(header[:8], uint64(time.Now().Unix()))
	rand.Read(header[8:16])

	signed := append(header, payload...)
	sig := netutil.HMACSign(psk, signed)
	return append(signed, sig...)
}

func (a *Agent) consumeRouteMiss() {
	if a.maps.RouteMissRingbuf == nil {
		return
	}
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
		missedIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(missedIP, binary.BigEndian.Uint32(record.RawSample[:4]))
		log.Printf("[agent] route miss for %s", missedIP)
		a.metrics.inc("route_misses")

		a.mu.RLock()
		for addr := range a.seedConns {
			a.queryNodeFromSeed(addr, missedIP.String())
		}
		a.mu.RUnlock()

		if a.natType == NATSymmetric {
			a.tryRelayForTarget(missedIP.String())
		}
	}
}

func (a *Agent) tryRelayForTarget(targetIP string) {
	a.mu.RLock()
	var relayPeer *NodeRegistration
	for _, peer := range a.peerBook {
		if peer.RelayCapable && peer.NATType != NATSymmetric {
			relayPeer = &NodeRegistration{
				PublicIP:     peer.Addr.IP.String(),
				PublicPort:   peer.Addr.Port,
				RelayCapable: true,
			}
			break
		}
	}
	a.mu.RUnlock()

	if relayPeer != nil {
		a.sendRelayRequest(targetIP, relayPeer)
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

func (a *Agent) sendRelayRequest(targetIP string, relayPeer *NodeRegistration) {
	if relayPeer == nil || !relayPeer.RelayCapable {
		return
	}
	qid := fmt.Sprintf("%x-%d", time.Now().UnixNano(), a.publicPort)
	a.mu.RLock()
	for _, conn := range a.seedConns {
		a.sendToSeed(conn, Message{
			Type:       "relay_request",
			QueryIP:    targetIP,
			QueryID:    qid,
			Relay:      &RelayInfo{RelayIP: relayPeer.PublicIP, RelayPort: relayPeer.PublicPort},
		})
		log.Printf("[agent] sent relay_request for %s via %s:%d (qid=%s)",
			targetIP, relayPeer.PublicIP, relayPeer.PublicPort, qid)
	}
	a.mu.RUnlock()
}
