package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

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
		a.sendPong(remote)
	case "query_resp":
		a.handleQueryResponse(msg)
	case "relay_request":
		a.handleRelayRequest(msg, remote)
	}
}

func (a *Agent) sendPong(remote net.Addr) {
	a.sendMessage(Message{Type: "pong"}, remote)
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
