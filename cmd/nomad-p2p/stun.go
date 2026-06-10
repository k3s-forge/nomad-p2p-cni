package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

const stunMagicCookie = 0x2112A442

type stunResult struct {
	PublicIP   net.IP
	PublicPort int
}

type stunClient struct {
	servers []string
	timeout time.Duration
}

func (c *stunClient) discover() (*stunResult, error) {
	for _, srv := range c.servers {
		if r, err := c.query(srv); err == nil {
			log.Printf("[stun] %s -> %s:%d", srv, r.PublicIP, r.PublicPort)
			return r, nil
		}
	}
	return nil, fmt.Errorf("all STUN servers failed")
}

func (c *stunClient) query(addr string) (*stunResult, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(c.timeout))

	txID := make([]byte, 12)
	for i := range txID {
		txID[i] = byte(i + 1)
	}

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001)
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	copy(req[8:20], txID)

	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseSTUNResp(buf[:n], txID)
}

func (c *stunClient) queryFromConn(conn *net.UDPConn, addr string) (*stunResult, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}

	txID := make([]byte, 12)
	for i := range txID {
		txID[i] = byte(i + 2)
	}

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001)
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	copy(req[8:20], txID)

	conn.SetWriteDeadline(time.Now().Add(c.timeout))
	if _, err := conn.WriteTo(req, udpAddr); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(c.timeout))
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return parseSTUNResp(buf[:n], txID)
}

func detectNATType(servers []string, timeout time.Duration) NATType {
	if len(servers) < 2 {
		log.Printf("[stun] need at least 2 STUN servers for NAT detection, have %d", len(servers))
		return NATUnknown
	}

	localAddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	if err != nil {
		return NATUnknown
	}
	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return NATUnknown
	}
	defer conn.Close()

	first, err := (&stunClient{timeout: timeout}).queryFromConn(conn, servers[0])
	if err != nil {
		log.Printf("[stun] NAT detection: first server failed: %v", err)
		return NATUnknown
	}

	second, err := (&stunClient{timeout: timeout}).queryFromConn(conn, servers[1])
	if err != nil {
		log.Printf("[stun] NAT detection: second server failed: %v", err)
		return NATUnknown
	}

	if first.PublicPort != second.PublicPort {
		log.Printf("[stun] symmetric NAT detected: port %d vs %d", first.PublicPort, second.PublicPort)
		return NATSymmetric
	}

	log.Printf("[stun] easy NAT (port-consistent): %d", first.PublicPort)
	return NATEasy
}

func parseSTUNResp(data []byte, txID []byte) (*stunResult, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("too short")
	}
	if binary.BigEndian.Uint16(data[0:2]) != 0x0101 {
		return nil, fmt.Errorf("not binding response")
	}
	for i := 8; i < 20; i++ {
		if data[i] != txID[i-8] {
			return nil, fmt.Errorf("txID mismatch")
		}
	}

	length := int(binary.BigEndian.Uint16(data[2:4]))
	off := 20
	for off+4 <= 20+length {
		attrType := binary.BigEndian.Uint16(data[off : off+2])
		attrLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		if attrType == 0x0001 || attrType == 0x0020 {
			return parseXORAddr(data[off+4:off+4+attrLen], attrType)
		}
		off += 4 + attrLen
		if attrLen%4 != 0 {
			off += 4 - (attrLen % 4)
		}
	}
	return nil, fmt.Errorf("no mapped address")
}

func parseXORAddr(data []byte, attrType uint16) (*stunResult, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("attr too short")
	}
	port := int(binary.BigEndian.Uint16(data[2:4]))
	ip := make(net.IP, 4)
	copy(ip, data[4:8])

	if attrType == 0x0020 {
		ip[0] ^= byte((stunMagicCookie >> 24) & 0xFF)
		ip[1] ^= byte((stunMagicCookie >> 16) & 0xFF)
		ip[2] ^= byte((stunMagicCookie >> 8) & 0xFF)
		ip[3] ^= byte(stunMagicCookie & 0xFF)
		port ^= int((stunMagicCookie >> 16) & 0xFFFF)
	}
	return &stunResult{PublicIP: ip, PublicPort: port}, nil
}

func (a *Agent) discoverPublicIP() error {
	c := &stunClient{servers: a.cfg.StunServers, timeout: 3 * time.Second}
	r, err := c.discover()
	if err != nil {
		return err
	}
	a.publicIP = r.PublicIP
	a.publicPort = r.PublicPort

	a.natType = detectNATType(a.cfg.StunServers, 3*time.Second)
	log.Printf("[agent] NAT type: %s", a.natType)

	return nil
}

func (a *Agent) stunRefreshLoop() {
	interval := time.Duration(a.cfg.StunRefreshInterval) * time.Second
	ticker := time.NewTicker(interval)
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
			a.metrics.inc("stun_refreshes")
			if a.publicIP.String() != oldIP || a.publicPort != oldPort {
				log.Printf("[agent] public IP changed: %s:%d -> %s:%d",
					oldIP, oldPort, a.publicIP, a.publicPort)
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
		NATType:      string(a.natType),
	}
	a.mu.RLock()
	for addr, conn := range a.seedConns {
		a.sendToSeed(conn, Message{Type: "register", NodeInfo: &reg})
		log.Printf("[agent] re-registered with seed %s", addr)
	}
	a.mu.RUnlock()
}
