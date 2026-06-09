package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	stunBindingRequest  = 0x0001
	stunBindingResponse = 0x0101
	stunMagicCookie     = 0x2112A442
)

type STUNResult struct {
	PublicIP   net.IP
	PublicPort int
	MappedAddr string
}

type STUNClient struct {
	servers []string
	timeout time.Duration
}

func NewSTUNClient(servers []string) *STUNClient {
	return &STUNClient{
		servers: servers,
		timeout: 3 * time.Second,
	}
}

func (c *STUNClient) Discover() (*STUNResult, error) {
	for _, server := range c.servers {
		result, err := c.queryServer(server)
		if err != nil {
			log.Printf("[STUN] failed to query %s: %v", server, err)
			continue
		}
		log.Printf("[STUN] discovered public endpoint: %s", result.MappedAddr)
		return result, nil
	}
	return nil, fmt.Errorf("all STUN servers failed")
}

func (c *STUNClient) queryServer(addr string) (*STUNResult, error) {
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

	// Build STUN Binding Request
	txID := make([]byte, 12)
	for i := range txID {
		txID[i] = byte(i + 1)
	}

	req := buildSTUNRequest(stunBindingRequest, txID)
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return parseSTUNResponse(buf[:n], txID)
}

func buildSTUNRequest(msgType uint16, txID []byte) []byte {
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], msgType)
	binary.BigEndian.PutUint16(msg[2:4], 0) // length: no attributes
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txID)
	return msg
}

func parseSTUNResponse(data []byte, expectedTxID []byte) (*STUNResult, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("response too short")
	}

	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != stunBindingResponse {
		return nil, fmt.Errorf("unexpected message type: %d", msgType)
	}

	txID := data[8:20]
	for i := range txID {
		if txID[i] != expectedTxID[i] {
			return nil, fmt.Errorf("transaction ID mismatch")
		}
	}

	// Parse attributes
	offset := 20
	length := int(binary.BigEndian.Uint16(data[2:4]))
	for offset+4 <= 20+length {
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))

		if attrType == 0x0001 || attrType == 0x0020 {
			// MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
			return parseMappedAddress(data[offset+4:offset+4+attrLen], attrType, data[4:20])
		}

		offset += 4 + attrLen
		// Align to 4 bytes
		if attrLen%4 != 0 {
			offset += 4 - (attrLen % 4)
		}
	}

	return nil, fmt.Errorf("no mapped address in response")
}

func parseMappedAddress(data []byte, attrType uint16, msgID []byte) (*STUNResult, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("attribute too short")
	}

	port := int(binary.BigEndian.Uint16(data[2:4]))
	ip := net.IP(data[4:8])

	if attrType == 0x0020 {
		// XOR-MAPPED-ADDRESS: decode with magic cookie and txID
		ip[0] ^= byte(stunMagicCookie >> 24)
		ip[1] ^= byte(stunMagicCookie >> 16)
		ip[2] ^= byte(stunMagicCookie >> 8)
		ip[3] ^= byte(stunMagicCookie)
		port ^= int(stunMagicCookie >> 16)
	}

	return &STUNResult{
		PublicIP:   ip,
		PublicPort: port,
		MappedAddr: fmt.Sprintf("%s:%d", ip, port),
	}, nil
}

func GetLocalIP() (net.IP, error) {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}
