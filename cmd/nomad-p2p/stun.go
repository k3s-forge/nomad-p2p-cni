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
	binary.BigEndian.PutUint16(req[0:2], 0x0001) // Binding Request
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
			return parseXORAddr(data[off+4:off+4+attrLen], attrType, data[4:20])
		}
		off += 4 + attrLen
		if attrLen%4 != 0 {
			off += 4 - (attrLen % 4)
		}
	}
	return nil, fmt.Errorf("no mapped address")
}

func parseXORAddr(data []byte, attrType uint16, msgID []byte) (*stunResult, error) {
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
