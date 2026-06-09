package netutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
)

func HMACSign(psk string, data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(data)
	return mac.Sum(nil)
}

func HMACVerify(psk string, data, sig []byte) bool {
	expected := HMACSign(psk, data)
	return hmac.Equal(expected, sig)
}

func PackEndpoint(ip net.IP, port int) uint64 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	ipUint := binary.LittleEndian.Uint32(ip4)
	return (uint64(ipUint) << 32) | uint64(port)
}

func UnpackEndpoint(val uint64) (net.IP, int) {
	ipUint := uint32(val >> 32)
	port := int(val & 0xFFFF)
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipUint)
	return ip, port
}

func CreateUDPSocket(addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	return conn, nil
}
