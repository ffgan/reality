package main

import (
	"encoding/binary"
	"net"
)

const (
	cmdTCP byte = 0x01
	cmdUDP byte = 0x02

	addrIPv4   byte = 1
	addrDomain byte = 2
	addrIPv6   byte = 3

	flowVision = "xtls-rprx-vision"
)

func encodeRequest(uuid []byte, command byte, host string, port uint16) []byte {
	addons := encodeAddons(flowVision)
	out := make([]byte, 0, 1+16+1+len(addons)+1+2+1+len(host))
	out = append(out, 0)
	out = append(out, uuid...)
	out = append(out, byte(len(addons)))
	out = append(out, addons...)
	out = append(out, command)
	var portb [2]byte
	binary.BigEndian.PutUint16(portb[:], port)
	out = append(out, portb[:]...)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, addrIPv4)
			out = append(out, v4...)
			return out
		}
		out = append(out, addrIPv6)
		out = append(out, ip.To16()...)
		return out
	}
	out = append(out, addrDomain, byte(len(host)))
	out = append(out, host...)
	return out
}

func encodeAddons(flow string) []byte {
	// proto3 field 1, length-delimited string. Field 2 (seed) stays absent.
	body := append([]byte{0x0a, byte(len(flow))}, flow...)
	return body
}

func decodeResponse(buf []byte) (int, error) {
	if len(buf) < 2 {
		return 0, errNeedMore
	}
	if buf[0] != 0 {
		return 0, errBadVersion
	}
	n := int(buf[1])
	if len(buf) < 2+n {
		return 0, errNeedMore
	}
	return 2 + n, nil
}
