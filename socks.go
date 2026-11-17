package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

func serveSOCKS(ln net.Listener, dial func(host string, port uint16) (net.Conn, error)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			host, port, err := socks5(conn)
			if err != nil {
				return
			}
			remote, err := dial(host, port)
			if err != nil {
				_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			defer remote.Close()
			_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			errc := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(remote, conn); errc <- struct{}{} }()
			go func() { _, _ = io.Copy(conn, remote); errc <- struct{}{} }()
			<-errc
		}()
	}
}

func socks5(conn net.Conn) (string, uint16, error) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{})
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", 0, err
	}
	if head[0] != 5 {
		return "", 0, fmt.Errorf("socks version %d", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", 0, err
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", 0, err
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", 0, err
	}
	if req[0] != 5 || req[1] != 1 {
		return "", 0, fmt.Errorf("unsupported socks command %d", req[1])
	}
	var host string
	switch req[3] {
	case 1:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case 3:
		n := make([]byte, 1)
		if _, err := io.ReadFull(conn, n); err != nil {
			return "", 0, err
		}
		buf := make([]byte, int(n[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, err
		}
		host = string(buf)
	case 4:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	default:
		return "", 0, fmt.Errorf("bad atyp %d", req[3])
	}
	portb := make([]byte, 2)
	if _, err := io.ReadFull(conn, portb); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(portb), nil
}
