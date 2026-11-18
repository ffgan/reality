package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	crt := cert()
	tln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{crt}})
	if err != nil {
		panic(err)
	}
	dln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert()}})
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n%s\n%s\n", ln.Addr().String(), tln.Addr().String(), dln.Addr().String())
	_ = os.Stdout.Sync()
	mux := http.NewServeMux()
	mux.HandleFunc("/small", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("small-ok"))
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 300000)
		for i := range buf {
			buf[i] = 'x'
		}
		_, _ = w.Write(buf)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = io.Copy(w, r.Body)
			return
		}
		_, _ = w.Write([]byte("tls-ok"))
	})
	go func() { _ = http.Serve(ln, mux) }()
	go serveDuplex(dln)
	_ = http.Serve(tln, mux)
}

func serveDuplex(ln net.Listener) {
	const n = 512 * 1024
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			done := make(chan struct{})
			go func() {
				buf := make([]byte, 32*1024)
				for i := range buf {
					buf[i] = 0xA1
				}
				left := n
				for left > 0 {
					k := len(buf)
					if k > left {
						k = left
					}
					if _, err := conn.Write(buf[:k]); err != nil {
						break
					}
					left -= k
				}
				close(done)
			}()
			buf := make([]byte, n)
			_, _ = io.ReadFull(conn, buf)
			<-done
		}(conn)
	}
}

func cert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}
