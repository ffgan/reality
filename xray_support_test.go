package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func serveEcho(t *testing.T, addr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func serveHTTP(t *testing.T, paths map[string]string) string {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range paths {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, body)
		})
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func serveTLS(t *testing.T) string {
	t.Helper()
	cert, err := selfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = io.Copy(w, r.Body)
			return
		}
		_, _ = io.WriteString(w, "tls-ok")
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytesOf(300000))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
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
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
}

func tlsClient(conn net.Conn) *tls.Conn {
	return tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "example.com"})
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func waitPort(port int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	addr := (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}).String()
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func bytesOf(n int) []byte { return bytes.Repeat([]byte{'x'}, n) }

func readLog(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	if len(b) > 4000 {
		return string(b[len(b)-4000:])
	}
	return string(b)
}

func splitRaw(raw string) (string, uint16, string, error) {
	path := "/"
	hostport := raw
	if i := strings.Index(raw, "/"); i >= 0 {
		hostport = raw[:i]
		path = raw[i:]
	}
	host, portText, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, "", err
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		return "", 0, "", err
	}
	return host, uint16(port), path, nil
}

func portOfHost(raw string) uint16 {
	_, port, _, err := splitRaw(raw)
	if err != nil {
		return 0
	}
	return port
}

func bodyOf(buf []byte) string {
	if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
		return string(buf[i+4:])
	}
	return string(buf)
}

func skipSocksAddr(t *testing.T, r io.Reader, atyp byte) {
	t.Helper()
	var n int
	switch atyp {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			t.Fatal(err)
		}
		n = int(l[0])
	default:
		t.Fatalf("atyp %d", atyp)
	}
	if _, err := io.ReadFull(r, make([]byte, n+2)); err != nil {
		t.Fatal(err)
	}
}
