package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestXrayRealityEndToEnd(t *testing.T) {
	xray := "/tmp/xray-bin"
	if _, err := os.Stat(xray); err != nil {
		t.Skip(err)
	}
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes())
	private := base64.RawURLEncoding.EncodeToString(serverKey.Bytes())
	var id [16]byte
	id[0] = 0x42
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
	shortHex := "0123456789abcdef"

	httpSrv := serveHTTP(t, map[string]string{"/small": "small-ok", "/big": string(bytesOf(200000))})
	httpsSrv := serveTLS(t)

	realityPort := freePort(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.json")
	logPath := filepath.Join(dir, "xray.log")
	config := fmt.Sprintf(`{
		"log": {"loglevel": "debug", "access": "%s", "error": "%s"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": %d,
			"protocol": "vless",
			"settings": {"clients": [{"id": "%s", "flow": "xtls-rprx-vision"}], "decryption": "none"},
			"streamSettings": {
				"network": "raw",
				"security": "reality",
				"realitySettings": {
					"dest": "%s",
					"serverNames": ["www.example.com"],
					"privateKey": "%s",
					"shortIds": ["%s"]
				}
			}
		}],
		"outbounds": [{
			"protocol": "freedom",
			"settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}
		}]
	}`, logPath, logPath, realityPort, uuid, httpsSrv, private, shortHex)
	if err := os.WriteFile(cfgPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(xray, "run", "-c", cfgPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	if !waitPort(realityPort, 5*time.Second) {
		t.Fatal(readLog(logPath))
	}
	// REALITY probes dest before it will read application data. Give that
	// probe time to finish so the first client is not held for five seconds.
	time.Sleep(1500 * time.Millisecond)

	rawID, _ := parseUUID(uuid)
	pub, _ := parseKey(public)
	var short [8]byte
	decoded, _ := hex.DecodeString(shortHex)
	copy(short[:], decoded)
	cfg := realityConfig{ServerName: "www.example.com", PublicKey: pub, ShortID: short, Fingerprint: "chrome"}
	serverAddr := fmt.Sprintf("127.0.0.1:%d", realityPort)

	t.Run("http", func(t *testing.T) {
		body, err := get(serverAddr, cfg, rawID, httpSrv+"/small")
		if err != nil || body != "small-ok" {
			t.Fatalf("body %q err %v log %s", body, err, readLog(logPath))
		}
	})
	t.Run("large", func(t *testing.T) {
		body, err := get(serverAddr, cfg, rawID, httpSrv+"/big")
		if err != nil || body != string(bytesOf(200000)) {
			t.Fatalf("len %d err %v", len(body), err)
		}
	})
	t.Run("tls", func(t *testing.T) {
		body, err := getTLS(serverAddr, cfg, rawID, httpsSrv)
		if err != nil || body != "tls-ok" {
			t.Fatalf("body %q err %v log %s", body, err, readLog(logPath))
		}
	})
	t.Run("socks", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go serveSOCKS(ln, func(host string, port uint16) (net.Conn, error) {
			return dialVision(serverAddr, cfg, rawID, host, port)
		})
		out := socksGet(t, ln.Addr().String(), httpSrv+"/small")
		if out != "small-ok" {
			t.Fatalf("socks %q", out)
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		errc := make(chan error, 8)
		for i := 0; i < 8; i++ {
			go func() {
				body, err := get(serverAddr, cfg, rawID, httpSrv+"/small")
				if err != nil || body != "small-ok" {
					errc <- fmt.Errorf("%q %v", body, err)
					return
				}
				errc <- nil
			}()
		}
		for i := 0; i < 8; i++ {
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("bad short id", func(t *testing.T) {
		bad := cfg
		bad.ShortID[0] ^= 0xff
		if _, err := dialVision(serverAddr, bad, rawID, "127.0.0.1", 1); err == nil {
			t.Fatal("expected authentication failure")
		}
	})
	t.Run("bad uuid", func(t *testing.T) {
		wrong := append([]byte(nil), rawID...)
		wrong[0] ^= 0xff
		conn, err := dialVision(serverAddr, cfg, wrong, "127.0.0.1", portOfHost(httpSrv))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("GET /small HTTP/1.0\r\n\r\n"))
		buf := make([]byte, 32)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Read(buf); err == nil {
			t.Fatal("server accepted a bad user id")
		}
	})
	t.Run("bad sni", func(t *testing.T) {
		bad := cfg
		bad.ServerName = "wrong.example"
		if _, err := dialVision(serverAddr, bad, rawID, "127.0.0.1", 1); err == nil {
			t.Fatal("expected SNI rejection")
		}
	})
	t.Run("bad public key", func(t *testing.T) {
		bad := cfg
		bad.PublicKey = append([]byte(nil), cfg.PublicKey...)
		bad.PublicKey[0] ^= 0xff
		if _, err := dialVision(serverAddr, bad, rawID, "127.0.0.1", 1); err == nil {
			t.Fatal("expected public key rejection")
		}
	})
	t.Run("firefox", func(t *testing.T) {
		ff := cfg
		ff.Fingerprint = "firefox"
		body, err := get(serverAddr, ff, rawID, httpSrv+"/small")
		if err != nil || body != "small-ok" {
			t.Fatalf("body %q err %v", body, err)
		}
	})
}

func dialVision(server string, cfg realityConfig, id []byte, host string, port uint16) (net.Conn, error) {
	raw, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	rc, err := dialREALITY(raw, cfg)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return newVision(rc, id, host, port), nil
}

func get(server string, cfg realityConfig, id []byte, rawURL string) (string, error) {
	host, port, path, err := splitRaw(rawURL)
	if err != nil {
		return "", err
	}
	conn, err := dialVision(server, cfg, id, host, port)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", path, host)
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	buf, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return bodyOf(buf), nil
}

func getTLS(server string, cfg realityConfig, id []byte, rawURL string) (string, error) {
	host, port, _, err := splitRaw(rawURL)
	if err != nil {
		return "", err
	}
	conn, err := dialVision(server, cfg, id, host, port)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	tlsConn := tlsClient(conn)
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return "", err
	}
	fmt.Fprintf(tlsConn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
	buf, err := io.ReadAll(tlsConn)
	if err != nil {
		return "", err
	}
	return bodyOf(buf), nil
}

func socksGet(t *testing.T, proxy, rawURL string) string {
	t.Helper()
	host, port, path, err := splitRaw(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil || head[1] != 0 {
		t.Fatalf("socks reply %v %v", head, err)
	}
	skipSocksAddr(t, conn, head[3])
	fmt.Fprintf(conn, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", path, host)
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	buf, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	return bodyOf(buf)
}
