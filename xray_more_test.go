package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestParseUUID(t *testing.T) {
	dashed, err := parseUUID("00000000-0000-0000-0000-000000000042")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := parseUUID("00000000000000000000000000000042")
	if err != nil || !bytes.Equal(dashed, plain) || plain[15] != 0x42 {
		t.Fatalf("%x %v", plain, err)
	}
	if _, err := parseUUID("zz"); err == nil {
		t.Fatal("odd or non-hex uuid accepted")
	}
	if _, err := parseUUID("aa"); err == nil {
		t.Fatal("short uuid accepted")
	}
}

func TestParseKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0x11}, 32)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		got, err := parseKey(enc.EncodeToString(raw))
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("%v %x", err, got)
		}
	}
	if _, err := parseKey("aaaa"); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestXrayMore(t *testing.T) {
	xray := "/tmp/xray-bin"
	if _, err := os.Stat(xray); err != nil {
		t.Skip(err)
	}
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private := base64.RawURLEncoding.EncodeToString(serverKey.Bytes())
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		t.Fatal(err)
	}
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", idBytes[0:4], idBytes[4:6], idBytes[6:8], idBytes[8:10], idBytes[10:16])
	httpSrv := serveHTTP(t, map[string]string{"/small": "small-ok"})
	httpsSrv := serveTLS(t)
	echoSrv := serveEcho(t, "127.0.0.1:0")

	port := freePort(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "xray.log")
	cfgPath := filepath.Join(dir, "server.json")
	config := fmt.Sprintf(`{
		"log": {"loglevel": "warning", "access": "%s", "error": "%s"},
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
					"shortIds": ["", "ab", "0123456789abcdef"]
				}
			}
		}],
		"outbounds": [{
			"protocol": "freedom",
			"settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8", "::1/128"]}]}
		}]
	}`, logPath, logPath, port, uuid, httpsSrv, private)
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
	if !waitPort(port, 5*time.Second) {
		t.Fatal(readLog(logPath))
	}
	time.Sleep(1500 * time.Millisecond)

	serverAddr := fmt.Sprintf("127.0.0.1:%d", port)
	pub := serverKey.PublicKey().Bytes()
	full := realityConfig{ServerName: "www.example.com", PublicKey: pub, Fingerprint: "chrome"}
	decoded, _ := hex.DecodeString("0123456789abcdef")
	copy(full.ShortID[:], decoded)

	t.Run("short ids", func(t *testing.T) {
		for _, sid := range []string{"", "ab", "0123456789abcdef"} {
			cfg := full
			cfg.ShortID = [8]byte{}
			raw, _ := hex.DecodeString(sid)
			copy(cfg.ShortID[:], raw)
			body, err := get(serverAddr, cfg, idBytes[:], httpSrv+"/small")
			if err != nil || body != "small-ok" {
				t.Fatalf("sid %q body %q err %v log %s", sid, body, err, readLog(logPath))
			}
		}
	})

	t.Run("key encodings", func(t *testing.T) {
		for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
			cfg := full
			parsed, err := parseKey(enc.EncodeToString(pub))
			if err != nil {
				t.Fatal(err)
			}
			cfg.PublicKey = parsed
			body, err := get(serverAddr, cfg, idBytes[:], httpSrv+"/small")
			if err != nil || body != "small-ok" {
				t.Fatalf("%v body %q err %v", enc, body, err)
			}
		}
	})

	t.Run("split request", func(t *testing.T) {
		host, port, err := splitHost(httpSrv)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := dialVision(serverAddr, full, idBytes[:], host, port)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write(nil); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("GET /small HTTP/1.0\r\n")); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("Host: x\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		buf, err := io.ReadAll(conn)
		if err != nil || bodyOf(buf) != "small-ok" {
			t.Fatalf("body %q err %v", bodyOf(buf), err)
		}
	})

	t.Run("byte writes then bulk", func(t *testing.T) {
		conn := dialEcho(t, serverAddr, full, idBytes[:], echoSrv)
		defer conn.Close()
		var one []byte
		for i := 0; i < 32; i++ {
			one = append(one, byte(i))
			if _, err := conn.Write(one[i : i+1]); err != nil {
				t.Fatal(err)
			}
		}
		if got := readN(t, conn, len(one)); !bytes.Equal(got, one) {
			t.Fatalf("byte echo %x", got)
		}
		bulk := bytesOf(100000)
		got := exchange(t, conn, bulk)
		if !bytes.Equal(got, bulk) {
			t.Fatalf("bulk len %d", len(got))
		}
	})

	t.Run("one large write", func(t *testing.T) {
		conn := dialEcho(t, serverAddr, full, idBytes[:], echoSrv)
		defer conn.Close()
		bulk := bytesOf(180000)
		got := exchange(t, conn, bulk)
		if !bytes.Equal(got, bulk) {
			t.Fatalf("len %d", len(got))
		}
	})

	t.Run("bidirectional", func(t *testing.T) {
		conn := dialEcho(t, serverAddr, full, idBytes[:], echoSrv)
		defer conn.Close()
		payload := make([]byte, 65536)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		errc := make(chan error, 1)
		go func() {
			_, err := conn.Write(payload)
			errc <- err
		}()
		got := readN(t, conn, len(payload))
		if err := <-errc; err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("err %v match %v", err, bytes.Equal(got, payload))
		}
	})

	t.Run("tls upload and download", func(t *testing.T) {
		host, port, err := splitHost(httpsSrv)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := dialVision(serverAddr, full, idBytes[:], host, port)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		tlsConn := tlsClient(conn)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			t.Fatal(err)
		}
		post := make([]byte, 100000)
		if _, err := rand.Read(post); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(tlsConn, "POST / HTTP/1.0\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", host, len(post))
		if _, err := tlsConn.Write(post); err != nil {
			t.Fatal(err)
		}
		_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
		buf, err := io.ReadAll(tlsConn)
		if err != nil || !bytes.Contains(buf, post) {
			t.Fatalf("post echo len %d err %v log %s", len(buf), err, readLog(logPath))
		}

		conn2, err := dialVision(serverAddr, full, idBytes[:], host, port)
		if err != nil {
			t.Fatal(err)
		}
		defer conn2.Close()
		tlsConn = tlsClient(conn2)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(tlsConn, "GET /big HTTP/1.0\r\nHost: %s\r\n\r\n", host)
		_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
		buf, err = io.ReadAll(tlsConn)
		if err != nil || bodyOf(buf) != string(bytesOf(300000)) {
			t.Fatalf("download len %d err %v", len(bodyOf(buf)), err)
		}
	})

	t.Run("socks addresses", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go serveSOCKS(ln, func(host string, port uint16) (net.Conn, error) {
			return dialVision(serverAddr, full, idBytes[:], host, port)
		})
		proxy := ln.Addr().String()
		host, hport, err := splitHost(httpSrv)
		if err != nil {
			t.Fatal(err)
		}
		if body := socksGetAddr(t, proxy, 1, net.ParseIP(host).To4(), hport, "/small"); body != "small-ok" {
			t.Fatalf("ipv4 socks %q", body)
		}
		if _, err := socksCommand(proxy, 2); err == nil {
			t.Fatal("bind was accepted")
		}
		if _, err := socksCommand(proxy, 3); err == nil {
			t.Fatal("udp associate was accepted")
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		v6, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skip(err)
		}
		v6.Close()
		echo6 := serveEcho(t, "[::1]:0")
		host, port, err := splitHost(echo6)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := dialVision(serverAddr, full, idBytes[:], host, port)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		got := exchange(t, conn, []byte("ipv6-echo"))
		if !bytes.Equal(got, []byte("ipv6-echo")) {
			t.Fatalf("%q", got)
		}
		ip := net.ParseIP(host)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go serveSOCKS(ln, func(host string, port uint16) (net.Conn, error) {
			return dialVision(serverAddr, full, idBytes[:], host, port)
		})
		if body := socksGetAddr(t, ln.Addr().String(), 4, ip, port, ""); body != "ping" {
			t.Fatalf("socks ipv6 %q", body)
		}
	})

	t.Run("fingerprints", func(t *testing.T) {
		names := []string{
			"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
			"hellofirefox_120", "hellofirefox_148", "hellochrome_120", "hellochrome_131",
			"hellochrome_133", "hellochrome_155", "helloios_13", "helloios_14",
			"helloedge_106", "hellosafari_26_3", "hello360_11_0", "helloqq_11_1", "hellogolang",
		}
		for _, name := range names {
			cfg := full
			cfg.Fingerprint = name
			has := fingerprintHasMLKEM(name)
			body, err := get(serverAddr, cfg, idBytes[:], httpSrv+"/small")
			if has {
				if err != nil || body != "small-ok" {
					t.Fatalf("%s body %q err %v log %s", name, body, err, readLog(logPath))
				}
				continue
			}
			if err == nil {
				t.Fatalf("%s has no X25519MLKEM768 share but the server accepted it", name)
			}
		}
	})

	t.Run("unknown fingerprint", func(t *testing.T) {
		cfg := full
		cfg.Fingerprint = "not-a-fingerprint"
		if _, err := dialVision(serverAddr, cfg, idBytes[:], "127.0.0.1", 1); err == nil {
			t.Fatal("unknown fingerprint was accepted")
		}
	})
}

func dialEcho(t *testing.T, server string, cfg realityConfig, id []byte, echo string) net.Conn {
	t.Helper()
	host, port, err := splitHost(echo)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialVision(server, cfg, id, host, port)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	return conn
}

func exchange(t *testing.T, conn net.Conn, payload []byte) []byte {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		errc <- err
	}()
	got := readN(t, conn, len(payload))
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	return got
}

func readN(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	return buf
}

func splitHost(hostport string) (string, uint16, error) {
	host, port, _, err := splitRaw(hostport)
	return host, port, err
}

func socksGetAddr(t *testing.T, proxy string, atyp byte, ip net.IP, port uint16, path string) string {
	t.Helper()
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	req := []byte{5, 1, 0, atyp}
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil || head[1] != 0 {
		t.Fatalf("socks %v %v", head, err)
	}
	skipSocksAddr(t, conn, head[3])
	if path == "" {
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		return string(buf)
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.0\r\nHost: x\r\n\r\n", path)
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	buf, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	return bodyOf(buf)
}

func socksCommand(proxy string, cmd byte) ([]byte, error) {
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte{5, cmd, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
		return nil, err
	}
	buf := make([]byte, 10)
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		return buf[:n], err
	}
	if buf[1] == 0 {
		return buf, nil
	}
	return buf, fmt.Errorf("rejected %d", buf[1])
}

func fingerprintHasMLKEM(name string) bool {
	id := fingerprint(name)
	if id == nil {
		return false
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	u := utls.UClient(a, &utls.Config{ServerName: "www.example.com", InsecureSkipVerify: true, SessionTicketsDisabled: true}, *id)
	if err := u.BuildHandshakeState(); err != nil || len(u.HandshakeState.Hello.Raw) < 40 {
		return false
	}
	return bytes.Contains(u.HandshakeState.Hello.Raw, mlkemSharePrefix())
}

func mlkemSharePrefix() []byte {
	var prefix [4]byte
	binary.BigEndian.PutUint16(prefix[0:2], uint16(utls.X25519MLKEM768))
	binary.BigEndian.PutUint16(prefix[2:4], uint16(mlkem.EncapsulationKeySize768+32))
	return prefix[:]
}
