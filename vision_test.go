package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestVisionPadRoundTrip(t *testing.T) {
	id := bytes.Repeat([]byte{0xab}, 16)
	c := newTestVision(id)
	payload := []byte("hello vision")
	frame := c.pad(payload)
	if !bytes.HasPrefix(frame, id) {
		t.Fatal("first frame must start with the user id")
	}
	got := c.unpad(frame)
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip %q", got)
	}
	second := c.pad([]byte("more"))
	if bytes.HasPrefix(second, id) {
		t.Fatal("user id is only sent once")
	}
	if !bytes.Equal(c.unpad(second), []byte("more")) {
		t.Fatal("second frame")
	}
}

func TestVisionSplitReads(t *testing.T) {
	id := bytes.Repeat([]byte{0x11}, 16)
	c := newTestVision(id)
	frame := c.pad([]byte("abcdefghij"))
	var got []byte
	for i := 0; i < len(frame); i++ {
		got = append(got, c.unpad(frame[i:i+1])...)
	}
	if !bytes.Equal(got, []byte("abcdefghij")) {
		t.Fatalf("split %q", got)
	}
}

func TestVisionDirectCommand(t *testing.T) {
	id := bytes.Repeat([]byte{0x22}, 16)
	c := newTestVision(id)
	c.isTLS = true
	c.enableXtls = true
	record := []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0xff}
	frame := c.pad(record)
	if !c.directArmed {
		t.Fatal("complete TLS application record should arm direct copy")
	}
	if c.unpad(frame) == nil || c.curCmd != int(padDirect) {
		t.Fatalf("command %d", c.curCmd)
	}
	if !c.directRead {
		t.Fatal("reader should switch to the raw connection")
	}
}

func TestFilterTLS13(t *testing.T) {
	c := newTestVision(bytes.Repeat([]byte{1}, 16))
	hello := make([]byte, 90)
	copy(hello, []byte{0x16, 0x03, 0x03, 0x00, 0x55, 0x02})
	hello[43] = 32
	hello[43+32+1] = 0x13
	hello[43+32+2] = 0x01
	copy(hello[70:], []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
	c.filter(hello)
	if !c.enableXtls || !c.isTLS12 || !c.isTLS {
		t.Fatalf("tls=%v 1.2=%v xtls=%v", c.isTLS, c.isTLS12, c.enableXtls)
	}
}

func TestAddressEncodings(t *testing.T) {
	id := bytes.Repeat([]byte{2}, 16)
	v4 := encodeRequest(id, cmdTCP, "1.2.3.4", 443)
	if v4[len(v4)-5] != addrIPv4 || !bytes.Equal(v4[len(v4)-4:], []byte{1, 2, 3, 4}) {
		t.Fatalf("ipv4 %x", v4)
	}
	if portOf(v4) != 443 {
		t.Fatalf("port %d", portOf(v4))
	}
	dom := encodeRequest(id, cmdTCP, "example.com", 80)
	if !bytes.Contains(dom, append([]byte{addrDomain, byte(len("example.com"))}, "example.com"...)) {
		t.Fatalf("domain %x", dom)
	}
	v6 := encodeRequest(id, cmdTCP, "2001:db8::1", 53)
	if v6[len(v6)-17] != addrIPv6 || len(v6) < 19 {
		t.Fatalf("ipv6 %x", v6)
	}
}

func TestChromeHelloSealsForServer(t *testing.T) {
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, b := pipe()
	defer a.Close()
	defer b.Close()
	u := utls.UClient(a, &utls.Config{ServerName: "www.example.com", InsecureSkipVerify: true, SessionTicketsDisabled: true}, utls.HelloChrome_Auto)
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	hello := u.HandshakeState.Hello
	if len(hello.SessionId) != 32 && len(hello.Raw) < 71 {
		t.Fatalf("session %d raw %d", len(hello.SessionId), len(hello.Raw))
	}
	keys := u.HandshakeState.State13.KeyShareKeys
	if keys == nil || (keys.Ecdhe == nil && keys.MlkemEcdhe == nil) {
		t.Fatal("chrome hello has no X25519 key share")
	}
	hasMLKEM := false
	for _, share := range hello.KeyShares {
		if share.Group == utls.X25519MLKEM768 {
			hasMLKEM = true
		}
	}
	if !hasMLKEM {
		t.Fatal("xray 26.11.9 rejects a ClientHello without X25519MLKEM768")
	}
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = 26, 11, 9
	var short [8]byte
	short[0] = 0xab
	copy(hello.SessionId[8:], short[:])
	ecdhe := keys.Ecdhe
	if ecdhe == nil {
		ecdhe = keys.MlkemEcdhe
	}
	shared, err := ecdhe.ECDH(server.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	serverShared, err := server.ECDH(ecdhe.PublicKey())
	if err != nil || !bytes.Equal(shared, serverShared) {
		t.Fatal("client and server X25519 secrets differ")
	}
	auth, err := hkdf.Key(sha256.New, shared, hello.Random[:20], "REALITY", 32)
	if err != nil {
		t.Fatal(err)
	}
	sealed := gcmSeal(t, auth, hello.Random[20:], hello.SessionId[:16], hello.Raw)
	aad := append([]byte(nil), hello.Raw...)
	copy(aad[39:71], sealed)
	for i := 39; i < 71; i++ {
		aad[i] = 0
	}
	opened := gcmOpen(t, auth, hello.Random[20:], sealed, aad)
	if opened[0] != 26 || opened[1] != 11 || opened[2] != 9 || opened[8] != 0xab {
		t.Fatalf("server saw %x", opened)
	}
}

func newTestVision(id []byte) *visionConn {
	return &visionConn{
		uuid:        append([]byte(nil), id...),
		isPadding:   true,
		filterLeft:  8,
		serverHello: -1,
		within:      true,
		remCmd:      -1,
		remContent:  -1,
		remPad:      -1,
	}
}

func portOf(packet []byte) uint16 {
	n := 1 + 16 + 1 + int(packet[17])
	return binary.BigEndian.Uint16(packet[n+1 : n+3])
}

func pipe() (net.Conn, net.Conn) {
	a, b := net.Pipe()
	return a, b
}

func gcmSeal(t *testing.T, key, nonce, plain, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead.Seal(nil, nonce, plain, aad)
}

func gcmOpen(t *testing.T, key, nonce, ciphertext, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	out, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
