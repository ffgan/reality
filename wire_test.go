package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestWireHelloOpens(t *testing.T) {
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var short [8]byte
	short[0] = 0x42
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		buf, _ := io.ReadAll(c)
		got <- buf
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
	cfg := realityConfig{
		ServerName:  "www.example.com",
		PublicKey:   server.PublicKey().Bytes(),
		ShortID:     short,
		Fingerprint: "chrome",
	}
	_, err = dialREALITY(raw, cfg)
	raw.Close()
	wire := <-got
	if len(wire) < 50 || wire[0] != 0x16 {
		t.Fatalf("handshake error %v wire %d", err, len(wire))
	}
	hello, err := handshakeMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	if hello[0] != 0x01 {
		t.Fatalf("type %x", hello[0])
	}
	sidLen := int(hello[38])
	if sidLen != 32 {
		t.Fatalf("session id len %d", sidLen)
	}
	aad := bytes.Clone(hello)
	peer, random := x25519FromHello(t, hello)
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := server.ECDH(pub)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := hkdf.Key(sha256.New, shared, random[:20], "REALITY", 32)
	if err != nil {
		t.Fatal(err)
	}
	sealed := bytes.Clone(aad[39 : 39+32])
	for i := 39; i < 71; i++ {
		aad[i] = 0
	}
	plain := gcmOpen(t, auth, random[20:], sealed, aad)
	if plain[0] != xrayVersionX || plain[1] != xrayVersionY || plain[2] != xrayVersionZ {
		t.Fatalf("version %d.%d.%d", plain[0], plain[1], plain[2])
	}
	if !bytes.Equal(plain[8:16], short[:]) {
		t.Fatalf("short id %x", plain[8:16])
	}
}

func handshakeMessage(wire []byte) ([]byte, error) {
	var msg []byte
	for len(wire) >= 5 && wire[0] == 0x16 {
		n := int(wire[3])<<8 | int(wire[4])
		if len(wire) < 5+n {
			break
		}
		msg = append(msg, wire[5:5+n]...)
		wire = wire[5+n:]
		if len(msg) >= 4 {
			want := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
			if len(msg) >= 4+want {
				return msg[:4+want], nil
			}
		}
	}
	return nil, io.ErrUnexpectedEOF
}

func x25519FromHello(t *testing.T, hello []byte) ([]byte, []byte) {
	t.Helper()
	if len(hello) < 39 {
		t.Fatal("short hello")
	}
	random := hello[6:38]
	i := 39 + int(hello[38])
	if len(hello) < i+2 {
		t.Fatal("short ciphers")
	}
	cs := int(binary.BigEndian.Uint16(hello[i:]))
	i += 2 + cs
	if len(hello) < i+1 {
		t.Fatal("short compression")
	}
	i += 1 + int(hello[i])
	if len(hello) < i+2 {
		t.Fatal("short extensions")
	}
	extEnd := i + 2 + int(binary.BigEndian.Uint16(hello[i:]))
	i += 2
	for i+4 <= extEnd && i+4 <= len(hello) {
		typ := binary.BigEndian.Uint16(hello[i:])
		n := int(binary.BigEndian.Uint16(hello[i+2:]))
		i += 4
		if i+n > len(hello) {
			break
		}
		body := hello[i : i+n]
		i += n
		if typ != 0x0033 || len(body) < 2 {
			continue
		}
		shares := body[2:]
		var hybrid, plain []byte
		for len(shares) >= 4 {
			group := binary.BigEndian.Uint16(shares)
			ln := int(binary.BigEndian.Uint16(shares[2:]))
			shares = shares[4:]
			if ln > len(shares) {
				break
			}
			data := shares[:ln]
			shares = shares[ln:]
			switch group {
			case uint16(utls.X25519):
				if len(data) == 32 {
					plain = data
				}
			case uint16(utls.X25519MLKEM768):
				if len(data) != mlkem.EncapsulationKeySize768+32 {
					t.Fatalf("mlkem share %d", len(data))
				}
				hybrid = data[mlkem.EncapsulationKeySize768:]
			}
		}
		if plain == nil && hybrid == nil {
			t.Fatal("no X25519 share")
		}
		if hybrid == nil {
			t.Fatal("server rejects a hello without X25519MLKEM768")
		}
		if plain != nil {
			return plain, random
		}
		return hybrid, random
	}
	t.Fatal("no key share extension")
	return nil, nil
}
