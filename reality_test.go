package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestSessionIDMatchesServerOpen(t *testing.T) {
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := client.ECDH(server.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	auth, err := hkdf.Key(sha256.New, shared, random[:20], "REALITY", 32)
	if err != nil {
		t.Fatal(err)
	}
	hello := make([]byte, 80)
	copy(hello[6:38], random[:])
	plain := []byte{26, 11, 9, 0, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8}
	block, err := aes.NewCipher(auth)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, random[20:], plain, hello)
	if len(sealed) != 32 {
		t.Fatalf("sealed len %d", len(sealed))
	}
	copy(hello[39:], sealed)

	serverShared, err := server.ECDH(client.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	serverAuth, err := hkdf.Key(sha256.New, serverShared, hello[6:26], "REALITY", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = aes.NewCipher(serverAuth)
	aead, _ = cipher.NewGCM(block)
	ciphertext := append([]byte(nil), hello[39:71]...)
	for i := 39; i < 71; i++ {
		hello[i] = 0
	}
	opened, err := aead.Open(nil, hello[6+20:6+32], ciphertext, hello)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatalf("opened %x", opened)
	}
}

func TestChromeHelloHasMLKEM(t *testing.T) {
	id := fingerprint("chrome")
	if id == nil {
		t.Fatal("missing chrome fingerprint")
	}
}

func TestAddonsFlow(t *testing.T) {
	got := encodeAddons(flowVision)
	want := append([]byte{0x0a, byte(len(flowVision))}, flowVision...)
	if !bytes.Equal(got, want) {
		t.Fatalf("%x", got)
	}
}
