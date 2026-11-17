package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Versions match xray-core 26.11.9. The REALITY server checks these three bytes.
const (
	xrayVersionX = 26
	xrayVersionY = 11
	xrayVersionZ = 9
)

type realityConfig struct {
	ServerName  string
	PublicKey   []byte
	ShortID     [8]byte
	Fingerprint string
}

type realityConn struct {
	*utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

func dialREALITY(raw net.Conn, cfg realityConfig) (*realityConn, error) {
	helloID := fingerprint(cfg.Fingerprint)
	if helloID == nil {
		return nil, fmt.Errorf("REALITY: failed to get fingerprint")
	}
	rc := &realityConn{serverName: cfg.ServerName}
	utlsConfig := &utls.Config{
		VerifyPeerCertificate:  rc.verify,
		ServerName:             cfg.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}
	rc.UConn = utls.UClient(raw, utlsConfig, *helloID)
	if err := rc.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := rc.HandshakeState.Hello
	if len(hello.Raw) < 39+32 || hello.Raw[38] != 32 {
		return nil, fmt.Errorf("REALITY: fingerprint %s has no 32-byte session id", cfg.Fingerprint)
	}
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	hello.SessionId[0] = xrayVersionX
	hello.SessionId[1] = xrayVersionY
	hello.SessionId[2] = xrayVersionZ
	hello.SessionId[3] = 0
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], cfg.ShortID[:])

	publicKey, err := ecdh.X25519().NewPublicKey(cfg.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("REALITY: nil publicKey: %w", err)
	}
	keys := rc.HandshakeState.State13.KeyShareKeys
	if keys == nil {
		return nil, fmt.Errorf("REALITY: fingerprint %s has no TLS 1.3 key share", cfg.Fingerprint)
	}
	ecdhe := keys.Ecdhe
	if ecdhe == nil {
		ecdhe = keys.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, fmt.Errorf("REALITY: fingerprint %s does not support TLS 1.3", cfg.Fingerprint)
	}
	shared, err := ecdhe.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("REALITY: nil sharedKey: %w", err)
	}
	rc.authKey, err = hkdf.Key(sha256.New, shared, hello.Random[:20], "REALITY", 32)
	if err != nil {
		return nil, fmt.Errorf("REALITY: nil authKey: %w", err)
	}
	block, err := aes.NewCipher(rc.authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// AAD is the ClientHello with a zero SessionId. The server zeroes the
	// received SessionId before Open, because that field aliases original[39:].
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	if err := rc.Handshake(); err != nil {
		return nil, err
	}
	if !rc.verified {
		return nil, fmt.Errorf("REALITY: processed invalid connection")
	}
	return rc, nil
}

func (c *realityConn) verify(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("REALITY: empty certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	if pub, ok := leaf.PublicKey.(ed25519.PublicKey); ok {
		mac := hmac.New(sha512.New, c.authKey)
		mac.Write(pub)
		if bytes.Equal(mac.Sum(nil), leaf.Signature) {
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{DNSName: c.serverName, Intermediates: x509.NewCertPool()}
	for _, raw := range rawCerts[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		opts.Intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(opts); err != nil {
		return err
	}
	return nil
}

func fingerprint(name string) *utls.ClientHelloID {
	presets := map[string]*utls.ClientHelloID{
		"":                 &utls.HelloChrome_Auto,
		"chrome":           &utls.HelloChrome_Auto,
		"firefox":          &utls.HelloFirefox_Auto,
		"safari":           &utls.HelloSafari_Auto,
		"ios":              &utls.HelloIOS_Auto,
		"android":          &utls.HelloAndroid_11_OkHttp,
		"edge":             &utls.HelloEdge_Auto,
		"360":              &utls.Hello360_Auto,
		"qq":               &utls.HelloQQ_Auto,
		"hellofirefox_120": &utls.HelloFirefox_120,
		"hellofirefox_148": &utls.HelloFirefox_148,
		"hellochrome_120":  &utls.HelloChrome_120,
		"hellochrome_131":  &utls.HelloChrome_131,
		"hellochrome_133":  &utls.HelloChrome_133,
		"hellochrome_155":  &utls.HelloChrome_155,
		"helloios_13":      &utls.HelloIOS_13,
		"helloios_14":      &utls.HelloIOS_14,
		"helloedge_106":    &utls.HelloEdge_106,
		"hellosafari_26_3": &utls.HelloSafari_26_3,
		"hello360_11_0":    &utls.Hello360_11_0,
		"helloqq_11_1":     &utls.HelloQQ_11_1,
		"hellogolang":      &utls.HelloGolang,
	}
	return presets[name]
}
