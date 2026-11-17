package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"reflect"
	"sync"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
)

const (
	padContinue byte = 0
	padEnd      byte = 1
	padDirect   byte = 2

	bufSize = 8192
)

var (
	tls13Versions    = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	tlsClientHello   = []byte{0x16, 0x03}
	tlsServerHello   = []byte{0x16, 0x03, 0x03}
	tlsAppData       = []byte{0x17, 0x03, 0x03}
	tls13CipherSuite = map[uint16]bool{0x1301: true, 0x1302: true, 0x1303: true, 0x1304: true}
)

type visionConn struct {
	tls net.Conn
	raw net.Conn
	u   *utls.UConn

	uuid     []byte
	uuidSent bool

	isPadding    bool
	enableXtls   bool
	isTLS        bool
	isTLS12      bool
	filterLeft   int
	serverHello  int
	cipher       uint16
	directArmed  bool
	directRead   bool
	mu           sync.Mutex
	within       bool
	remCmd       int
	remContent   int
	remPad       int
	curCmd       int
	pending      []byte
	carry        []byte
	headerSent   bool
	responseDone bool
	request      []byte
}

func newVision(u *realityConn, uuid []byte, host string, port uint16) *visionConn {
	return &visionConn{
		tls:         u.UConn,
		raw:         u.NetConn(),
		u:           u.UConn,
		uuid:        append([]byte(nil), uuid...),
		isPadding:   true,
		filterLeft:  8,
		serverHello: -1,
		within:      true,
		remCmd:      -1,
		remContent:  -1,
		remPad:      -1,
		request:     encodeRequest(uuid, cmdTCP, host, port),
	}
}

func (c *visionConn) Write(p []byte) (int, error) {
	// The vision length field is a uint16. Xray also keeps each chunk within
	// one buffer so a single write cannot overflow it. A complete TLS record
	// stays intact so direct mode can still recognize it.
	if len(p) <= bufSize || (len(p) <= 0xffff && isCompleteRecord(p)) {
		if err := c.writeChunk(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	written := 0
	for len(p) > 0 {
		n := bufSize
		if n > len(p) {
			n = len(p)
		}
		if err := c.writeChunk(p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *visionConn) writeChunk(p []byte) error {
	c.mu.Lock()
	w := c.tls
	if c.directArmed {
		w = c.raw
		c.directArmed = false
	}
	if c.filterLeft > 0 && len(p) > 0 {
		c.filter(p)
	}
	frame := c.pad(p)
	first := !c.headerSent
	if first {
		c.headerSent = true
	}
	c.mu.Unlock()
	packet := frame
	if first {
		packet = append(append([]byte{}, c.request...), frame...)
	}
	_, err := w.Write(packet)
	return err
}

func (c *visionConn) Read(p []byte) (int, error) {
	if err := c.ensureHeader(); err != nil {
		return 0, err
	}
	for len(c.pending) == 0 {
		if c.directRead {
			n, err := c.raw.Read(p)
			return n, err
		}
		buf := make([]byte, 32*1024)
		n, err := c.tls.Read(buf)
		if n > 0 {
			c.mu.Lock()
			plain := c.unpad(buf[:n])
			if c.filterLeft > 0 && len(plain) > 0 {
				c.filter(plain)
			}
			direct := c.directRead
			c.pending = append(c.pending, plain...)
			c.mu.Unlock()
			if direct {
				c.pending = append(c.pending, leftover(c.u)...)
			}
		}
		if err != nil && len(c.pending) == 0 {
			return 0, err
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *visionConn) ensureHeader() error {
	c.mu.Lock()
	if c.headerSent && c.responseDone {
		c.mu.Unlock()
		return nil
	}
	var packet []byte
	if !c.headerSent {
		frame := c.pad(nil)
		packet = append(append([]byte{}, c.request...), frame...)
		c.headerSent = true
	}
	done := c.responseDone
	c.mu.Unlock()
	if packet != nil {
		if _, err := c.tls.Write(packet); err != nil {
			return err
		}
	}
	if done {
		return nil
	}
	for !c.responseDone {
		buf := make([]byte, 32*1024)
		n, err := c.tls.Read(buf)
		if n > 0 {
			c.pending = append(c.pending, buf[:n]...)
		}
		used, decErr := decodeResponse(c.pending)
		if decErr == errNeedMore {
			if err != nil {
				return err
			}
			continue
		}
		if decErr != nil {
			return decErr
		}
		rest := append([]byte{}, c.pending[used:]...)
		c.mu.Lock()
		c.pending = c.unpad(rest)
		c.responseDone = true
		c.mu.Unlock()
		if err != nil && len(c.pending) == 0 {
			return err
		}
	}
	return nil
}

func (c *visionConn) Close() error                       { return c.tls.Close() }
func (c *visionConn) LocalAddr() net.Addr                { return c.tls.LocalAddr() }
func (c *visionConn) RemoteAddr() net.Addr               { return c.tls.RemoteAddr() }
func (c *visionConn) SetDeadline(t time.Time) error      { return c.tls.SetDeadline(t) }
func (c *visionConn) SetReadDeadline(t time.Time) error  { return c.tls.SetReadDeadline(t) }
func (c *visionConn) SetWriteDeadline(t time.Time) error { return c.tls.SetWriteDeadline(t) }

func (c *visionConn) pad(content []byte) []byte {
	if !c.isPadding {
		return content
	}
	contentLen := len(content)
	var paddingLen int
	long := c.isTLS
	command := padContinue
	complete := isCompleteRecord(content)
	if c.isTLS && contentLen >= 6 && bytes.Equal(content[:3], tlsAppData) && complete {
		command = padEnd
		if c.enableXtls {
			command = padDirect
			c.directArmed = true
		}
		c.isPadding = false
		long = true
	} else if !c.isTLS12 && c.filterLeft <= 1 {
		command = padEnd
		c.isPadding = false
	}
	if contentLen < 900 && long {
		paddingLen = int(randInt(500)) + 900 - contentLen
	} else {
		paddingLen = int(randInt(256))
	}
	if paddingLen > bufSize-21-contentLen {
		paddingLen = bufSize - 21 - contentLen
	}
	if paddingLen < 0 {
		paddingLen = 0
	}
	out := make([]byte, 0, 16+5+contentLen+paddingLen)
	if !c.uuidSent {
		out = append(out, c.uuid...)
		c.uuidSent = true
	}
	out = append(out, command, byte(contentLen>>8), byte(contentLen), byte(paddingLen>>8), byte(paddingLen))
	out = append(out, content...)
	out = append(out, make([]byte, paddingLen)...)
	return out
}

func (c *visionConn) unpad(b []byte) []byte {
	if c.directRead {
		return b
	}
	if len(c.carry) > 0 {
		b = append(c.carry, b...)
		c.carry = nil
	}
	out := make([]byte, 0, len(b))
	for len(b) > 0 {
		if c.remCmd == -1 && c.remContent == -1 && c.remPad == -1 {
			if c.within && len(b) < 21 {
				c.carry = append([]byte{}, b...)
				break
			}
			if c.within && bytes.Equal(c.uuid, b[:16]) {
				b = b[16:]
				c.remCmd = 5
			} else {
				out = append(out, b...)
				break
			}
		}
		if c.remCmd > 0 {
			data := b[0]
			b = b[1:]
			switch c.remCmd {
			case 5:
				c.curCmd = int(data)
			case 4:
				c.remContent = int(data) << 8
			case 3:
				c.remContent |= int(data)
			case 2:
				c.remPad = int(data) << 8
			case 1:
				c.remPad |= int(data)
			}
			c.remCmd--
			continue
		}
		if c.remContent > 0 {
			n := c.remContent
			if n > len(b) {
				n = len(b)
			}
			out = append(out, b[:n]...)
			b = b[n:]
			c.remContent -= n
			continue
		}
		n := c.remPad
		if n > len(b) {
			n = len(b)
		}
		b = b[n:]
		c.remPad -= n
		if c.remCmd <= 0 && c.remContent <= 0 && c.remPad <= 0 {
			if c.curCmd == 0 {
				c.remCmd = 5
			} else {
				c.remCmd, c.remContent, c.remPad = -1, -1, -1
				c.within = false
				if c.curCmd == 2 {
					c.directRead = true
				}
				if len(b) > 0 {
					out = append(out, b...)
				}
				break
			}
		}
	}
	return out
}

func (c *visionConn) filter(b []byte) {
	if len(b) == 0 {
		return
	}
	c.filterLeft--
	if len(b) >= 6 {
		if bytes.Equal(tlsServerHello, b[:3]) && b[5] == 0x02 {
			c.serverHello = (int(b[3])<<8 | int(b[4])) + 5
			c.isTLS12 = true
			c.isTLS = true
			if len(b) >= 79 && c.serverHello >= 79 {
				sid := int(b[43])
				off := 43 + sid + 1
				if off+2 <= len(b) {
					c.cipher = binary.BigEndian.Uint16(b[off : off+2])
				}
			}
		} else if bytes.Equal(tlsClientHello, b[:2]) && b[5] == 0x01 {
			c.isTLS = true
		}
	}
	if c.serverHello > 0 {
		end := c.serverHello
		if end > len(b) {
			end = len(b)
		}
		c.serverHello -= len(b)
		if bytes.Contains(b[:end], tls13Versions) {
			if tls13CipherSuite[c.cipher] {
				c.enableXtls = true
			}
			c.filterLeft = 0
			return
		}
		if c.serverHello <= 0 {
			c.filterLeft = 0
		}
	}
}

func isCompleteRecord(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	header, record := 5, 0
	for i := 0; i < len(b); {
		if header > 0 {
			data := b[i]
			i++
			switch header {
			case 5:
				if data != 0x17 {
					return false
				}
			case 4, 3:
				if data != 0x03 {
					return false
				}
			case 2:
				record = int(data) << 8
			case 1:
				record |= int(data)
			}
			header--
			continue
		}
		if len(b)-i < record {
			return false
		}
		i += record
		record = 0
		header = 5
	}
	return header == 5 && record == 0
}

func randInt(n int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}

func leftover(u *utls.UConn) []byte {
	if u == nil || u.Conn == nil {
		return nil
	}
	v := reflect.ValueOf(u.Conn).Elem()
	var out []byte
	if f := v.FieldByName("input"); f.IsValid() {
		r := (*bytes.Reader)(unsafe.Pointer(f.UnsafeAddr()))
		if r.Len() > 0 {
			b := make([]byte, r.Len())
			_, _ = r.Read(b)
			out = append(out, b...)
		}
	}
	if f := v.FieldByName("rawInput"); f.IsValid() {
		buf := (*bytes.Buffer)(unsafe.Pointer(f.UnsafeAddr()))
		out = append(out, buf.Bytes()...)
		buf.Reset()
	}
	return out
}

var _ io.Reader = (*visionConn)(nil)
