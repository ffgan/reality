package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:10808", "local socks5 address")
	server := flag.String("server", "", "reality server host:port")
	uuid := flag.String("uuid", "", "vless user id")
	sni := flag.String("sni", "", "reality server name")
	pbk := flag.String("pbk", "", "reality public key, base64")
	sid := flag.String("sid", "", "reality short id, hex")
	fp := flag.String("fp", "chrome", "utls fingerprint, same names as xray")
	flag.Parse()
	if *server == "" || *uuid == "" || *sni == "" || *pbk == "" {
		fmt.Fprintln(os.Stderr, "usage: reality -server host:port -uuid UUID -sni name -pbk BASE64 [-sid HEX] [-fp chrome] [-listen 127.0.0.1:10808]")
		os.Exit(2)
	}
	id, err := parseUUID(*uuid)
	if err != nil {
		fatal(err)
	}
	pub, err := parseKey(*pbk)
	if err != nil {
		fatal(err)
	}
	var short [8]byte
	if *sid != "" {
		raw, err := hex.DecodeString(*sid)
		if err != nil || len(raw) > 8 {
			fatal(fmt.Errorf("short id must be hex and at most 8 bytes"))
		}
		copy(short[:], raw)
	}
	cfg := realityConfig{ServerName: *sni, PublicKey: pub, ShortID: short, Fingerprint: *fp}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "reality socks5 %s -> %s sni %s fp %s\n", *listen, *server, *sni, *fp)
	err = serveSOCKS(ln, func(host string, port uint16) (net.Conn, error) {
		raw, err := net.Dial("tcp", *server)
		if err != nil {
			return nil, err
		}
		rc, err := dialREALITY(raw, cfg)
		if err != nil {
			raw.Close()
			return nil, err
		}
		return newVision(rc, id, host, port), nil
	})
	if err != nil {
		fatal(err)
	}
}

func parseUUID(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "")
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 16 {
		return nil, fmt.Errorf("uuid must be 16 bytes")
	}
	return raw, nil
}

func parseKey(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		raw, err := enc.DecodeString(s)
		if err == nil && len(raw) == 32 {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("public key must be 32 bytes of base64")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
