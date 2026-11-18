use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use reality::{parse_key, parse_short_id, serve_listener, spliced_bytes, Config, Endpoint, ReadOut, Tunnel, UdpTunnel};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn against_xray() {
    let xray = "/tmp/xray-bin";
    if !std::path::Path::new(xray).exists() {
        eprintln!("skip: {xray} missing");
        return;
    }
    let dest = Command::new("go")
        .args(["build", "-o", "target/tlsdest", "tests/tlsdest.go"])
        .status()
        .expect("build tls dest");
    assert!(dest.success());
    let mut dest = Command::new("target/tlsdest")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("tls dest");
    let mut out = String::new();
    {
        let stdout = dest.stdout.as_mut().unwrap();
        let mut byte = [0u8; 1];
        while stdout.read(&mut byte).unwrap() == 1 {
            out.push(byte[0] as char);
            if out.lines().count() >= 3 && out.ends_with('\n') {
                break;
            }
        }
    }
    let mut lines = out.lines();
    let http_addr = lines.next().unwrap().to_string();
    let tls_addr = lines.next().unwrap().to_string();
    let raw_tls = lines.next().unwrap().to_string();
    let echo_addr = serve_echo("127.0.0.1:0");
    let echo6_addr = serve_echo("[::1]:0");

    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let private_b64 = URL_SAFE_NO_PAD.encode(secret.to_bytes());
    let public_b64 = URL_SAFE_NO_PAD.encode(public.as_bytes());
    let uuid = "42000000-0000-0000-0000-000000000000";
    let short_hex = "0123456789abcdef";
    let dir = std::env::temp_dir().join(format!("reality-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("xray.log");
    let cfg_path = dir.join("server.json");
    let reality_port = free_port();
    let config = format!(
        r#"{{
            "log": {{"loglevel": "debug", "access": "{log}", "error": "{log}"}},
            "inbounds": [{{
                "listen": "127.0.0.1",
                "port": {port},
                "protocol": "vless",
                "settings": {{"clients": [{{"id": "{uuid}", "flow": "xtls-rprx-vision"}}, {{"id": "{uuid2}", "flow": "xtls-rprx-vision"}}], "decryption": "none"}},
                "streamSettings": {{
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "{tls}",
                        "serverNames": ["www.example.com"],
                        "privateKey": "{private}",
                        "shortIds": ["", "ab", "abcdef", "abcd", "0011223344", "00112233", "001122334455", "00112233445566", "{sid}"]
                    }}
                }}
            }}],
            "outbounds": [{{
                "protocol": "freedom",
                "settings": {{"finalRules": [{{"action": "allow", "ip": ["127.0.0.0/8", "::1/128"]}}]}}
            }}]
        }}"#,
        log = log_path.display(),
        port = reality_port,
        tls = tls_addr,
        private = private_b64,
        sid = short_hex,
        uuid2 = "43000000-0000-0000-0000-000000000000",
    );
    std::fs::write(&cfg_path, config).unwrap();
    let mut xray_proc = Command::new(xray)
        .args(["run", "-c", cfg_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("xray");
    let server = format!("127.0.0.1:{reality_port}");
    let guard = Guard {
        dest: &mut dest,
        xray: &mut xray_proc,
    };
    assert!(wait_port(&server), "xray did not listen\n{}", read_log(&log_path));
    thread::sleep(Duration::from_millis(1500));

    let mut raw_id = [0u8; 16];
    raw_id[0] = 0x42;
    let mut short = [0u8; 8];
    short.copy_from_slice(&hex_decode(short_hex));
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(public.as_bytes());
    let cfg = Config {
        server_name: "www.example.com".into(),
        public_key: pub_bytes,
        short_id: short,
    };
    let _ = public_b64;
    // The router UDP backend must interoperate with a Vision-configured
    // account without treating packet bytes as Vision/TLS records.
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_dest = echo.local_addr().unwrap();
    echo.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    thread::spawn(move || {
        let mut packet = [0u8; 65535];
        while let Ok((n, source)) = echo.recv_from(&mut packet) {
            echo.send_to(&packet[..n], source).unwrap();
        }
    });
    let udp = UdpTunnel::dial(&server, &cfg, raw_id, "127.0.0.1", udp_dest.port()).expect("UDP dial");
    for size in [1, 24, 1200, 4096] {
        let packet: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        udp.send(&packet).expect("UDP send");
        assert_eq!(udp.recv().expect("UDP receive"), packet, "UDP length {size}");
    }
    udp.shutdown();


    let body = http_get(&server, &cfg, raw_id, &http_addr, "/small")
        .unwrap_or_else(|e| panic!("{e}\n{}", read_log(&log_path)));
    assert!(body.contains("small-ok"), "{body}\n{}", read_log(&log_path));

    let big = http_get(&server, &cfg, raw_id, &http_addr, "/big")
        .unwrap_or_else(|e| panic!("{e}\n{}", read_log(&log_path)));
    let big_body = big.split("\r\n\r\n").nth(1).unwrap_or("");
    assert_eq!(big_body.len(), 300000, "header {}", &big[..big.len().min(200)]);
    assert!(big_body.bytes().all(|b| b == b'x'));

    let mut bad = cfg.clone();
    bad.short_id[0] ^= 0xff;
    assert!(Tunnel::dial(&server, &bad, raw_id, "127.0.0.1", 1).is_err());

    let mut wrong = raw_id;
    wrong[0] ^= 0xff;
    let mut conn = Tunnel::dial(&server, &cfg, wrong, &host_of(&http_addr), port_of(&http_addr))
        .expect("bad uuid still finishes the handshake");
    let req = b"GET /small HTTP/1.0\r\nHost: x\r\n\r\n";
    let _ = conn.write_all(req);
    let mut buf = Vec::new();
    let read_result = conn.read_to_end(&mut buf);
    assert!(read_result.is_err() || !String::from_utf8_lossy(&buf).contains("small-ok"));

    let before = spliced_bytes();
    let socks = free_port();
    let listen = format!("127.0.0.1:{socks}");
    let ln = std::net::TcpListener::bind(&listen).unwrap();
    let endpoint = Endpoint {
        server: server.clone(),
        cfg: cfg.clone(),
        uuid: raw_id,
    };
    thread::spawn(move || {
        let _ = serve_listener(ln, endpoint);
    });
    let tls_body = tls_get(&listen, &tls_addr, "/big");
    let tls_payload = tls_body.split("\r\n\r\n").nth(1).unwrap_or("");
    assert_eq!(tls_payload.len(), 300000, "tls head {}", &tls_body[..tls_body.len().min(200)]);
    assert!(tls_payload.bytes().all(|b| b == b'x'));
    let moved = spliced_bytes() - before;
    assert!(moved > 1000, "io_uring splice moved {moved} bytes");

    for sid in ["", "ab", short_hex] {
        let mut cfg = cfg.clone();
        cfg.short_id = parse_short_id(sid).unwrap();
        let body = http_get(&server, &cfg, raw_id, &http_addr, "/small")
            .unwrap_or_else(|e| panic!("sid {sid}: {e}\n{}", read_log(&log_path)));
        assert!(body.contains("small-ok"), "sid {sid}: {body}");
    }

    for encoded in key_encodings(&pub_bytes) {
        let mut cfg = cfg.clone();
        cfg.public_key = parse_key(&encoded).unwrap();
        let body = http_get(&server, &cfg, raw_id, &http_addr, "/small")
            .unwrap_or_else(|e| panic!("key {encoded}: {e}"));
        assert!(body.contains("small-ok"), "{encoded}: {body}");
    }

    let mut bad_name = cfg.clone();
    bad_name.server_name = "not-the-name.test".into();
    assert!(Tunnel::dial(&server, &bad_name, raw_id, "127.0.0.1", 1).is_err());
    let mut bad_key = cfg.clone();
    bad_key.public_key[0] ^= 0xff;
    assert!(Tunnel::dial(&server, &bad_key, raw_id, "127.0.0.1", 1).is_err());

    split_http(&server, &cfg, raw_id, &http_addr).unwrap_or_else(|e| panic!("split: {e}"));

    echo_bytes(&server, &cfg, raw_id, &echo_addr).unwrap_or_else(|e| panic!("bytes: {e}"));
    let large = vec![0x5au8; 180_000];
    let got = echo_exchange(&server, &cfg, raw_id, &echo_addr, &large).unwrap_or_else(|e| panic!("large: {e}"));
    assert_eq!(got, large);
    let mut both = vec![0u8; 65_536];
    rand::RngCore::fill_bytes(&mut OsRng, &mut both);
    let got = echo_exchange(&server, &cfg, raw_id, &echo_addr, &both).unwrap_or_else(|e| panic!("both: {e}"));
    assert_eq!(got, both);

    let mut post = vec![0u8; 100_000];
    rand::RngCore::fill_bytes(&mut OsRng, &mut post);
    let posted = tls_post_direct(&server, &cfg, raw_id, &tls_addr, &post)
        .unwrap_or_else(|e| panic!("post: {e}\n{}", read_log(&log_path)));
    assert!(posted.windows(post.len()).any(|w| w == post), "post echo missing");

    let v4 = host_of(&http_addr);
    let v4_port = port_of(&http_addr);
    let octets: [u8; 4] = v4.parse::<std::net::Ipv4Addr>().unwrap().octets();
    let via_v4 = socks_http(&listen, 1, &octets, v4_port, "/small");
    assert!(via_v4.contains("small-ok"), "{via_v4}");
    assert!(socks_command(&listen, 2).is_err(), "bind was accepted");
    assert!(socks_command(&listen, 3).is_err(), "udp was accepted");

    let ping = echo_exchange(&server, &cfg, raw_id, &echo6_addr, b"ipv6-echo").unwrap_or_else(|e| panic!("v6: {e}"));
    assert_eq!(ping, b"ipv6-echo");
    let v6 = host_of(&echo6_addr).parse::<std::net::Ipv6Addr>().unwrap().octets();
    let via_v6 = socks_payload(&listen, 4, &v6, port_of(&echo6_addr), b"ping");
    assert_eq!(via_v6, b"ping");

    let mut handles = Vec::new();
    for _ in 0..8 {
        let server = server.clone();
        let cfg = cfg.clone();
        let http_addr = http_addr.clone();
        handles.push(thread::spawn(move || http_get(&server, &cfg, raw_id, &http_addr, "/small")));
    }
    for handle in handles {
        let body = handle.join().unwrap().unwrap_or_else(|e| panic!("concurrent: {e}"));
        assert!(body.contains("small-ok"), "{body}");
    }

    let before_post = spliced_bytes();
    let posted = tls_post_socks(&listen, &tls_addr, &post);
    assert!(posted.windows(post.len()).any(|w| w == post.as_slice()), "socks post echo missing");
    assert!(spliced_bytes() > before_post, "upload splice did not run");

    for (n, byte) in [(1usize, 0x21u8), (8191, 0x22), (8192, 0x23), (8193, 0x24), (16384, 0x25), (65535, 0x26)] {
        echo_len(&server, &cfg, raw_id, &echo_addr, n, byte).unwrap_or_else(|e| panic!("boundary: {e}"));
    }
    echo_len(&server, &cfg, raw_id, &echo_addr, 1_000_000, 0x27).unwrap_or_else(|e| panic!("megabyte: {e}"));
    echo_twice(&server, &cfg, raw_id, &echo_addr).unwrap_or_else(|e| panic!("twice: {e}"));
    opaque_shapes(&server, &cfg, raw_id, &echo_addr).unwrap_or_else(|e| panic!("opaque: {e}"));
    drip_http(&server, &cfg, raw_id, &http_addr).unwrap_or_else(|e| panic!("drip http: {e}"));

    let mut raw_id2 = [0u8; 16];
    raw_id2[0] = 0x43;
    let second = http_get(&server, &cfg, raw_id2, &http_addr, "/small").unwrap_or_else(|e| panic!("uuid2: {e}"));
    assert!(second.contains("small-ok"), "{second}");
    for sid in ["abcdef", "abcd", "0011223344", "00112233", "001122334455", "00112233445566"] {
        let mut cfg = cfg.clone();
        cfg.short_id = parse_short_id(sid).unwrap();
        let body = http_get(&server, &cfg, raw_id, &http_addr, "/small").unwrap_or_else(|e| panic!("sid {sid}: {e}"));
        assert!(body.contains("small-ok"), "sid {sid}: {body}");
    }

    for chunk in [1usize, 7] {
        let drip = serve_drip(&server, chunk);
        let body = http_get(&drip, &cfg, raw_id, &http_addr, "/small").unwrap_or_else(|e| panic!("segment {chunk}: {e}"));
        assert!(body.contains("small-ok"), "segment {chunk}: {body}");
    }
    let drip = serve_drip(&server, 3);
    echo_len(&drip, &cfg, raw_id, &echo_addr, 2048, 0x3c).unwrap_or_else(|e| panic!("segment echo: {e}"));

    let domain = host_of(&echo_addr);
    let via_domain = socks_payload(
        &listen,
        3,
        &[&[domain.len() as u8], domain.as_bytes()].concat(),
        port_of(&echo_addr),
        b"domain-echo",
    );
    assert_eq!(via_domain, b"domain-echo");

    let echoed = socks_half_close(&listen, 1, &octets, port_of(&echo_addr), b"half-close-echo");
    assert_eq!(echoed, b"half-close-echo");
    let dripped = socks_byte_upload(&listen, 1, &octets, port_of(&echo_addr), &vec![0x44; 300]);
    assert_eq!(dripped, vec![0x44; 300]);

    socks_garbage(&listen);
    let after_garbage = socks_http(&listen, 1, &octets, v4_port, "/small");
    assert!(after_garbage.contains("small-ok"), "{after_garbage}");
    for _ in 0..20 {
        let body = socks_http(&listen, 1, &octets, v4_port, "/small");
        assert!(body.contains("small-ok"), "{body}");
    }

    let before_many = spliced_bytes();
    let mut downloads = Vec::new();
    for _ in 0..4 {
        let listen = listen.clone();
        let tls_addr = tls_addr.clone();
        downloads.push(thread::spawn(move || tls_get(&listen, &tls_addr, "/big")));
    }
    for handle in downloads {
        let body = handle.join().unwrap();
        let payload = body.split("\r\n\r\n").nth(1).unwrap_or("");
        assert_eq!(payload.len(), 300000);
        assert!(payload.bytes().all(|b| b == b'x'));
    }
    let many = spliced_bytes() - before_many;
    // Integrity is checked for every transfer above. The TLS/Vision boundary
    // and thread scheduling determine how many bytes are still left for the
    // raw fast path; a fixed percentage of the 1.2 MB is not an invariant.
    assert!(many > 1000, "concurrent splice made no bulk progress: {many} bytes");

    echo_len(&server, &cfg, raw_id, &echo6_addr, 256 * 1024, 0x61).unwrap_or_else(|e| panic!("v6 bulk: {e}"));
    http11_twice(&server, &cfg, raw_id, &http_addr).unwrap_or_else(|e| panic!("keep-alive: {e}"));
    tls_twice_direct(&server, &cfg, raw_id, &tls_addr).unwrap_or_else(|e| panic!("tls keep-alive: {e}"));
    tls_twice_socks(&listen, &tls_addr).unwrap_or_else(|e| panic!("socks tls keep-alive: {e}"));

    let duplex_addr = serve_duplex();
    duplex_tunnel(&server, &cfg, raw_id, &duplex_addr, 2_000_000).unwrap_or_else(|e| panic!("duplex: {e}"));
    let dup_octets = host_of(&duplex_addr).parse::<std::net::Ipv4Addr>().unwrap().octets();
    socks_duplex(&listen, &dup_octets, port_of(&duplex_addr), 2_000_000);

    let slow = socks_slow_handshake(&listen, &octets, port_of(&echo_addr));
    assert_eq!(slow, b"slow-hs");
    let piped = socks_pipelined(&listen, &octets, port_of(&echo_addr));
    assert_eq!(piped, b"piped");

    socks_dead_dest(&listen);
    let after_dead = socks_http(&listen, 1, &octets, v4_port, "/small");
    assert!(after_dead.contains("small-ok"), "{after_dead}");

    tls_abort(&listen, &tls_addr);
    let recovered = tls_get(&listen, &tls_addr, "/big");
    let recovered_body = recovered.split("\r\n\r\n").nth(1).unwrap_or("");
    assert_eq!(recovered_body.len(), 300000);
    assert!(recovered_body.bytes().all(|b| b == b'x'));

    for n in [0usize, 16384, 16385] {
        let body = vec![0x5c; n];
        let posted = tls_post_direct(&server, &cfg, raw_id, &tls_addr, &body)
            .unwrap_or_else(|e| panic!("post {n}: {e}"));
        assert_eq!(http_body(&posted), body.as_slice(), "post {n}");
    }
    let before_boundary = spliced_bytes();
    let boundary = vec![0x5d; 16384];
    let posted = tls_post_socks(&listen, &tls_addr, &boundary);
    assert_eq!(http_body(&posted), boundary.as_slice());
    assert!(spliced_bytes() > before_boundary, "record-sized post did not splice");

    let mut crowd = Vec::new();
    for _ in 0..32 {
        let server = server.clone();
        let cfg = cfg.clone();
        let http_addr = http_addr.clone();
        crowd.push(thread::spawn(move || http_get(&server, &cfg, raw_id, &http_addr, "/small")));
    }
    for handle in crowd {
        let body = handle.join().unwrap().unwrap_or_else(|e| panic!("crowd: {e}"));
        assert!(body.contains("small-ok"), "{body}");
    }

    echo_len(&server, &cfg, raw_id, &echo_addr, 65536, 0x29).unwrap_or_else(|e| panic!("65536: {e}"));
    echo_len(&server, &cfg, raw_id, &echo_addr, 100_000, 0).unwrap_or_else(|e| panic!("zeros: {e}"));
    let mut lead = vec![0u8; 64];
    lead.extend(std::iter::repeat(0x7f).take(1000));
    let got = echo_exchange(&server, &cfg, raw_id, &echo_addr, &lead).unwrap_or_else(|e| panic!("lead zero: {e}"));
    assert_eq!(got, lead);
    let mut tail = vec![0x7f; 1000];
    tail.extend(std::iter::repeat(0u8).take(64));
    let got = echo_exchange(&server, &cfg, raw_id, &echo_addr, &tail).unwrap_or_else(|e| panic!("tail zero: {e}"));
    assert_eq!(got, tail);
    let zeros = socks_payload(&listen, 1, &octets, port_of(&echo_addr), &vec![0u8; 10_000]);
    assert_eq!(zeros, vec![0u8; 10_000]);

    for chunk in [5usize, 20, 21, 22] {
        let drip = serve_drip(&server, chunk);
        let body = http_get(&drip, &cfg, raw_id, &http_addr, "/small").unwrap_or_else(|e| panic!("segment {chunk}: {e}"));
        assert!(body.contains("small-ok"), "segment {chunk}: {body}");
    }

    let banner_addr = serve_banner();
    read_banner(&server, &cfg, raw_id, &banner_addr).unwrap_or_else(|e| panic!("banner: {e}"));
    ping_pong(&server, &cfg, raw_id, &echo_addr, 200).unwrap_or_else(|e| panic!("ping-pong: {e}"));

    let hold_addr = serve_hold();
    let hold_octets = host_of(&hold_addr).parse::<std::net::Ipv4Addr>().unwrap().octets();
    socks_hold(&listen, &hold_octets, port_of(&hold_addr));
    socks_idle_gap(&listen, &octets, port_of(&echo_addr));
    socks_record_shapes(&listen, &octets, port_of(&echo_addr));

    let before_keep = spliced_bytes();
    tls_big_twice(&listen, &tls_addr).unwrap_or_else(|e| panic!("two big: {e}"));
    let kept = spliced_bytes() - before_keep;
    assert!(kept > 400_000, "keep-alive splice moved {kept} bytes");

    let down_addr = serve_asym(1_000_000, 0xA1, 4096);
    let down_octets = host_of(&down_addr).parse::<std::net::Ipv4Addr>().unwrap().octets();
    socks_asym(&listen, &down_octets, port_of(&down_addr), &vec![0xB2; 4096], 1_000_000, 0xA1);
    let up_addr = serve_asym(4096, 0xA3, 1_000_000);
    let up_octets = host_of(&up_addr).parse::<std::net::Ipv4Addr>().unwrap().octets();
    socks_asym(&listen, &up_octets, port_of(&up_addr), &vec![0xB4; 1_000_000], 4096, 0xA3);

    let mut unique = Vec::new();
    for i in 0..8u8 {
        let server = server.clone();
        let cfg = cfg.clone();
        let echo_addr = echo_addr.clone();
        unique.push(thread::spawn(move || {
            let payload = vec![i.wrapping_add(1); 50_000];
            echo_exchange(&server, &cfg, raw_id, &echo_addr, &payload).map(|got| got == payload)
        }));
    }
    for (i, handle) in unique.into_iter().enumerate() {
        assert!(handle.join().unwrap().unwrap_or(false), "cross-talk {i}");
    }

    let before_tls = spliced_bytes();
    socks_tls_duplex(&listen, &raw_tls, 512 * 1024);
    let both = spliced_bytes() - before_tls;
    assert!(both > 700_000, "tls duplex splice moved {both} bytes");

    tls_abort_after_splice(&listen, &tls_addr);
    let after_abort = tls_get(&listen, &tls_addr, "/big");
    let after_body = after_abort.split("\r\n\r\n").nth(1).unwrap_or("");
    assert_eq!(after_body.len(), 300000);

    socks_bad_target(&listen, &[]);
    socks_bad_target(&listen, b"no-such-host.invalid");
    let after_bad = socks_http(&listen, 1, &octets, v4_port, "/small");
    assert!(after_bad.contains("small-ok"), "{after_bad}");

    let mut upper = cfg.clone();
    upper.server_name = "WWW.EXAMPLE.COM".into();
    assert!(Tunnel::dial(&server, &upper, raw_id, "127.0.0.1", 1).is_err(), "uppercase sni");
    let mut dotted = cfg.clone();
    dotted.server_name = "www.example.com.".into();
    assert!(Tunnel::dial(&server, &dotted, raw_id, "127.0.0.1", 1).is_err(), "trailing dot sni");

    let still = http_get(&server, &cfg, raw_id, &http_addr, "/small").unwrap_or_else(|e| panic!("still: {e}"));
    assert!(still.contains("small-ok"), "{still}");
    let log = read_log(&log_path);
    assert!(!log.to_ascii_lowercase().contains("panic"), "{log}");
    drop(guard);
}

struct Guard<'a> {
    dest: &'a mut Child,
    xray: &'a mut Child,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let _ = self.dest.kill();
        let _ = self.xray.kill();
        let _ = self.dest.wait();
        let _ = self.xray.wait();
    }
}

fn http_get(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str, path: &str) -> Result<String, String> {
    let mut conn = Tunnel::dial(server, cfg, uuid, &host_of(origin), port_of(origin)).map_err(|e| e.to_string())?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {origin}\r\nConnection: close\r\n\r\n");
    conn.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn tls_get(proxy: &str, origin: &str, path: &str) -> String {
    let mut sock = TcpStream::connect(proxy).expect("socks");
    sock.write_all(&[5, 1, 0]).unwrap();
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).unwrap();
    assert_eq!(greet, [5, 0]);
    let host = host_of(origin);
    let port = port_of(origin);
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    sock.write_all(&req).unwrap();
    let mut head = [0u8; 4];
    sock.read_exact(&mut head).unwrap();
    assert_eq!(head[1], 0, "socks connect failed {}", head[1]);
    let rest = match head[3] {
        1 => 6,
        4 => 18,
        3 => {
            let mut n = [0u8; 1];
            sock.read_exact(&mut n).unwrap();
            n[0] as usize + 2
        }
        _ => 0,
    };
    let mut skip = vec![0u8; rest];
    sock.read_exact(&mut skip).unwrap();

    let tls_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let name = ServerName::try_from("example.com").unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(tls_cfg), name).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, sock);
    let req = format!("GET {path} HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

fn host_of(addr: &str) -> String {
    let (host, _) = split_host(addr);
    host.trim_matches(|c| c == '[' || c == ']').to_string()
}

fn port_of(addr: &str) -> u16 {
    let (_, port) = split_host(addr);
    port
}

fn split_host(addr: &str) -> (String, u16) {
    if let Some((host, port)) = addr.rsplit_once(':') {
        return (host.to_string(), port.parse().unwrap_or(80));
    }
    (addr.to_string(), 80)
}

fn free_port() -> u16 {
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    ln.local_addr().unwrap().port()
}

fn wait_port(addr: &str) -> bool {
    for _ in 0..50 {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn read_log(path: &std::path::Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let start = text.len().saturating_sub(2500);
    text[start..].to_string()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn key_encodings(raw: &[u8]) -> [String; 4] {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    [
        URL_SAFE_NO_PAD.encode(raw),
        URL_SAFE.encode(raw),
        STANDARD_NO_PAD.encode(raw),
        STANDARD.encode(raw),
    ]
}

fn serve_echo(addr: &str) -> String {
    let ln = std::net::TcpListener::bind(addr).unwrap_or_else(|e| panic!("echo {addr}: {e}"));
    let local = ln.local_addr().unwrap().to_string();
    thread::spawn(move || {
        for conn in ln.incoming().flatten() {
            thread::spawn(move || {
                let mut conn = conn;
                let mut buf = [0u8; 32 * 1024];
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    local
}

fn dial_to(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str) -> Tunnel {
    let conn = Tunnel::dial(server, cfg, uuid, &host_of(origin), port_of(origin)).expect("dial");
    conn.set_timeout(Some(Duration::from_secs(15))).expect("timeout");
    conn
}

fn read_n(conn: &Tunnel, n: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; n];
    let mut off = 0;
    while off < n {
        match conn.read_some(&mut out[off..]).map_err(|e| e.to_string())? {
            ReadOut::Data(0) => return Err("empty read".into()),
            ReadOut::Data(k) => off += k,
            ReadOut::Eof => return Err(format!("eof at {off}/{n}")),
            ReadOut::Splice => return Err("unexpected splice on a direct tunnel".into()),
        }
    }
    Ok(out)
}

fn split_http(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str) -> Result<(), String> {
    let conn = dial_to(server, cfg, uuid, origin);
    conn.write_all_chunks(&[]).map_err(|e| e.to_string())?;
    conn.write_all_chunks(b"GET /small HTTP/1.0\r\n").map_err(|e| e.to_string())?;
    conn.write_all_chunks(b"Host: x\r\nConnection: close\r\n\r\n").map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    loop {
        let mut tmp = [0u8; 4096];
        match conn.read_some(&mut tmp).map_err(|e| e.to_string())? {
            ReadOut::Data(0) => continue,
            ReadOut::Data(n) => buf.extend_from_slice(&tmp[..n]),
            ReadOut::Eof | ReadOut::Splice => break,
        }
        if buf.windows(8).any(|w| w == b"small-ok") {
            return Ok(());
        }
    }
    Err(format!("split body {}", String::from_utf8_lossy(&buf)))
}

fn echo_bytes(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str) -> Result<(), String> {
    let conn = dial_to(server, cfg, uuid, origin);
    let mut one = Vec::new();
    for i in 0..32u8 {
        conn.write_all_chunks(&[i]).map_err(|e| e.to_string())?;
        one.push(i);
    }
    let got = read_n(&conn, one.len())?;
    if got != one {
        return Err(format!("byte echo {got:02x?}"));
    }
    let bulk = vec![0x11u8; 100_000];
    conn.write_all_chunks(&bulk).map_err(|e| e.to_string())?;
    let got = read_n(&conn, bulk.len())?;
    if got != bulk {
        return Err(format!("bulk {}", got.len()));
    }
    Ok(())
}

fn echo_exchange(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    let conn = dial_to(server, cfg, uuid, origin);
    thread::scope(|scope| {
        let write = scope.spawn(|| conn.write_all_chunks(payload).map_err(|e| e.to_string()));
        let got = read_n(&conn, payload.len());
        write.join().unwrap()?;
        got
    })
}

fn tls_post_direct(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str, post: &[u8]) -> Result<Vec<u8>, String> {
    let conn = dial_to(server, cfg, uuid, origin);
    let mut tls = rustls_on(conn);
    let req = format!(
        "POST / HTTP/1.0\r\nHost: example.com\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        post.len()
    );
    tls.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    tls.write_all(post).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn rustls_on<S: Read + Write>(sock: S) -> rustls::StreamOwned<rustls::ClientConnection, S> {
    let tls_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let name = ServerName::try_from("example.com").unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(tls_cfg), name).unwrap();
    rustls::StreamOwned::new(conn, sock)
}

fn socks_connect(proxy: &str, atyp: u8, addr: &[u8], port: u16) -> TcpStream {
    let mut sock = TcpStream::connect(proxy).expect("socks");
    sock.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
    sock.write_all(&[5, 1, 0]).unwrap();
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).unwrap();
    assert_eq!(greet, [5, 0]);
    let mut req = vec![5, 1, 0, atyp];
    req.extend_from_slice(addr);
    req.extend_from_slice(&port.to_be_bytes());
    sock.write_all(&req).unwrap();
    let mut head = [0u8; 4];
    sock.read_exact(&mut head).unwrap();
    assert_eq!(head[1], 0, "socks connect failed {}", head[1]);
    let rest = match head[3] {
        1 => 6,
        4 => 18,
        3 => {
            let mut n = [0u8; 1];
            sock.read_exact(&mut n).unwrap();
            n[0] as usize + 2
        }
        _ => 0,
    };
    let mut skip = vec![0u8; rest];
    sock.read_exact(&mut skip).unwrap();
    sock
}

fn socks_http(proxy: &str, atyp: u8, addr: &[u8], port: u16, path: &str) -> String {
    let mut sock = socks_connect(proxy, atyp, addr, port);
    let req = format!("GET {path} HTTP/1.0\r\nHost: x\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

fn socks_payload(proxy: &str, atyp: u8, addr: &[u8], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut sock = socks_connect(proxy, atyp, addr, port);
    sock.write_all(payload).unwrap();
    let mut buf = vec![0u8; payload.len()];
    sock.read_exact(&mut buf).unwrap();
    buf
}

fn socks_command(proxy: &str, cmd: u8) -> Result<(), String> {
    let mut sock = TcpStream::connect(proxy).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
    sock.write_all(&[5, 1, 0]).map_err(|e| e.to_string())?;
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).map_err(|e| e.to_string())?;
    sock.write_all(&[5, cmd, 0, 1, 127, 0, 0, 1, 0, 80]).map_err(|e| e.to_string())?;
    let mut head = [0u8; 4];
    sock.read_exact(&mut head).map_err(|e| e.to_string())?;
    if head[1] == 0 {
        Ok(())
    } else {
        Err(format!("rejected {}", head[1]))
    }
}

fn tls_post_socks(proxy: &str, origin: &str, post: &[u8]) -> Vec<u8> {
    let host = host_of(origin);
    let sock = socks_connect(proxy, 3, &[&[host.len() as u8], host.as_bytes()].concat(), port_of(origin));
    let mut tls = rustls_on(sock);
    let req = format!(
        "POST / HTTP/1.0\r\nHost: example.com\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        post.len()
    );
    tls.write_all(req.as_bytes()).unwrap();
    tls.write_all(post).unwrap();
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).unwrap();
    buf
}

fn echo_len(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str, n: usize, byte: u8) -> Result<(), String> {
    let payload = vec![byte; n];
    let got = echo_exchange(server, cfg, uuid, origin, &payload)?;
    if got != payload {
        return Err(format!("{n} bytes came back as {}", got.len()));
    }
    Ok(())
}

fn echo_twice(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str) -> Result<(), String> {
    let conn = dial_to(server, cfg, uuid, origin);
    for (n, byte) in [(100usize, 0x11u8), (9000, 0x22)] {
        let payload = vec![byte; n];
        conn.write_all_chunks(&payload).map_err(|e| e.to_string())?;
        let got = read_n(&conn, n)?;
        if got != payload {
            return Err(format!("second exchange {n}"));
        }
    }
    Ok(())
}

fn opaque_shapes(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str) -> Result<(), String> {
    let conn = dial_to(server, cfg, uuid, origin);
    let mut hello = vec![0x5a; 64];
    hello[..6].copy_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x3b, 0x01]);
    let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x20];
    record.extend(std::iter::repeat(0x11).take(32));
    let tail = vec![0x7e; 100];
    for part in [&hello, &record, &tail] {
        conn.write_all_chunks(part).map_err(|e| e.to_string())?;
        let got = read_n(&conn, part.len())?;
        if got != *part {
            return Err(format!("opaque {} bytes diverged", part.len()));
        }
    }
    Ok(())
}

fn drip_http(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str) -> Result<(), String> {
    let conn = dial_to(server, cfg, uuid, origin);
    let req = b"GET /small HTTP/1.0\r\nHost: x\r\nConnection: close\r\n\r\n";
    for byte in req {
        conn.write_all_chunks(&[*byte]).map_err(|e| e.to_string())?;
    }
    let mut buf = Vec::new();
    loop {
        let mut tmp = [0u8; 4096];
        match conn.read_some(&mut tmp).map_err(|e| e.to_string())? {
            ReadOut::Data(0) => continue,
            ReadOut::Data(n) => buf.extend_from_slice(&tmp[..n]),
            ReadOut::Eof | ReadOut::Splice => break,
        }
        if buf.windows(8).any(|w| w == b"small-ok") {
            return Ok(());
        }
    }
    Err(format!("drip body {}", String::from_utf8_lossy(&buf)))
}

fn serve_drip(upstream: &str, chunk: usize) -> String {
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local = ln.local_addr().unwrap().to_string();
    let upstream = upstream.to_string();
    thread::spawn(move || {
        for conn in ln.incoming().flatten() {
            let upstream = upstream.clone();
            thread::spawn(move || {
                let mut up = match TcpStream::connect(&upstream) {
                    Ok(up) => up,
                    Err(_) => return,
                };
                let _ = up.set_nodelay(true);
                let _ = conn.set_nodelay(true);
                let mut up_read = up.try_clone().unwrap();
                let mut down_write = conn.try_clone().unwrap();
                thread::spawn(move || copy_chunks(&mut up_read, &mut down_write, chunk));
                copy_chunks(&mut { conn }, &mut up, chunk);
            });
        }
    });
    local
}

fn copy_chunks(from: &mut TcpStream, to: &mut TcpStream, chunk: usize) {
    let mut buf = vec![0u8; chunk.max(1)];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => {
                let _ = to.shutdown(Shutdown::Write);
                break;
            }
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

fn socks_half_close(proxy: &str, atyp: u8, addr: &[u8], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut sock = socks_connect(proxy, atyp, addr, port);
    sock.write_all(payload).unwrap();
    sock.shutdown(Shutdown::Write).unwrap();
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).unwrap();
    buf
}

fn socks_byte_upload(proxy: &str, atyp: u8, addr: &[u8], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut sock = socks_connect(proxy, atyp, addr, port);
    for byte in payload {
        sock.write_all(&[*byte]).unwrap();
    }
    let mut buf = vec![0u8; payload.len()];
    sock.read_exact(&mut buf).unwrap();
    buf
}

fn socks_garbage(proxy: &str) {
    if let Ok(mut sock) = TcpStream::connect(proxy) {
        sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let _ = sock.write_all(&[0, 1, 2, 3, 4]);
        let mut buf = [0u8; 8];
        let _ = sock.read(&mut buf);
    }
}

struct HttpBuf<S> {
    sock: S,
    buf: Vec<u8>,
}

impl<S: Read> HttpBuf<S> {
    fn read_response(&mut self) -> Result<Vec<u8>, String> {
        let header_end = self.fill_until(|buf| buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4))?;
        let header = String::from_utf8_lossy(&self.buf[..header_end]).to_ascii_lowercase();
        let chunked = header.split("\r\n").any(|line| {
            line.strip_prefix("transfer-encoding:")
                .is_some_and(|value| value.contains("chunked"))
        });
        if chunked {
            self.buf.drain(..header_end);
            return self.read_chunks();
        }
        let len = content_length(&header)?;
        self.fill_exact(header_end + len)?;
        let body = self.buf[header_end..header_end + len].to_vec();
        self.buf.drain(..header_end + len);
        Ok(body)
    }

    fn read_chunks(&mut self) -> Result<Vec<u8>, String> {
        let mut body = Vec::new();
        loop {
            let line = self.read_line()?;
            let size_hex = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_hex, 16).map_err(|_| format!("chunk {line}"))?;
            if size == 0 {
                loop {
                    if self.read_line()?.is_empty() {
                        break;
                    }
                }
                return Ok(body);
            }
            self.fill_exact(size + 2)?;
            body.extend_from_slice(&self.buf[..size]);
            if &self.buf[size..size + 2] != b"\r\n" {
                return Err("chunk missing crlf".into());
            }
            self.buf.drain(..size + 2);
        }
    }

    fn read_line(&mut self) -> Result<String, String> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line = String::from_utf8_lossy(&self.buf[..i]).into_owned();
                self.buf.drain(..i + 2);
                return Ok(line);
            }
            self.pull()?;
        }
    }

    fn fill_exact(&mut self, n: usize) -> Result<(), String> {
        while self.buf.len() < n {
            self.pull()?;
        }
        Ok(())
    }

    fn fill_until(&mut self, mut done: impl FnMut(&[u8]) -> Option<usize>) -> Result<usize, String> {
        loop {
            if let Some(n) = done(&self.buf) {
                return Ok(n);
            }
            self.pull()?;
        }
    }

    fn pull(&mut self) -> Result<(), String> {
        let mut tmp = [0u8; 8192];
        let n = self.sock.read(&mut tmp).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err(format!("eof with {} bytes buffered", self.buf.len()));
        }
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(())
    }
}

fn http_body(msg: &[u8]) -> &[u8] {
    let i = msg
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no http header in {} bytes", msg.len()));
    &msg[i + 4..]
}

fn content_length(header: &str) -> Result<usize, String> {
    for line in header.split("\r\n") {
        if let Some(rest) = line.strip_prefix("content-length:") {
            return rest.trim().parse().map_err(|_| format!("bad length in {header}"));
        }
    }
    Err(format!("no content-length in {header}"))
}

fn http11_twice(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str) -> Result<(), String> {
    let conn = dial_to(server, cfg, uuid, origin);
    let mut http = HttpBuf { sock: conn, buf: Vec::new() };
    for _ in 0..2 {
        http.sock
            .write_all(b"GET /small HTTP/1.1\r\nHost: x\r\n\r\n")
            .map_err(|e| e.to_string())?;
        let body = http.read_response()?;
        if body != b"small-ok" {
            return Err(format!("keep-alive body {}", String::from_utf8_lossy(&body)));
        }
    }
    Ok(())
}

fn tls_twice_direct(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str) -> Result<(), String> {
    let conn = dial_to(server, cfg, uuid, origin);
    let tls = rustls_on(conn);
    two_gets(tls)
}

fn tls_twice_socks(proxy: &str, origin: &str) -> Result<(), String> {
    let host = host_of(origin);
    let sock = socks_connect(proxy, 3, &[&[host.len() as u8], host.as_bytes()].concat(), port_of(origin));
    two_gets(rustls_on(sock))
}

fn two_gets<S: Read + Write>(sock: S) -> Result<(), String> {
    let mut http = HttpBuf { sock, buf: Vec::new() };
    for _ in 0..2 {
        http.sock
            .write_all(b"GET /small HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .map_err(|e| e.to_string())?;
        let body = http.read_response()?;
        if body != b"small-ok" {
            return Err(format!("tls keep-alive {}", String::from_utf8_lossy(&body)));
        }
    }
    Ok(())
}

fn serve_duplex() -> String {
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local = ln.local_addr().unwrap().to_string();
    thread::spawn(move || {
        for conn in ln.incoming().flatten() {
            thread::spawn(move || duplex_peer(conn));
        }
    });
    local
}

fn duplex_peer(conn: TcpStream) {
    let _ = conn.set_nodelay(true);
    let mut writer = conn.try_clone().unwrap();
    let mut reader = conn;
    let n = 2_000_000usize;
    thread::spawn(move || {
        let buf = vec![0xA1u8; 64 * 1024];
        let mut left = n;
        while left > 0 {
            let k = left.min(buf.len());
            if writer.write_all(&buf[..k]).is_err() {
                break;
            }
            left -= k;
        }
    });
    let mut got = vec![0u8; n];
    let _ = reader.read_exact(&mut got);
}

fn duplex_tunnel(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str, n: usize) -> Result<(), String> {
    let conn = dial_to(server, cfg, uuid, origin);
    conn.set_timeout(Some(Duration::from_secs(20))).map_err(|e| e.to_string())?;
    thread::scope(|scope| {
        let write = scope.spawn(|| {
            let buf = vec![0xB2u8; 64 * 1024];
            let mut left = n;
            while left > 0 {
                let k = left.min(buf.len());
                conn.write_all_chunks(&buf[..k]).map_err(|e| e.to_string())?;
                left -= k;
            }
            Ok::<(), String>(())
        });
        let got = read_n(&conn, n)?;
        write.join().unwrap()?;
        if got.iter().any(|b| *b != 0xA1) {
            return Err(format!("duplex got {} bytes", got.len()));
        }
        Ok(())
    })
}

fn socks_duplex(proxy: &str, addr: &[u8], port: u16, n: usize) {
    let mut sock = socks_connect(proxy, 1, addr, port);
    sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut reader = sock.try_clone().unwrap();
    thread::scope(|scope| {
        scope.spawn(|| {
            let buf = vec![0xB2u8; 64 * 1024];
            let mut left = n;
            while left > 0 {
                let k = left.min(buf.len());
                sock.write_all(&buf[..k]).unwrap();
                left -= k;
            }
        });
        let mut got = vec![0u8; n];
        reader.read_exact(&mut got).unwrap();
        assert!(got.iter().all(|b| *b == 0xA1), "socks duplex corrupted");
    });
}

fn socks_slow_handshake(proxy: &str, addr: &[u8], port: u16) -> Vec<u8> {
    let mut sock = TcpStream::connect(proxy).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
    for byte in [5u8, 2, 0, 2] {
        sock.write_all(&[byte]).unwrap();
    }
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).unwrap();
    assert_eq!(greet, [5, 0]);
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(addr);
    req.extend_from_slice(&port.to_be_bytes());
    for byte in req {
        sock.write_all(&[byte]).unwrap();
    }
    finish_socks(&mut sock);
    sock.write_all(b"slow-hs").unwrap();
    let mut buf = [0u8; 7];
    sock.read_exact(&mut buf).unwrap();
    buf.to_vec()
}

fn socks_pipelined(proxy: &str, addr: &[u8], port: u16) -> Vec<u8> {
    let mut sock = TcpStream::connect(proxy).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
    let mut req = vec![5, 1, 0, 5, 1, 0, 1];
    req.extend_from_slice(addr);
    req.extend_from_slice(&port.to_be_bytes());
    sock.write_all(&req).unwrap();
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).unwrap();
    assert_eq!(greet, [5, 0]);
    finish_socks(&mut sock);
    sock.write_all(b"piped").unwrap();
    let mut buf = [0u8; 5];
    sock.read_exact(&mut buf).unwrap();
    buf.to_vec()
}

fn finish_socks(sock: &mut TcpStream) {
    let mut head = [0u8; 4];
    sock.read_exact(&mut head).unwrap();
    assert_eq!(head[1], 0, "socks connect failed {}", head[1]);
    let rest = match head[3] {
        1 => 6,
        4 => 18,
        _ => 0,
    };
    let mut skip = vec![0u8; rest];
    sock.read_exact(&mut skip).unwrap();
}

fn socks_dead_dest(proxy: &str) {
    let mut sock = socks_connect(proxy, 1, &[127, 0, 0, 1], 1);
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    sock.write_all(b"x").unwrap();
    let started = std::time::Instant::now();
    let mut buf = [0u8; 64];
    let result = sock.read(&mut buf);
    assert!(started.elapsed() < Duration::from_secs(3), "dead dest hung");
    match result {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("dead dest returned {n} bytes: {:02x?}", &buf[..n]),
    }
}

fn tls_abort(proxy: &str, origin: &str) {
    let host = host_of(origin);
    let sock = socks_connect(proxy, 3, &[&[host.len() as u8], host.as_bytes()].concat(), port_of(origin));
    let mut tls = rustls_on(sock);
    tls.write_all(b"GET /big HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = [0u8; 1024];
    assert!(tls.read(&mut buf).unwrap() > 0);
}

fn serve_banner() -> String {
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local = ln.local_addr().unwrap().to_string();
    thread::spawn(move || {
        for conn in ln.incoming().flatten() {
            thread::spawn(move || {
                let mut conn = conn;
                if conn.write_all(b"BANNER!").is_err() {
                    return;
                }
                let mut buf = [0u8; 1024];
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    local
}

fn read_banner(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str) -> Result<(), String> {
    let conn = dial_to(server, cfg, uuid, origin);
    let got = read_n(&conn, b"BANNER!".len())?;
    if got != b"BANNER!" {
        return Err(format!("banner {}", String::from_utf8_lossy(&got)));
    }
    conn.write_all_chunks(b"ping").map_err(|e| e.to_string())?;
    let got = read_n(&conn, 4)?;
    if got != b"ping" {
        return Err(format!("after banner {}", String::from_utf8_lossy(&got)));
    }
    Ok(())
}

fn ping_pong(server: &str, cfg: &Config, uuid: [u8; 16], origin: &str, rounds: u16) -> Result<(), String> {
    let conn = dial_to(server, cfg, uuid, origin);
    for i in 0..rounds {
        let byte = [(i & 0xff) as u8];
        conn.write_all_chunks(&byte).map_err(|e| e.to_string())?;
        let got = read_n(&conn, 1)?;
        if got != byte {
            return Err(format!("round {i} got {got:02x?}"));
        }
    }
    Ok(())
}

fn serve_hold() -> String {
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local = ln.local_addr().unwrap().to_string();
    thread::spawn(move || {
        for conn in ln.incoming().flatten() {
            thread::spawn(move || {
                let mut conn = conn;
                let mut buf = [0u8; 64];
                if conn.read_exact(&mut buf).is_err() {
                    return;
                }
                thread::sleep(Duration::from_secs(2));
                let _ = conn.write_all(&buf);
            });
        }
    });
    local
}

fn socks_hold(proxy: &str, addr: &[u8], port: u16) {
    let mut sock = socks_connect(proxy, 1, addr, port);
    let payload = vec![0x42u8; 64];
    let started = std::time::Instant::now();
    sock.write_all(&payload).unwrap();
    let mut got = vec![0u8; payload.len()];
    sock.read_exact(&mut got).unwrap();
    assert_eq!(got, payload);
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(2), "hold returned in {elapsed:?}");
    assert!(elapsed < Duration::from_secs(8), "hold took {elapsed:?}");
}

fn socks_idle_gap(proxy: &str, addr: &[u8], port: u16) {
    let mut sock = socks_connect(proxy, 1, addr, port);
    sock.write_all(b"abc").unwrap();
    thread::sleep(Duration::from_secs(2));
    sock.write_all(b"def").unwrap();
    let mut buf = [0u8; 6];
    sock.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"abcdef");
}

fn socks_record_shapes(proxy: &str, addr: &[u8], port: u16) {
    let mut two = vec![0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb];
    two.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x02, 0xcc, 0xdd]);
    two.extend_from_slice(b"END");
    assert_eq!(socks_payload(proxy, 1, addr, port, &two), two);

    let mut empty = vec![0x17, 0x03, 0x03, 0x00, 0x00];
    empty.extend_from_slice(b"AFTER");
    assert_eq!(socks_payload(proxy, 1, addr, port, &empty), empty);

    let mut prefixed = b"HEAD".to_vec();
    prefixed.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xff]);
    assert_eq!(socks_payload(proxy, 1, addr, port, &prefixed), prefixed);

    let mut sock = socks_connect(proxy, 1, addr, port);
    let first = [0x17u8, 0x03, 0x03, 0x00, 0x05, 0x01];
    let second = [0x02u8, 0x03, 0x04, 0x05];
    sock.write_all(&first).unwrap();
    sock.write_all(&second).unwrap();
    sock.write_all(b"TAIL").unwrap();
    let mut got = [0u8; 14];
    sock.read_exact(&mut got).unwrap();
    let mut expect = first.to_vec();
    expect.extend_from_slice(&second);
    expect.extend_from_slice(b"TAIL");
    assert_eq!(got.as_slice(), expect.as_slice());
}

fn serve_asym(out_n: usize, out_byte: u8, in_n: usize) -> String {
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local = ln.local_addr().unwrap().to_string();
    thread::spawn(move || {
        for conn in ln.incoming().flatten() {
            thread::spawn(move || {
                let _ = conn.set_nodelay(true);
                let mut writer = conn.try_clone().unwrap();
                let mut reader = conn;
                thread::spawn(move || {
                    let buf = vec![out_byte; 32 * 1024];
                    let mut left = out_n;
                    while left > 0 {
                        let k = left.min(buf.len());
                        if writer.write_all(&buf[..k]).is_err() {
                            break;
                        }
                        left -= k;
                    }
                });
                let mut got = vec![0u8; in_n];
                let _ = reader.read_exact(&mut got);
            });
        }
    });
    local
}

fn socks_asym(proxy: &str, addr: &[u8], port: u16, send: &[u8], expect: usize, expect_byte: u8) {
    let mut sock = socks_connect(proxy, 1, addr, port);
    sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut reader = sock.try_clone().unwrap();
    thread::scope(|scope| {
        scope.spawn(|| {
            sock.write_all(send).unwrap();
        });
        let mut got = vec![0u8; expect];
        reader.read_exact(&mut got).unwrap();
        assert!(got.iter().all(|b| *b == expect_byte), "asymmetric payload");
    });
}

fn socks_tls_duplex(proxy: &str, origin: &str, n: usize) {
    let host = host_of(origin);
    let sock = socks_connect(proxy, 3, &[&[host.len() as u8], host.as_bytes()].concat(), port_of(origin));
    let mut tls = rustls_on(sock);
    let mut sent = 0usize;
    let mut got = Vec::with_capacity(n);
    let chunk = vec![0xB2u8; 16 * 1024];
    let started = std::time::Instant::now();
    let first = (n).min(chunk.len());
    match tls.write(&chunk[..first]) {
        Ok(wrote) => sent += wrote,
        Err(e) => panic!("tls duplex handshake: {e}"),
    }
    tls.sock.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    while sent < n || got.len() < n {
        assert!(started.elapsed() < Duration::from_secs(20), "tls duplex stalled sent {sent} got {}", got.len());
        if sent < n {
            let k = (n - sent).min(chunk.len());
            match tls.write(&chunk[..k]) {
                Ok(0) => panic!("tls duplex write ended"),
                Ok(wrote) => sent += wrote,
                Err(e) if is_wait(&e) => {}
                Err(e) => panic!("tls duplex write: {e}"),
            }
        }
        if got.len() < n {
            let mut buf = [0u8; 16 * 1024];
            match tls.read(&mut buf) {
                Ok(0) => panic!("tls duplex eof after {}", got.len()),
                Ok(read) => got.extend_from_slice(&buf[..read]),
                Err(e) if is_wait(&e) => {}
                Err(e) => panic!("tls duplex read: {e}"),
            }
        }
    }
    assert!(got.iter().all(|b| *b == 0xA1), "tls duplex corrupted");
}

fn is_wait(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::TimedOut || err.kind() == std::io::ErrorKind::WouldBlock
}

fn tls_abort_after_splice(proxy: &str, origin: &str) {
    let before = spliced_bytes();
    let host = host_of(origin);
    let sock = socks_connect(proxy, 3, &[&[host.len() as u8], host.as_bytes()].concat(), port_of(origin));
    let mut tls = rustls_on(sock);
    tls.write_all(b"GET /big HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = [0u8; 8192];
    let started = std::time::Instant::now();
    while spliced_bytes() == before {
        assert!(started.elapsed() < Duration::from_secs(8), "splice did not start");
        assert!(tls.read(&mut buf).unwrap() > 0);
    }
}

fn socks_bad_target(proxy: &str, host: &[u8]) {
    let mut sock = TcpStream::connect(proxy).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    sock.write_all(&[5, 1, 0]).unwrap();
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).unwrap();
    assert_eq!(greet, [5, 0]);
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&80u16.to_be_bytes());
    sock.write_all(&req).unwrap();
    let started = std::time::Instant::now();
    let mut head = [0u8; 4];
    match sock.read_exact(&mut head) {
        Err(_) => return,
        Ok(()) if head[1] != 0 => return,
        Ok(()) => {}
    }
    let _ = sock.write_all(b"x");
    let mut buf = [0u8; 32];
    let _ = sock.read(&mut buf);
    assert!(started.elapsed() < Duration::from_secs(3), "bad target hung");
}

fn tls_big_twice(proxy: &str, origin: &str) -> Result<(), String> {
    let host = host_of(origin);
    let sock = socks_connect(proxy, 3, &[&[host.len() as u8], host.as_bytes()].concat(), port_of(origin));
    let mut http = HttpBuf { sock: rustls_on(sock), buf: Vec::new() };
    for _ in 0..2 {
        http.sock
            .write_all(b"GET /big HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .map_err(|e| e.to_string())?;
        let body = http.read_response()?;
        if body.len() != 300_000 || body.iter().any(|b| *b != b'x') {
            return Err(format!("big keep-alive len {}", body.len()));
        }
    }
    Ok(())
}
