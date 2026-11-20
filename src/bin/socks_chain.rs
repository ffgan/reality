//! SOCKS5 listener that opens each CONNECT through an upstream SOCKS5 server.
//!
//! PassWall starts this with the same `run -c config.json` arguments it uses
//! for Xray's proto config: one SOCKS inbound and one SOCKS outbound. HAProxy
//! sits in front of the node SOCKS ports and only forwards raw TCP, so this
//! process is the small piece that speaks SOCKS on both sides.

use std::env;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

struct Chain {
    listen: String,
    upstream: String,
}

fn main() -> ExitCode {
    match parse_args(env::args().skip(1)) {
        Ok(chain) => {
            if let Err(error) = serve(&chain) {
                eprintln!("socks-chain: {error}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("socks-chain: {error}");
            eprintln!(
                "usage: socks-chain run -c config.json\n       socks-chain --listen 127.0.0.1:1070 --upstream 127.0.0.1:1181"
            );
            ExitCode::from(2)
        }
    }
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Chain, String> {
    let args: Vec<String> = args.collect();
    if args.first().map(String::as_str) == Some("run") {
        let mut config = None;
        let mut i = 1;
        while i < args.len() {
            if args[i] == "-c" || args[i] == "-config" {
                config = args.get(i + 1).cloned();
                i += 2;
            } else {
                return Err(format!("unknown argument {}", args[i]));
            }
        }
        let path = config.ok_or("missing -c config")?;
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
        return chain_from_xray_config(&text);
    }
    let mut listen = None;
    let mut upstream = None;
    let mut i = 0;
    while i < args.len() {
        let value = args.get(i + 1).ok_or_else(|| format!("missing value for {}", args[i]))?;
        match args[i].as_str() {
            "--listen" => listen = Some(value.clone()),
            "--upstream" => upstream = Some(value.clone()),
            other => return Err(format!("unknown argument {other}")),
        }
        i += 2;
    }
    Ok(Chain {
        listen: listen.ok_or("missing --listen")?,
        upstream: upstream.ok_or("missing --upstream")?,
    })
}

fn chain_from_xray_config(text: &str) -> Result<Chain, String> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let inbound = value["inbounds"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["protocol"] == "socks"))
        .ok_or("config has no SOCKS inbound")?;
    if inbound["settings"]["auth"] == "password" {
        return Err("SOCKS authentication is not supported".to_string());
    }
    let listen_host = inbound["listen"].as_str().unwrap_or("127.0.0.1");
    let listen_port = json_port(&inbound["port"]).ok_or("invalid inbound port")?;
    let server = value["outbounds"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["protocol"] == "socks"))
        .and_then(|outbound| outbound["settings"]["servers"].as_array())
        .and_then(|servers| servers.first())
        .ok_or("config has no SOCKS outbound")?;
    let upstream_host = server["address"].as_str().ok_or("invalid outbound address")?;
    let upstream_port = json_port(&server["port"]).ok_or("invalid outbound port")?;
    Ok(Chain {
        listen: endpoint(listen_host, listen_port),
        upstream: endpoint(upstream_host, upstream_port),
    })
}

fn json_port(value: &serde_json::Value) -> Option<u16> {
    let port = value.as_u64().or_else(|| value.as_str()?.parse().ok())?;
    u16::try_from(port).ok().filter(|port| *port != 0)
}

fn endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn serve(chain: &Chain) -> io::Result<()> {
    let listener = TcpListener::bind(&chain.listen)?;
    eprintln!("socks-chain {} -> {}", chain.listen, chain.upstream);
    let upstream = chain.upstream.clone();
    for client in listener.incoming() {
        let client = match client {
            Ok(client) => client,
            Err(error) => {
                eprintln!("socks-chain accept: {error}");
                continue;
            }
        };
        let upstream = upstream.clone();
        thread::spawn(move || {
            if let Err(error) = handle(client, &upstream) {
                eprintln!("socks-chain: {error}");
            }
        });
    }
    Ok(())
}

fn handle(mut client: TcpStream, upstream: &str) -> io::Result<()> {
    client.set_nodelay(true)?;
    let _ = client.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = client.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    let target = match read_client_request(&mut client) {
        Ok(target) => target,
        Err(error) => {
            let _ = reject(&mut client, 0x01);
            return Err(error);
        }
    };
    let mut server = match TcpStream::connect(upstream) {
        Ok(server) => server,
        Err(error) => {
            let _ = reject(&mut client, 0x01);
            return Err(error);
        }
    };
    server.set_nodelay(true)?;
    let _ = server.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = server.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    if let Err(error) = connect_upstream(&mut server, &target) {
        let _ = reject(&mut client, 0x05);
        return Err(error);
    }
    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    let _ = server.set_read_timeout(None);
    let _ = server.set_write_timeout(None);
    tunnel(client, server)
}

fn read_client_request(client: &mut TcpStream) -> io::Result<Vec<u8>> {
    let methods = read_exact(client, 2)?;
    if methods[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let offered = read_exact(client, methods[1] as usize)?;
    if !offered.contains(&0) {
        let _ = client.write_all(&[5, 0xff]);
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "auth required"));
    }
    client.write_all(&[5, 0])?;
    let header = read_exact(client, 4)?;
    if header[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request version"));
    }
    if header[1] != 1 {
        let _ = reject(client, 0x07);
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "only CONNECT is supported"));
    }
    let mut target = vec![header[3]];
    target.extend(read_address(client, header[3])?);
    Ok(target)
}

fn read_address(stream: &mut TcpStream, kind: u8) -> io::Result<Vec<u8>> {
    let body = match kind {
        1 => read_exact(stream, 4 + 2)?,
        4 => read_exact(stream, 16 + 2)?,
        3 => {
            let len = read_exact(stream, 1)?[0] as usize;
            if len == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "empty domain"));
            }
            let mut body = vec![len as u8];
            body.extend(read_exact(stream, len + 2)?);
            body
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown address type")),
    };
    Ok(body)
}

fn connect_upstream(server: &mut TcpStream, target: &[u8]) -> io::Result<()> {
    server.write_all(&[5, 1, 0])?;
    let reply = read_exact(server, 2)?;
    if reply != [5, 0] {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "upstream auth rejected"));
    }
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(target);
    server.write_all(&request)?;
    let header = read_exact(server, 4)?;
    if header[0] != 5 || header[1] != 0 {
        return Err(io::Error::other(format!("upstream connect failed: {}", header.get(1).copied().unwrap_or(0))));
    }
    let _ = read_address(server, header[3])?;
    Ok(())
}

fn reject(stream: &mut TcpStream, reply: u8) -> io::Result<()> {
    stream.write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0])
}

fn tunnel(mut client: TcpStream, mut server: TcpStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut server_write = server.try_clone()?;
    let copied = thread::spawn(move || {
        let result = io::copy(&mut client_read, &mut server_write);
        let _ = server_write.shutdown(Shutdown::Write);
        result
    });
    let _ = io::copy(&mut server, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = copied.join();
    Ok(())
}

fn read_exact(stream: &mut TcpStream, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener as StdListener;

    #[test]
    fn reads_xray_proto_config() {
        let chain = chain_from_xray_config(
            r#"{"inbounds":[{"listen":"127.0.0.1","port":1070,"protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"freedom"},{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1181}]}}]}"#,
        )
        .unwrap();
        assert_eq!(chain.listen, "127.0.0.1:1070");
        assert_eq!(chain.upstream, "127.0.0.1:1181");
    }

    #[test]
    fn relays_connect_through_upstream_socks() {
        let echo = StdListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        thread::spawn(move || {
            let (mut socket, _) = echo.accept().unwrap();
            let mut buf = [0; 16];
            let n = socket.read(&mut buf).unwrap();
            socket.write_all(&buf[..n]).unwrap();
        });

        let upstream = StdListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            socket.set_nodelay(true).unwrap();
            assert_eq!(read_exact(&mut socket, 3).unwrap(), vec![5, 1, 0]);
            socket.write_all(&[5, 0]).unwrap();
            let header = read_exact(&mut socket, 4).unwrap();
            assert_eq!(&header[..3], &[5, 1, 0]);
            let dest = read_address(&mut socket, header[3]).unwrap();
            assert_eq!(dest[dest.len() - 2] as u16 * 256 + dest[dest.len() - 1] as u16, echo_addr.port());
            socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let remote = TcpStream::connect(echo_addr).unwrap();
            tunnel(socket, remote).unwrap();
        });

        let listen = StdListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listen.local_addr().unwrap();
        drop(listen);
        let upstream_text = upstream_addr.to_string();
        thread::spawn(move || {
            serve(&Chain { listen: listen_addr.to_string(), upstream: upstream_text }).unwrap();
        });

        let mut client = {
            let mut connected = None;
            for _ in 0..50 {
                if let Ok(socket) = TcpStream::connect(listen_addr) {
                    connected = Some(socket);
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            connected.expect("socks-chain did not accept")
        };
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        assert_eq!(read_exact(&mut client, 2).unwrap(), vec![5, 0]);
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&echo_addr.ip().to_string().parse::<std::net::Ipv4Addr>().unwrap().octets());
        request.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&request).unwrap();
        assert_eq!(read_exact(&mut client, 10).unwrap()[1], 0);
        client.write_all(b"hello").unwrap();
        let mut got = [0; 5];
        client.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hello");
    }
}
